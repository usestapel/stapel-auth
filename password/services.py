"""Service for password login, set, change, and OTP-based reset."""

import logging
import secrets

from stapel_core.django.api.errors import ERR_500_INTERNAL, StapelServiceError

from stapel_auth.mfa.services import TOTPService
from stapel_auth.otp.services import (
    EmailVerificationService,
    PhoneVerificationService,
    promote_anonymous_session,
)
from stapel_auth.password.dto import PasswordMethod, PasswordMethodType

logger = logging.getLogger(__name__)


# ── First-login policy (workspaces-org-program §C2) ──────────────────────────


class FirstLoginPolicyService:
    """Forced password change / MFA enroll intermediates on password login.

    Org-provisioned accounts (``auth.provision_user``) carry a first-login
    flag on the user row (``password_change_required`` /
    ``mfa_enrollment_required``, stapel-core Wave 0). While a flag is up, a
    successful password login returns a ``FirstLoginChallengeResponse``
    instead of a session — the same intermediate pattern as the TOTP
    step-up challenge (cache-stored opaque token, here with a 10-minute
    TTL). The challenge is resolved at:

    * ``POST /password/forced-change/`` — sets the new password by the
      deployment's password canon, clears the flag, mints a full session
      (or chains into the mfa_enroll intermediate when BOTH flags are up);
    * ``POST /mfa/enroll/exchange/`` — trades the challenge for a limited
      enroll-only session (JWT claim ``enroll_only``); activating a strong
      factor clears the flag and upgrades to a full session.

    Accounts without flags never touch this service — their login path is
    byte-identical to pre-0.12 behavior (the release gate).
    """

    CHALLENGE_TTL = 600  # 10 minutes

    REQUIRES_PASSWORD_CHANGE = "password_change"
    REQUIRES_MFA_ENROLL = "mfa_enroll"

    #: Every first-login policy an org may demand, in the order the login
    #: flow resolves them. INDEPENDENT, not alternatives (#90): "rotate the
    #: password we set for you" and "enrol a second factor" are two
    #: different demands, and an org that wants both used to be unable to
    #: say so — ``auth.provision_user`` took one ``first_login_policy``
    #: string, so raising either flag lowered the other by construction.
    #: The user row always had two independent booleans and the login flow
    #: always chained them (forced change → mfa enroll); only the
    #: provisioning API forced the choice.
    POLICIES = (REQUIRES_PASSWORD_CHANGE, REQUIRES_MFA_ENROLL)

    #: policy → the user-row boolean it raises. The one place the mapping
    #: is written; provisioning, the admin reset and the invite-accept
    #: seam all go through :meth:`flag_kwargs` / :meth:`apply` rather than
    #: naming the columns again.
    POLICY_FLAGS = {
        REQUIRES_PASSWORD_CHANGE: "password_change_required",
        REQUIRES_MFA_ENROLL: "mfa_enrollment_required",
    }

    @classmethod
    def normalize_policies(cls, policies) -> list[str] | None:
        """Validate a caller-supplied policy set; ``None`` if it is malformed.

        Accepts any iterable of policy names, returns them de-duplicated in
        :attr:`POLICIES` order so two callers asking for the same thing in
        a different order produce the same result. An empty set is
        legitimate and means "no first-login step" — the caller who wants
        nothing enforced says so explicitly rather than by omission.
        """
        if isinstance(policies, str) or not isinstance(policies, (list, tuple, set)):
            return None
        wanted = set(policies)
        if not wanted.issubset(set(cls.POLICIES)):
            return None
        return [p for p in cls.POLICIES if p in wanted]

    @classmethod
    def flag_kwargs(cls, policies) -> dict:
        """``{flag_name: bool}`` for every policy — for ``User(**kwargs)``.

        Every flag is named, not only the raised ones: a create call that
        listed just the True ones would inherit whatever the model default
        happens to be for the rest, which is exactly how "set one, clear
        the other" behaviour survives a refactor unnoticed.
        """
        wanted = set(policies or ())
        return {flag: policy in wanted for policy, flag in cls.POLICY_FLAGS.items()}

    @classmethod
    def apply(cls, user, policies) -> list[str]:
        """Raise the named policies on an EXISTING account; never lower any.

        Additive on purpose. The flags are per-account and this method is
        called by org-scoped surfaces (invite acceptance, an admin password
        reset); clearing a flag that another org — or the user's own
        security settings — put up would let one tenant lower another
        tenant's bar. Only the user completing the step clears it.

        A policy already satisfied is not raised: an ``mfa_enroll`` demand
        against an account that already carries a strong factor is a step
        with nothing to do, and raising it would bounce the user into an
        enrolment screen they have no enrolment left to make.

        Returns the policies actually raised by this call.
        """
        from stapel_core.verification import strong_factors

        raised: list[str] = []
        for policy in cls.POLICIES:
            if policy not in (policies or ()):
                continue
            if policy == cls.REQUIRES_MFA_ENROLL and strong_factors(user):
                continue
            flag = cls.POLICY_FLAGS[policy]
            if getattr(user, flag, False):
                continue  # already outstanding — nothing to raise
            setattr(user, flag, True)
            raised.append(policy)
        if raised:
            user.save(
                update_fields=[cls.POLICY_FLAGS[policy] for policy in raised]
            )
        return raised

    @staticmethod
    def _key(token: str) -> str:
        return f"first_login_challenge:{token}"

    @classmethod
    def required_intermediate(cls, user) -> str | None:
        """Which first-login step *user* still owes, or None.

        Order canon: password change first (the org-set password must stop
        working before anything else), then MFA enrollment. Self-heal: an
        ``mfa_enrollment_required`` flag on an account that already has a
        strong factor (e.g. set out-of-band after enrollment) is cleared on
        the spot instead of dead-ending the login.
        """
        if getattr(user, "password_change_required", False):
            return cls.REQUIRES_PASSWORD_CHANGE
        if getattr(user, "mfa_enrollment_required", False):
            from stapel_core.verification import strong_factors

            if strong_factors(user):
                user.mfa_enrollment_required = False
                user.save(update_fields=["mfa_enrollment_required"])
                return None
            return cls.REQUIRES_MFA_ENROLL
        return None

    @classmethod
    def create_challenge(cls, user, requires: str) -> str:
        """Store a short-lived first-login challenge; return opaque token."""
        from django.core.cache import cache

        token = secrets.token_urlsafe(32)
        cache.set(
            cls._key(token),
            {"user_id": str(user.pk), "requires": requires},
            cls.CHALLENGE_TTL,
        )
        return token

    @classmethod
    def resolve_challenge(cls, token: str, requires: str):
        """Resolve (WITHOUT consuming) a challenge to its active user.

        Returns the user or None (unknown/expired token, requirement
        mismatch, inactive user). Non-consuming so a recoverable downstream
        failure — e.g. a too-weak new password on forced change — does not
        burn the challenge; call :meth:`burn_challenge` once the flow
        actually succeeds.
        """
        from django.contrib.auth import get_user_model
        from django.core.cache import cache

        data = cache.get(cls._key(token))
        if not data or data.get("requires") != requires:
            return None
        User = get_user_model()
        user = User.objects.filter(pk=data.get("user_id")).first()
        if user is None or not user.is_active:
            return None
        return user

    @classmethod
    def burn_challenge(cls, token: str) -> None:
        """Consume the challenge (single successful use)."""
        from django.core.cache import cache

        cache.delete(cls._key(token))


# ── Password service ─────────────────────────────────────────────────────────


class PasswordService:
    """Password login, set, change, and OTP-based reset."""

    @staticmethod
    def mask_email(email: str) -> str:
        if not email or "@" not in email:
            return "***"
        local, domain = email.split("@", 1)
        masked = local[0] + "***" if len(local) > 1 else "***"
        return f"{masked}@{domain}"

    @staticmethod
    def mask_phone(phone: str) -> str:
        if not phone or len(phone) < 4:
            return "***"
        return phone[:3] + "***" + phone[-2:]

    @staticmethod
    def _check_mock_admin(user) -> None:
        """Block OTP flows for staff/superuser accounts when mock OTP is active."""
        from stapel_auth.conf import auth_settings
        from stapel_auth.errors import ERR_403_MOCK_OTP_ADMIN

        if (user.is_staff or user.is_superuser) and (
            auth_settings.USE_MOCK_EMAIL_OTP or auth_settings.USE_MOCK_SMS_OTP
        ):
            raise StapelServiceError(403, ERR_403_MOCK_OTP_ADMIN)

    @staticmethod
    def _raise_for_otp_result(result) -> None:
        """Convert an OTP service result to StapelServiceError. No-op on success."""
        from stapel_core.django.api.errors import ERR_429_RATE_LIMIT

        from stapel_auth.errors import (
            ERR_400_CODE_EXPIRED,
            ERR_400_INVALID_CODE,
            ERR_400_INVALID_CODE_ATTEMPTS,
            ERR_400_INVALID_METHOD,
            ERR_400_NO_VERIFIED_CONTACT,
            ERR_404_USER_FOR_RESET,
            ERR_422_BLOCKED,
            retry_params,
        )

        if not isinstance(result, dict):
            if not result:
                raise StapelServiceError(500, ERR_500_INTERNAL)
            return  # success object
        err = result.get("error")
        if not err:
            return  # success dict
        if err == "rate_limit":
            raise StapelServiceError(
                429, ERR_429_RATE_LIMIT, params=retry_params(result.get("retry_after"))
            )
        if err == "blocked":
            raise StapelServiceError(
                422, ERR_422_BLOCKED, params=retry_params(result.get("retry_after"))
            )
        if err in ("expired", "expired_retry_allowed"):
            raise StapelServiceError(400, ERR_400_CODE_EXPIRED)
        if err == "invalid_code":
            rem = result.get("attempts_remaining")
            if rem is not None:
                raise StapelServiceError(
                    400,
                    ERR_400_INVALID_CODE_ATTEMPTS,
                    params={"attempts_remaining": rem},
                )
            raise StapelServiceError(400, ERR_400_INVALID_CODE)
        if err == "no_verified_contact":
            raise StapelServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
        if err == "invalid_method":
            raise StapelServiceError(400, ERR_400_INVALID_METHOD)
        if err == "user_not_found":
            raise StapelServiceError(404, ERR_404_USER_FOR_RESET)
        raise StapelServiceError(500, ERR_500_INTERNAL)

    @classmethod
    def get_available_methods(cls, user) -> list:
        methods = []
        if user.has_usable_password():
            methods.append(PasswordMethod(method=PasswordMethodType.PASSWORD))
        if user.email and user.is_email_verified:
            methods.append(
                PasswordMethod(
                    method=PasswordMethodType.EMAIL, target=cls.mask_email(user.email)
                )
            )
        if user.phone and user.is_phone_verified:
            methods.append(
                PasswordMethod(
                    method=PasswordMethodType.PHONE, target=cls.mask_phone(user.phone)
                )
            )
        if TOTPService.is_enabled(user):
            methods.append(PasswordMethod(method=PasswordMethodType.TOTP))
        return methods

    @staticmethod
    def login(login: str, password: str):
        """Return User or None. Checks password directly, bypassing JWT/session backends."""
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = None
        try:
            user = User.objects.get(username=login)
        except User.DoesNotExist:
            try:
                user = User.objects.get(email=login)
            except User.DoesNotExist:
                return None
        if user.check_password(password):
            return user
        return None

    @staticmethod
    def change_via_old(
        user, old_password: str, new_password: str, *, keep_session_jti: str = None
    ) -> bool:
        """Change the password of a user who knows the current one.

        *keep_session_jti* spares exactly one session — the one the caller is
        making this request from. Every other session dies: the OTP-verified
        reset paths have always revoked, the know-the-old-password path did
        not, so the one case where the user is most likely reacting to a
        suspected compromise left every existing session — including the
        attacker's — alive (audit AUTH-05).

        The default spares nothing, because a service-level caller with no
        request behind it cannot vouch for any session.
        """
        if not user.check_password(old_password):
            return False
        user.set_password(new_password)
        user.save(update_fields=["password"])
        PasswordService._revoke_all_sessions(user, except_jti=keep_session_jti)
        return True

    @classmethod
    def send_change_otp(cls, user, method: PasswordMethodType) -> str:
        """Send OTP for password change. Returns masked target. Raises StapelServiceError."""
        from stapel_auth.errors import (
            ERR_400_INVALID_METHOD,
            ERR_400_NO_VERIFIED_CONTACT,
        )

        cls._check_mock_admin(user)
        if method == PasswordMethodType.EMAIL:
            if not user.email or not user.is_email_verified:
                raise StapelServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = EmailVerificationService().send_verification_code(user.email)
            cls._raise_for_otp_result(result)
            return cls.mask_email(user.email)
        if method == PasswordMethodType.PHONE:
            if not user.phone or not user.is_phone_verified:
                raise StapelServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = PhoneVerificationService().send_verification_code(user.phone)
            cls._raise_for_otp_result(result)
            return cls.mask_phone(user.phone)
        if method == PasswordMethodType.TOTP:
            if not TOTPService.is_enabled(user):
                raise StapelServiceError(400, ERR_400_INVALID_METHOD)
            return ""  # TOTP needs no "send" — code is already in the authenticator app
        raise StapelServiceError(400, ERR_400_INVALID_METHOD)

    @classmethod
    def change_via_otp(
        cls, user, method: PasswordMethodType, code: str, new_password: str
    ):
        """Verify OTP/TOTP and update password. Raises StapelServiceError on any error.

        Returns the (possibly mutated) *user*. If *user* was still an
        anonymous guest session — normally unreachable here since EMAIL/PHONE
        both require the contact to already be verified, but defensive in
        case that invariant is ever violated upstream — a successful contact
        OTP verification is itself proof of the same anchor
        email_verify/phone_verify promote on, so it promotes too rather than
        leaving the account anon after their password is already set on it.
        """
        from stapel_auth.errors import (
            ERR_400_INVALID_CODE,
            ERR_400_INVALID_METHOD,
            ERR_400_NO_VERIFIED_CONTACT,
        )

        was_anonymous = False
        if method == PasswordMethodType.EMAIL:
            if not user.email or not user.is_email_verified:
                raise StapelServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = EmailVerificationService().verify_code(user.email, code)
            cls._raise_for_otp_result(result)
            if user.is_anonymous:
                was_anonymous = True
                promote_anonymous_session(user, auth_type="email")
        elif method == PasswordMethodType.PHONE:
            if not user.phone or not user.is_phone_verified:
                raise StapelServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = PhoneVerificationService().verify_code(user.phone, code)
            cls._raise_for_otp_result(result)
            if user.is_anonymous:
                was_anonymous = True
                promote_anonymous_session(user, auth_type="phone")
        elif method == PasswordMethodType.TOTP:
            if not TOTPService.is_enabled(user):
                raise StapelServiceError(400, ERR_400_INVALID_METHOD)
            if not TOTPService.verify_code(user, code):
                raise StapelServiceError(400, ERR_400_INVALID_CODE)
        else:
            raise StapelServiceError(400, ERR_400_INVALID_METHOD)
        user.set_password(new_password)
        update_fields = ["password"]
        if was_anonymous:
            update_fields += ["is_anonymous", "auth_type", "username"]
        user.save(update_fields=update_fields)
        cls._revoke_all_sessions(user)
        return user

    @staticmethod
    def _revoke_all_sessions(user, *, except_jti: str = None):
        """A changed/reset password must kill existing sessions — otherwise an
        attacker's session survives the victim's account recovery."""
        # Deliberately NOT wrapped in a swallow: "the password changed but we
        # could not revoke the old sessions" is not a success, and reporting
        # it as one is what turns a revocation-store outage into a silently
        # ineffective account recovery (audit AUTH-05, fail-open revocation).
        from stapel_auth.sessions.services import SessionService

        SessionService.revoke_all(user, except_jti=except_jti)

    @classmethod
    def reset_request(cls, *, email=None, phone=None) -> str:
        """Send reset OTP. Returns masked target. Raises StapelServiceError."""
        from django.contrib.auth import get_user_model

        from stapel_auth.errors import ERR_404_USER_FOR_RESET

        User = get_user_model()
        if email:
            try:
                user = User.objects.get(email=email, is_email_verified=True)
            except User.DoesNotExist:
                raise StapelServiceError(404, ERR_404_USER_FOR_RESET)
            cls._check_mock_admin(user)
            result = EmailVerificationService().send_verification_code(email)
            cls._raise_for_otp_result(result)
            return cls.mask_email(email)
        try:
            user = User.objects.get(phone=phone, is_phone_verified=True)
        except User.DoesNotExist:
            raise StapelServiceError(404, ERR_404_USER_FOR_RESET)
        cls._check_mock_admin(user)
        result = PhoneVerificationService().send_verification_code(phone)
        cls._raise_for_otp_result(result)
        return cls.mask_phone(phone)

    @classmethod
    def reset_verify(cls, *, email=None, phone=None, code: str, new_password: str):
        """Verify OTP and reset password. Returns User. Raises StapelServiceError."""
        from django.contrib.auth import get_user_model

        from stapel_auth.errors import ERR_404_USER_FOR_RESET

        User = get_user_model()
        if email:
            result = EmailVerificationService().verify_code(email, code)
            cls._raise_for_otp_result(result)
            try:
                user = User.objects.get(email=email, is_email_verified=True)
            except User.DoesNotExist:
                raise StapelServiceError(404, ERR_404_USER_FOR_RESET)
        else:
            result = PhoneVerificationService().verify_code(phone, code)
            cls._raise_for_otp_result(result)
            try:
                user = User.objects.get(phone=phone, is_phone_verified=True)
            except User.DoesNotExist:
                raise StapelServiceError(404, ERR_404_USER_FOR_RESET)
        user.set_password(new_password)
        user.save(update_fields=["password"])
        cls._revoke_all_sessions(user)
        return user
