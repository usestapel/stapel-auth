"""Service classes for MFA (TOTP and Passkey) domain."""
import hashlib as _hashlib
import logging as _logging
import secrets as _secrets

_logger = _logging.getLogger(__name__)


def notify_totp_change(user, notification_type: str, variables: dict | None = None) -> None:
    """Notify the user's verified contact that their TOTP factor changed.

    Mirrors the "always tell the owner" principle ``otp.services.
    AuthenticatorChangeService`` already applies to phone/email changes: a
    stolen session that enrolls, replaces, or disables 2FA must not do so
    silently — this is the anti-takeover awareness leg for TOTP (item 3 of
    the TOTP security hardening). Prefers the verified email, falls back
    to the verified phone; a no-argument no-op if neither is verified
    (delayed-mode initiation is the only place that HARD-requires a
    verified contact — see ``AuthenticatorChangeService.
    initiate_delayed_totp``; instant changes proceed either way since the
    proof-of-possession already establishes the actor is trusted).

    Best-effort: failures are logged, never raised — matches every other
    ``request_notification`` call site in this module family.
    """
    from stapel_core.notifications import request_notification

    email = user.email if (user.email and getattr(user, 'is_email_verified', False)) else None
    phone = None
    if not email:
        phone = user.phone if (user.phone and getattr(user, 'is_phone_verified', False)) else None
    if not email and not phone:
        return
    try:
        request_notification(
            notification_type=notification_type,
            user_id=str(user.id),
            email=email,
            phone=phone,
            variables=variables or {},
            source_service="auth",
        )
    except Exception:
        _logger.exception(
            "Failed to send %s notification for user %s", notification_type, user.id,
        )


# ── MFA account-state transitions (workspaces-org-program §C2-C3) ────────────
#
# user.mfa_enabled / user.mfa_disabled are ACCOUNT-LEVEL transition events of
# the "has a strong second factor" predicate (strength canon: totp/passkey/
# otp_phone strong, otp_email weak — stapel_core.verification.strong_factors),
# NOT per-factor ticks: adding a second passkey, or disabling TOTP while a
# verified phone still counts as strong, emits nothing. That lets the
# workspaces require_mfa consumer suspend/unsuspend on the events directly.
# Emission goes through the transactional outbox atomically with the factor
# write — callers below wrap the ORM change and the emit in one atomic block.


def _has_strong_mfa(user) -> bool:
    from stapel_core.verification import strong_factors

    return bool(strong_factors(user))


def _emit_mfa_transition(user, event: str, factor: str) -> None:
    """Outbox-emit a user.mfa_enabled|disabled transition (caller holds the
    atomic that performs the factor write)."""
    from stapel_core.comm import emit

    emit(  # emit-check: ok — every caller wraps this in the atomic that performs the factor write
        event,
        {"user_id": str(user.pk), "factor": factor},
        key=str(user.pk),
        service="auth",
    )


def _after_strong_factor_activation(user, factor: str, had_strong: bool) -> None:
    """Post-activation bookkeeping, inside the caller's atomic block.

    1. Clears ``mfa_enrollment_required`` (first-login policy C2): the user
       just activated a strong factor, whatever session they did it from.
    2. Emits ``user.mfa_enabled`` when this activation is the account-level
       transition (the user had no strong factor before).
    """
    from stapel_auth.events import EVENT_USER_MFA_ENABLED

    if getattr(user, "mfa_enrollment_required", False):
        user.mfa_enrollment_required = False
        user.save(update_fields=["mfa_enrollment_required"])
    if not had_strong and _has_strong_mfa(user):
        _emit_mfa_transition(user, EVENT_USER_MFA_ENABLED, factor)


def _after_strong_factor_removal(user, factor: str, had_strong: bool) -> None:
    """Emit ``user.mfa_disabled`` when the removal dropped the LAST strong
    factor (inside the caller's atomic block)."""
    from stapel_auth.events import EVENT_USER_MFA_DISABLED

    if had_strong and not _has_strong_mfa(user):
        _emit_mfa_transition(user, EVENT_USER_MFA_DISABLED, factor)


class TOTPService:
    BACKUP_CODE_COUNT = 8
    CHALLENGE_TTL = 300      # 5 min
    TOTP_WINDOW = 1          # ±1 step tolerance
    MAX_CHALLENGE_FAILURES = 5   # challenge is invalidated after this many bad codes
    # Digits per TOTP code — explicit here (rather than relying on pyotp's own
    # default) so it is one source of truth for both the code every
    # pyotp.TOTP(..., digits=cls.CODE_LENGTH) call below actually verifies
    # against, and the contract metadata the frontend reads instead of
    # guessing (AuthCapabilities.otp.totp_code_length, see oauth/services.py).
    CODE_LENGTH = 6

    # ── setup ────────────────────────────────────────────────────────────────

    @classmethod
    def setup(cls, user, code: str = None, backup_code: str = None) -> dict:
        """
        Start TOTP enrollment. Returns secret + otpauth URI.
        Creates/replaces a pending (is_active=False) TOTPDevice.

        SECURITY: if the user already has an ACTIVE device, this is a
        *replace* and requires proof of possession of the CURRENT device
        (``code`` or ``backup_code``) — otherwise a stolen session could
        silently strip 2FA by re-enrolling without ever proving the old
        device, bypassing ``disable()``'s proof requirement entirely
        (previously: anyone authenticated could call this with zero proof
        and immediately deactivate the existing device — the exact gap
        this hardening closes). Raises ``ValueError('proof_required')`` in
        that case. First-time enrollment (no active device yet) needs no
        proof, unchanged from before.

        The old device is only actually invalidated once ``confirm()``
        activates the new one (same as the pre-existing overwrite
        behavior) — there is no separate "pending device" slot
        (``TOTPDevice`` is one row per user) — but reaching that state now
        requires the caller to have proven the old device first.
        """
        import pyotp
        from stapel_auth.models import TOTPDevice

        try:
            existing_active = TOTPDevice.objects.get(user=user, is_active=True)
        except TOTPDevice.DoesNotExist:
            existing_active = None

        if existing_active is not None and not cls._verify_any(
            existing_active, code=code, backup_code=backup_code,
        ):
            raise ValueError('proof_required')

        secret = pyotp.random_base32()
        from stapel_auth.conf import auth_settings
        issuer = auth_settings.TOTP_ISSUER
        label = user.email or user.phone or str(user.id)
        totp = pyotp.TOTP(secret, digits=cls.CODE_LENGTH)
        uri = totp.provisioning_uri(name=label, issuer_name=issuer)

        TOTPDevice.objects.update_or_create(
            user=user,
            defaults={'secret': secret, 'is_active': False,
                      'backup_codes': [], 'confirmed_at': None},
        )
        return {'secret': secret, 'qr_uri': uri}

    @classmethod
    def confirm(cls, user, code: str) -> list:
        """
        Verify the first TOTP code, activate the device.
        Returns plain backup codes (shown once, then hashed-only).
        Raises ValueError on wrong code or no pending device.
        """
        import pyotp
        from stapel_auth.models import TOTPDevice
        from django.utils import timezone

        try:
            device = TOTPDevice.objects.get(user=user)
        except TOTPDevice.DoesNotExist:
            raise ValueError('no_pending_device')

        totp = pyotp.TOTP(device.secret, digits=cls.CODE_LENGTH)
        if not totp.verify(code, valid_window=cls.TOTP_WINDOW):
            raise ValueError('invalid_code')

        plain_codes = [_secrets.token_hex(4).upper() + '-' + _secrets.token_hex(4).upper()
                       for _ in range(cls.BACKUP_CODE_COUNT)]
        hashed_codes = [_hashlib.sha256(c.replace('-', '').encode()).hexdigest()
                        for c in plain_codes]

        from django.db import transaction

        had_strong = _has_strong_mfa(user)
        with transaction.atomic():
            device.is_active = True
            device.backup_codes = hashed_codes
            device.confirmed_at = timezone.now()
            device.save()
            # First-login policy + account-level mfa_enabled transition
            # (org-program §C2-C3) — atomically with the activation.
            _after_strong_factor_activation(user, "totp", had_strong)
        return plain_codes

    @classmethod
    def disable(cls, user, code: str = None, backup_code: str = None) -> bool:
        """Disable TOTP. Requires valid code or backup code."""
        from stapel_auth.models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
        except TOTPDevice.DoesNotExist:
            return False
        if not cls._verify_any(device, code=code, backup_code=backup_code):
            return False
        from django.db import transaction

        had_strong = _has_strong_mfa(user)
        with transaction.atomic():
            device.delete()
            _after_strong_factor_removal(user, "totp", had_strong)
        return True

    @classmethod
    def force_disable(cls, user) -> bool:
        """Disable TOTP without code check. Call only after external OTP verification.

        Also the delayed-change execute path (tasks.execute_pending_changes)
        — the account-level ``user.mfa_disabled`` transition is emitted here
        so every disable route reaches the outbox.
        """
        from django.db import transaction

        from stapel_auth.models import TOTPDevice

        had_strong = _has_strong_mfa(user)
        with transaction.atomic():
            deleted = TOTPDevice.objects.filter(user=user, is_active=True).delete()[0] > 0
            if deleted:
                _after_strong_factor_removal(user, "totp", had_strong)
        return deleted

    # ── verification helpers ─────────────────────────────────────────────────

    @classmethod
    def verify_code(cls, user, code: str) -> bool:
        import pyotp
        from stapel_auth.models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
        except TOTPDevice.DoesNotExist:
            return False
        return pyotp.TOTP(device.secret, digits=cls.CODE_LENGTH).verify(code, valid_window=cls.TOTP_WINDOW)

    @classmethod
    def verify_backup_code(cls, user, backup_code: str) -> bool:
        from stapel_auth.models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
        except TOTPDevice.DoesNotExist:
            return False
        h = _hashlib.sha256(backup_code.replace('-', '').encode()).hexdigest()
        if h not in device.backup_codes:
            return False
        device.backup_codes = [c for c in device.backup_codes if c != h]
        device.save(update_fields=['backup_codes'])
        return True

    @classmethod
    def _verify_any(cls, device, code=None, backup_code=None) -> bool:
        import pyotp
        if code:
            return pyotp.TOTP(device.secret, digits=cls.CODE_LENGTH).verify(code, valid_window=cls.TOTP_WINDOW)
        if backup_code:
            h = _hashlib.sha256(backup_code.replace('-', '').encode()).hexdigest()
            if h in device.backup_codes:
                device.backup_codes = [c for c in device.backup_codes if c != h]
                device.save(update_fields=['backup_codes'])
                return True
        return False

    @classmethod
    def is_enabled(cls, user) -> bool:
        from stapel_auth.models import TOTPDevice
        return TOTPDevice.objects.filter(user=user, is_active=True).exists()

    @classmethod
    def backup_codes_remaining(cls, user) -> int | None:
        from stapel_auth.models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
            return len(device.backup_codes)
        except TOTPDevice.DoesNotExist:
            return None

    # ── challenge (2FA on login) ─────────────────────────────────────────────

    @classmethod
    def create_challenge(cls, user_id: str) -> str:
        """Store a short-lived challenge in Redis; return opaque token."""
        from django.core.cache import cache
        token = _secrets.token_urlsafe(32)
        cache.set(f'totp_challenge:{token}', str(user_id), cls.CHALLENGE_TTL)
        return token

    @classmethod
    def resolve_challenge(cls, challenge_token: str, code: str = None,
                          backup_code: str = None):
        """
        Verify TOTP code against a challenge token.
        Returns user or None on failure. Clears the challenge on success.
        The challenge itself is invalidated after MAX_CHALLENGE_FAILURES bad
        codes — a stolen challenge token gives at most 5 guesses.
        """
        from django.core.cache import cache
        from django.contrib.auth import get_user_model

        key = f'totp_challenge:{challenge_token}'
        fail_key = f'totp_challenge_fails:{challenge_token}'
        user_id = cache.get(key)
        if not user_id:
            return None

        User = get_user_model()
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

        from stapel_auth.models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
        except TOTPDevice.DoesNotExist:
            return None

        ok = cls._verify_any(device, code=code, backup_code=backup_code)
        if ok:
            cache.delete(key)
            cache.delete(fail_key)
            return user

        failures = (cache.get(fail_key) or 0) + 1
        cache.set(fail_key, failures, cls.CHALLENGE_TTL)
        if failures >= cls.MAX_CHALLENGE_FAILURES:
            # Burn the challenge — the login must be restarted.
            cache.delete(key)
            cache.delete(fail_key)
        return None


class PasskeyService:
    @staticmethod
    def _rp_config():
        from stapel_auth.conf import auth_settings
        return (
            auth_settings.WEBAUTHN_RP_ID or 'localhost',
            auth_settings.WEBAUTHN_RP_NAME,
            auth_settings.WEBAUTHN_ORIGIN or auth_settings.FRONTEND_URL or 'http://localhost',
        )

    @classmethod
    def registration_begin(cls, user) -> dict:
        import webauthn
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement,
        )
        from django.core.cache import cache
        rp_id, rp_name, _ = cls._rp_config()
        from stapel_auth.models import PasskeyCredential
        existing = [
            webauthn.helpers.structs.PublicKeyCredentialDescriptor(id=bytes(c.credential_id))
            for c in PasskeyCredential.objects.filter(user=user, is_active=True)
        ]
        options = webauthn.generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=str(user.id).encode(),
            user_name=user.email or user.username,
            user_display_name=user.get_full_name() or user.username,
            exclude_credentials=existing,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )
        options_json = webauthn.options_to_json(options)
        cache.set(f'passkey_reg:{user.id}', options.challenge, 300)
        return options_json

    @staticmethod
    def _build_registration_credential(data: dict):
        import webauthn
        from webauthn.helpers.structs import (
            RegistrationCredential, AuthenticatorAttestationResponse,
            AuthenticatorAttachment, AuthenticatorTransport,
        )
        resp = data['response']
        transports = [AuthenticatorTransport(t) for t in resp.get('transports', [])] or None
        return RegistrationCredential(
            id=data['id'],
            raw_id=webauthn.base64url_to_bytes(data.get('rawId') or data['id']),
            response=AuthenticatorAttestationResponse(
                client_data_json=webauthn.base64url_to_bytes(resp['clientDataJSON']),
                attestation_object=webauthn.base64url_to_bytes(resp['attestationObject']),
                transports=transports,
            ),
            authenticator_attachment=AuthenticatorAttachment(data['authenticatorAttachment'])
                if data.get('authenticatorAttachment') else None,
        )

    @staticmethod
    def _build_authentication_credential(data: dict):
        import webauthn
        from webauthn.helpers.structs import (
            AuthenticationCredential, AuthenticatorAssertionResponse,
            AuthenticatorAttachment,
        )
        resp = data['response']
        return AuthenticationCredential(
            id=data['id'],
            raw_id=webauthn.base64url_to_bytes(data.get('rawId') or data['id']),
            response=AuthenticatorAssertionResponse(
                client_data_json=webauthn.base64url_to_bytes(resp['clientDataJSON']),
                authenticator_data=webauthn.base64url_to_bytes(resp['authenticatorData']),
                signature=webauthn.base64url_to_bytes(resp['signature']),
                user_handle=webauthn.base64url_to_bytes(resp['userHandle'])
                    if resp.get('userHandle') else None,
            ),
            authenticator_attachment=AuthenticatorAttachment(data['authenticatorAttachment'])
                if data.get('authenticatorAttachment') else None,
        )

    @classmethod
    def registration_complete(cls, user, credential_data: dict, device_name: str = '') -> 'PasskeyCredential':
        import webauthn
        from django.core.cache import cache
        rp_id, _, origin = cls._rp_config()
        challenge = cache.get(f'passkey_reg:{user.id}')
        if not challenge:
            raise ValueError('challenge_expired')
        cache.delete(f'passkey_reg:{user.id}')
        credential = cls._build_registration_credential(credential_data)
        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
        from django.db import transaction

        from stapel_auth.models import PasskeyCredential

        had_strong = _has_strong_mfa(user)
        with transaction.atomic():
            pc = PasskeyCredential.objects.create(
                user=user,
                credential_id=verification.credential_id,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
                aaguid=str(verification.aaguid) if verification.aaguid else '',
                device_name=device_name or 'Passkey',
                transports=list(credential.response.transports or []),
            )
            # First passkey while no other strong factor existed → the
            # account-level mfa_enabled transition (org-program §C3);
            # also clears mfa_enrollment_required (first-login policy C2).
            _after_strong_factor_activation(user, "passkey", had_strong)
        from stapel_auth.sessions.services import AuditService
        AuditService.log('passkey_registered', user=user, device_name=pc.device_name)
        return pc

    @classmethod
    def deactivate(cls, user, pc) -> None:
        """Deactivate a passkey credential of *user*.

        The single removal seam (views go through here, not through raw
        ``is_active`` flips) so the ``user.mfa_disabled`` transition — the
        LAST strong factor going away (org-program §C3) — commits atomically
        with the deactivation.
        """
        from django.db import transaction

        had_strong = _has_strong_mfa(user)
        with transaction.atomic():
            pc.is_active = False
            pc.save(update_fields=['is_active'])
            _after_strong_factor_removal(user, "passkey", had_strong)

    @classmethod
    def authentication_begin(cls, user=None) -> tuple[str, dict]:
        """Returns (session_key, options_json). user=None for usernameless flow."""
        import webauthn
        import secrets
        from webauthn.helpers.structs import UserVerificationRequirement
        from django.core.cache import cache
        rp_id, _, _ = cls._rp_config()
        allow_credentials = []
        if user:
            from stapel_auth.models import PasskeyCredential
            allow_credentials = [
                webauthn.helpers.structs.PublicKeyCredentialDescriptor(id=bytes(c.credential_id))
                for c in PasskeyCredential.objects.filter(user=user, is_active=True)
            ]
        options = webauthn.generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        session_key = secrets.token_urlsafe(16)
        options_json = webauthn.options_to_json(options)
        cache.set(
            f'passkey_auth:{session_key}',
            {'challenge': options.challenge, 'user_id': str(user.id) if user else None},
            300,
        )
        return session_key, options_json

    @classmethod
    def authentication_complete(cls, session_key: str, credential_data: dict):
        """Returns (user, passkey_credential) or raises ValueError."""
        import webauthn
        from django.core.cache import cache
        rp_id, _, origin = cls._rp_config()
        stored = cache.get(f'passkey_auth:{session_key}')
        if not stored:
            raise ValueError('challenge_expired')
        cache.delete(f'passkey_auth:{session_key}')
        challenge = stored['challenge']
        credential = cls._build_authentication_credential(credential_data)
        cred_id = bytes(credential.raw_id)
        from stapel_auth.models import PasskeyCredential
        try:
            pc = PasskeyCredential.objects.select_related('user').get(
                credential_id=cred_id, is_active=True,
            )
        except PasskeyCredential.DoesNotExist:
            raise ValueError('unknown_credential')
        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=bytes(pc.public_key),
            credential_current_sign_count=pc.sign_count,
        )
        pc.sign_count = verification.new_sign_count
        from django.utils import timezone
        pc.last_used_at = timezone.now()
        pc.save(update_fields=['sign_count', 'last_used_at'])
        from stapel_auth.sessions.services import AuditService
        AuditService.log('passkey_login', user=pc.user, device_name=pc.device_name)
        return pc.user, pc
