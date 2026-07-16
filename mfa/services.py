"""Service classes for MFA (TOTP and Passkey) domain."""
import hashlib as _hashlib
import secrets as _secrets
import warnings as _warnings


class TOTPService:
    BACKUP_CODE_COUNT = 8
    STEP_UP_TTL = 900        # 15 min
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
    def setup(cls, user) -> dict:
        """
        Start TOTP enrollment. Returns secret + otpauth URI.
        Creates/replaces a pending (is_active=False) TOTPDevice.
        """
        import pyotp
        from stapel_auth.models import TOTPDevice

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

        device.is_active = True
        device.backup_codes = hashed_codes
        device.confirmed_at = timezone.now()
        device.save()
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
        device.delete()
        return True

    @classmethod
    def force_disable(cls, user) -> bool:
        """Disable TOTP without code check. Call only after external OTP verification."""
        from stapel_auth.models import TOTPDevice
        return TOTPDevice.objects.filter(user=user, is_active=True).delete()[0] > 0

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

    # ── step-up (LEGACY, deprecated — removed in 1.0) ─────────────────────────
    #
    # The one-time X-Step-Up-Token mechanism is superseded by the unified
    # step-up contract: @requires_verification + the verification envelope
    # (stapel_core.verification). Migrate sensitive actions to
    # ``@requires_verification(scope=..., factors=["totp"], max_age=900)`` and
    # drop any hand-rolled X-Step-Up-Token check. See auth-stepup-unification.md.

    @classmethod
    def _issue_step_up_token(cls, user, code: str) -> str | None:
        """Verify TOTP and mint a one-time step-up token. None on bad code.

        Internal, warning-free entry point used by the (already deprecated)
        /totp/step-up/ endpoint. Public deprecated wrappers below delegate here.
        """
        if not cls.verify_code(user, code):
            return None
        from django.core.cache import cache
        token = _secrets.token_urlsafe(32)
        cache.set(f'step_up:{user.id}:{token}', '1', cls.STEP_UP_TTL)
        return token

    @classmethod
    def create_step_up(cls, user, code: str) -> str | None:
        """Verify TOTP code and issue a step-up token. Returns None on bad code.

        .. deprecated::
            The legacy one-time step-up token is superseded by the verification
            envelope. Use ``@requires_verification`` instead; this method is
            removed in stapel-auth 1.0.
        """
        _warnings.warn(
            "TOTPService.create_step_up is deprecated and will be removed in "
            "stapel-auth 1.0 — use @requires_verification (scope + factors + "
            "max_age) instead of the one-time X-Step-Up-Token.",
            DeprecationWarning,
            stacklevel=2,
        )
        return cls._issue_step_up_token(user, code)

    @classmethod
    def consume_step_up(cls, user, token: str) -> bool:
        """Check (and delete) a step-up token for the given user.

        .. deprecated::
            Enforcement moves to ``@requires_verification`` /
            ``stapel_core.verification.has_grant``. Removed in stapel-auth 1.0.
        """
        _warnings.warn(
            "TOTPService.consume_step_up is deprecated and will be removed in "
            "stapel-auth 1.0 — enforce step-up with @requires_verification "
            "(server-side grant) instead of reading X-Step-Up-Token.",
            DeprecationWarning,
            stacklevel=2,
        )
        from django.core.cache import cache
        key = f'step_up:{user.id}:{token}'
        val = cache.get(key)
        if val:
            cache.delete(key)
            return True
        return False


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
        from stapel_auth.models import PasskeyCredential
        pc = PasskeyCredential.objects.create(
            user=user,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            aaguid=str(verification.aaguid) if verification.aaguid else '',
            device_name=device_name or 'Passkey',
            transports=list(credential.response.transports or []),
        )
        from stapel_auth.services import AuditService
        AuditService.log('passkey_registered', user=user, device_name=pc.device_name)
        return pc

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
        from stapel_auth.services import AuditService
        AuditService.log('passkey_login', user=pc.user, device_name=pc.device_name)
        return pc.user, pc
