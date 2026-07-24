"""Step-up verification factors registered by stapel-auth.

The mechanism (challenge store, grant store, ``@requires_verification``)
lives in ``stapel_core.verification``; this module supplies the concrete
factor implementations on top of the existing auth services and registers
them in the core factor registry from ``apps.py ready()``:

    otp_email — one-time code to the user's verified email
    otp_phone — one-time code to the user's verified phone
    totp      — code from an enrolled authenticator app (verify only)
    passkey   — WebAuthn assertion (begin/complete)

The listed factors are interchangeable: completing any one of them closes
the same challenge. Host projects add their own factors via
``STAPEL_VERIFICATION['EXTRA_FACTORS']`` — the same escape-hatch pattern
as payment providers and notification channels.

Strength canon (workspaces-org-program §C2 — «email-код ≠ 2ФА»): totp,
passkey and otp_phone register as ``strength="strong"``; otp_email keeps
the core default ``"weak"`` — an email code only proves reach to the same
channel that resets the password. Strict "user has 2FA" checks
(``auth.mfa_status``, org require_mfa policies) count strong factors only
via ``stapel_core.verification.strong_factors``.

See docs: flows-and-verification.md §2 in the stapel workspace.
"""
from __future__ import annotations

import json
import logging

from stapel_core.verification import VerificationFactor

logger = logging.getLogger(__name__)


class FactorInitiationError(ValueError):
    """The factor could not be initiated (rate limit, send failure, ...).

    The verification endpoints translate this into a 400
    ``error.400.verification_failed`` response.
    """


class EmailOtpFactor(VerificationFactor):
    """One-time code sent to the user's verified email address.

    Explicitly weak (the core default): an email code is NOT a second
    factor — it proves reach to the password-reset channel, nothing more.
    """

    id = "otp_email"
    strength = "weak"

    def available_for(self, user) -> bool:
        return bool(getattr(user, "email", None)) and bool(
            getattr(user, "is_email_verified", False)
        )

    def initiate(self, user, challenge: dict) -> dict:
        from stapel_auth.otp.services import EmailVerificationService
        from stapel_auth.utils import mask_email

        result = EmailVerificationService().send_verification_code(user.email)
        if result is None or (isinstance(result, dict) and result.get("error")):
            logger.warning(
                "verification otp_email initiate failed user=%s result=%s",
                user.pk, result if isinstance(result, dict) else None,
            )
            raise FactorInitiationError("otp_email_send_failed")
        return {"target": mask_email(user.email)}

    def verify(self, user, challenge: dict, payload: dict) -> bool:
        from stapel_auth.otp.services import EmailVerificationService

        code = str(payload.get("code") or "")
        if not code:
            return False
        result = EmailVerificationService().verify_code(user.email, code)
        return bool(isinstance(result, dict) and result.get("success"))


class PhoneOtpFactor(VerificationFactor):
    """One-time code sent to the user's verified phone number."""

    id = "otp_phone"
    strength = "strong"

    def available_for(self, user) -> bool:
        return bool(getattr(user, "phone", None)) and bool(
            getattr(user, "is_phone_verified", False)
        )

    def initiate(self, user, challenge: dict) -> dict:
        from stapel_auth.otp.services import PhoneVerificationService
        from stapel_auth.utils import mask_phone

        result = PhoneVerificationService().send_verification_code(user.phone)
        if result is None or (isinstance(result, dict) and result.get("error")):
            logger.warning(
                "verification otp_phone initiate failed user=%s result=%s",
                user.pk, result if isinstance(result, dict) else None,
            )
            raise FactorInitiationError("otp_phone_send_failed")
        return {"target": mask_phone(user.phone)}

    def verify(self, user, challenge: dict, payload: dict) -> bool:
        from stapel_auth.otp.services import PhoneVerificationService

        code = str(payload.get("code") or "")
        if not code:
            return False
        result = PhoneVerificationService().verify_code(user.phone, code)
        return bool(isinstance(result, dict) and result.get("success"))


class TotpFactor(VerificationFactor):
    """Code from an enrolled authenticator app (or a one-time backup code).

    Nothing to initiate — the code generator lives on the user's device.
    """

    id = "totp"
    strength = "strong"

    def available_for(self, user) -> bool:
        from stapel_auth.mfa.services import TOTPService

        return TOTPService.is_enabled(user)

    def verify(self, user, challenge: dict, payload: dict) -> bool:
        from stapel_auth.mfa.services import TOTPService

        code = payload.get("code")
        if code:
            return TOTPService.verify_code(user, str(code))
        backup_code = payload.get("backup_code")
        if backup_code:
            return TOTPService.verify_backup_code(user, str(backup_code))
        return False


class PasskeyFactor(VerificationFactor):
    """WebAuthn assertion with one of the user's registered passkeys.

    ``initiate`` returns request options (plus the ``session_key`` binding
    the ceremony); ``verify`` expects ``{"session_key": ..., "credential":
    <assertion>}`` and checks the assertion resolves to the challenge owner.
    """

    id = "passkey"
    strength = "strong"

    def available_for(self, user) -> bool:
        from stapel_auth.models import PasskeyCredential

        return PasskeyCredential.objects.filter(user=user, is_active=True).exists()

    def initiate(self, user, challenge: dict) -> dict:
        from stapel_auth.mfa.services import PasskeyService

        try:
            session_key, options_json = PasskeyService.authentication_begin(user)
        except Exception:
            logger.exception("verification passkey initiate failed user=%s", user.pk)
            raise FactorInitiationError("passkey_begin_failed")
        options = json.loads(options_json) if isinstance(options_json, str) else options_json
        return {"session_key": session_key, "options": options}

    def verify(self, user, challenge: dict, payload: dict) -> bool:
        from stapel_auth.mfa.services import PasskeyService

        session_key = payload.get("session_key")
        credential = payload.get("credential")
        if not session_key or not credential:
            return False
        try:
            assertion_user, _ = PasskeyService.authentication_complete(
                str(session_key), credential
            )
        except ValueError:
            return False
        except Exception:
            logger.exception("verification passkey verify failed user=%s", user.pk)
            return False
        return str(assertion_user.pk) == str(user.pk)


#: Factors stapel-auth registers at startup (apps.py ready()).
DEFAULT_FACTOR_CLASSES = (EmailOtpFactor, PhoneOtpFactor, TotpFactor, PasskeyFactor)


__all__ = [
    "FactorInitiationError",
    "EmailOtpFactor",
    "PhoneOtpFactor",
    "TotpFactor",
    "PasskeyFactor",
    "DEFAULT_FACTOR_CLASSES",
]
