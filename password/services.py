"""Service for password login, set, change, and OTP-based reset."""
import logging

from stapel_core.django.api.errors import IronServiceError, ERR_500_INTERNAL

from stapel_auth.password.dto import PasswordMethod, PasswordMethodType
from stapel_auth.otp.services import EmailVerificationService, PhoneVerificationService
from stapel_auth.mfa.services import TOTPService

logger = logging.getLogger(__name__)


# ── Password service ─────────────────────────────────────────────────────────

class PasswordService:
    """Password login, set, change, and OTP-based reset."""

    @staticmethod
    def mask_email(email: str) -> str:
        if not email or '@' not in email:
            return '***'
        local, domain = email.split('@', 1)
        masked = local[0] + '***' if len(local) > 1 else '***'
        return f"{masked}@{domain}"

    @staticmethod
    def mask_phone(phone: str) -> str:
        if not phone or len(phone) < 4:
            return '***'
        return phone[:3] + '***' + phone[-2:]

    @staticmethod
    def _check_mock_admin(user) -> None:
        """Block OTP flows for staff/superuser accounts when mock OTP is active."""
        from django.conf import settings
        from stapel_auth.errors import ERR_403_MOCK_OTP_ADMIN
        if (user.is_staff or user.is_superuser) and (
            getattr(settings, 'USE_MOCK_EMAIL_OTP', False) or
            getattr(settings, 'USE_MOCK_SMS_OTP', False)
        ):
            raise IronServiceError(403, ERR_403_MOCK_OTP_ADMIN)

    @staticmethod
    def _raise_for_otp_result(result) -> None:
        """Convert an OTP service result to IronServiceError. No-op on success."""
        from stapel_auth.errors import (
            ERR_400_CODE_EXPIRED, ERR_400_INVALID_CODE, ERR_400_INVALID_CODE_ATTEMPTS,
            ERR_400_NO_VERIFIED_CONTACT, ERR_400_INVALID_METHOD, ERR_404_USER_FOR_RESET,
            ERR_422_BLOCKED, retry_params,
        )
        from stapel_core.django.api.errors import ERR_429_RATE_LIMIT
        if not isinstance(result, dict):
            if not result:
                raise IronServiceError(500, ERR_500_INTERNAL)
            return  # success object
        err = result.get('error')
        if not err:
            return  # success dict
        if err == 'rate_limit':
            raise IronServiceError(429, ERR_429_RATE_LIMIT, params=retry_params(result.get('retry_after')))
        if err == 'blocked':
            raise IronServiceError(422, ERR_422_BLOCKED, params=retry_params(result.get('retry_after')))
        if err in ('expired', 'expired_retry_allowed'):
            raise IronServiceError(400, ERR_400_CODE_EXPIRED)
        if err == 'invalid_code':
            rem = result.get('attempts_remaining')
            if rem is not None:
                raise IronServiceError(400, ERR_400_INVALID_CODE_ATTEMPTS, params={'attempts_remaining': rem})
            raise IronServiceError(400, ERR_400_INVALID_CODE)
        if err == 'no_verified_contact':
            raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
        if err == 'invalid_method':
            raise IronServiceError(400, ERR_400_INVALID_METHOD)
        if err == 'user_not_found':
            raise IronServiceError(404, ERR_404_USER_FOR_RESET)
        raise IronServiceError(500, ERR_500_INTERNAL)

    @classmethod
    def get_available_methods(cls, user) -> list:
        methods = []
        if user.has_usable_password():
            methods.append(PasswordMethod(method=PasswordMethodType.PASSWORD))
        if user.email and user.is_email_verified:
            methods.append(PasswordMethod(method=PasswordMethodType.EMAIL, target=cls.mask_email(user.email)))
        if user.phone and user.is_phone_verified:
            methods.append(PasswordMethod(method=PasswordMethodType.PHONE, target=cls.mask_phone(user.phone)))
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
    def change_via_old(user, old_password: str, new_password: str) -> bool:
        if not user.check_password(old_password):
            return False
        user.set_password(new_password)
        user.save(update_fields=['password'])
        return True

    @classmethod
    def send_change_otp(cls, user, method: PasswordMethodType) -> str:
        """Send OTP for password change. Returns masked target. Raises IronServiceError."""
        from stapel_auth.errors import ERR_400_NO_VERIFIED_CONTACT, ERR_400_INVALID_METHOD
        cls._check_mock_admin(user)
        if method == PasswordMethodType.EMAIL:
            if not user.email or not user.is_email_verified:
                raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = EmailVerificationService().send_verification_code(user.email)
            cls._raise_for_otp_result(result)
            return cls.mask_email(user.email)
        if method == PasswordMethodType.PHONE:
            if not user.phone or not user.is_phone_verified:
                raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = PhoneVerificationService().send_verification_code(user.phone)
            cls._raise_for_otp_result(result)
            return cls.mask_phone(user.phone)
        if method == PasswordMethodType.TOTP:
            if not TOTPService.is_enabled(user):
                raise IronServiceError(400, ERR_400_INVALID_METHOD)
            return ''  # TOTP needs no "send" — code is already in the authenticator app
        raise IronServiceError(400, ERR_400_INVALID_METHOD)

    @classmethod
    def change_via_otp(cls, user, method: PasswordMethodType, code: str, new_password: str) -> None:
        """Verify OTP/TOTP and update password. Raises IronServiceError on any error."""
        from stapel_auth.errors import ERR_400_NO_VERIFIED_CONTACT, ERR_400_INVALID_METHOD, ERR_400_INVALID_CODE
        if method == PasswordMethodType.EMAIL:
            if not user.email or not user.is_email_verified:
                raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = EmailVerificationService().verify_code(user.email, code)
            cls._raise_for_otp_result(result)
        elif method == PasswordMethodType.PHONE:
            if not user.phone or not user.is_phone_verified:
                raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = PhoneVerificationService().verify_code(user.phone, code)
            cls._raise_for_otp_result(result)
        elif method == PasswordMethodType.TOTP:
            if not TOTPService.is_enabled(user):
                raise IronServiceError(400, ERR_400_INVALID_METHOD)
            if not TOTPService.verify_code(user, code):
                raise IronServiceError(400, ERR_400_INVALID_CODE)
        else:
            raise IronServiceError(400, ERR_400_INVALID_METHOD)
        user.set_password(new_password)
        user.save(update_fields=['password'])

    @classmethod
    def reset_request(cls, *, email=None, phone=None) -> str:
        """Send reset OTP. Returns masked target. Raises IronServiceError."""
        from stapel_auth.errors import ERR_404_USER_FOR_RESET
        from django.contrib.auth import get_user_model
        User = get_user_model()
        if email:
            try:
                user = User.objects.get(email=email, is_email_verified=True)
            except User.DoesNotExist:
                raise IronServiceError(404, ERR_404_USER_FOR_RESET)
            cls._check_mock_admin(user)
            result = EmailVerificationService().send_verification_code(email)
            cls._raise_for_otp_result(result)
            return cls.mask_email(email)
        try:
            user = User.objects.get(phone=phone, is_phone_verified=True)
        except User.DoesNotExist:
            raise IronServiceError(404, ERR_404_USER_FOR_RESET)
        cls._check_mock_admin(user)
        result = PhoneVerificationService().send_verification_code(phone)
        cls._raise_for_otp_result(result)
        return cls.mask_phone(phone)

    @classmethod
    def reset_verify(cls, *, email=None, phone=None, code: str, new_password: str):
        """Verify OTP and reset password. Returns User. Raises IronServiceError."""
        from stapel_auth.errors import ERR_404_USER_FOR_RESET
        from django.contrib.auth import get_user_model
        User = get_user_model()
        if email:
            result = EmailVerificationService().verify_code(email, code)
            cls._raise_for_otp_result(result)
            try:
                user = User.objects.get(email=email, is_email_verified=True)
            except User.DoesNotExist:
                raise IronServiceError(404, ERR_404_USER_FOR_RESET)
        else:
            result = PhoneVerificationService().verify_code(phone, code)
            cls._raise_for_otp_result(result)
            try:
                user = User.objects.get(phone=phone, is_phone_verified=True)
            except User.DoesNotExist:
                raise IronServiceError(404, ERR_404_USER_FOR_RESET)
        user.set_password(new_password)
        user.save(update_fields=['password'])
        return user
