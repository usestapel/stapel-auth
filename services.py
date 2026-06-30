"""Backward-compatibility shim — re-exports from sub-packages."""
from stapel_auth.sessions.services import (  # noqa: F401
    TokenService, _parse_ua, _parse_device_name,
    SessionService, AuditService, LoginNotificationService,
)
from stapel_auth.otp.services import PhoneVerificationService, EmailVerificationService, AuthenticatorChangeService  # noqa: F401
from stapel_auth.oauth.services import OAuthService  # noqa: F401
from stapel_auth.security.services import SecurityService  # noqa: F401
from stapel_auth.password.services import PasswordService  # noqa: F401
from stapel_auth.mfa.services import TOTPService, PasskeyService  # noqa: F401
from stapel_auth.security.services import LockoutService  # noqa: F401
from stapel_auth.magic_link.services import MagicLinkService  # noqa: F401
