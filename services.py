"""Backward-compatibility shim — imports from sub-packages."""
from stapel_auth.otp.services import PhoneVerificationService, EmailVerificationService, AuthenticatorChangeService
from stapel_auth.oauth.services import OAuthService, AuthCapabilitiesService
from stapel_auth.sessions.services import TokenService, TokenPair, SessionService, AuditService, LoginNotificationService, _blacklist_jti, _parse_ua, _get_client_ip, _parse_device_name
from stapel_auth.password.services import PasswordService
from stapel_auth.qr.services import QRAuthService
from stapel_auth.mfa.services import TOTPService, PasskeyService
from stapel_auth.security.services import SecurityService, LockoutService
from stapel_auth.magic_link.services import MagicLinkService
