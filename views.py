"""Backward-compatibility shim — imports from sub-packages."""
from stapel_auth.sessions.views import CustomTokenObtainPairView, CustomTokenRefreshView, SessionViewSet, _issue_session_tokens, _add_login_hints
from stapel_auth.otp.views import AuthViewSet, AuthenticatorChangeViewSet
from stapel_auth.password.views import PasswordViewSet
from stapel_auth.qr.views import QRAuthViewSet
from stapel_auth.mfa.views import TOTPViewSet, PasskeyViewSet
from stapel_auth.security.views import SecurityStatusViewSet, AuditLogViewSet, RevokeSuspiciousView
from stapel_auth.magic_link.views import MagicLinkViewSet
from stapel_auth.openid.views import JWKSView, OpenIDConfigurationView
from stapel_auth.admin.views import ServiceAPIKeyViewSet, AdminUserViewSet, CapabilitiesView
