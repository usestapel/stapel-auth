"""OAuth service classes for authentication routing and capabilities."""
import logging

logger = logging.getLogger(__name__)


class OAuthService:
    """Service for OAuth authentication — routes through provider registry."""

    def get_user_data(self, provider, access_token):
        """Fetch user data from the given OAuth provider."""
        from stapel_core.oauth import get_provider
        p = get_provider(provider)
        if not p:
            logger.error(f"Unsupported OAuth provider: {provider}")
            return None
        try:
            return p.get_user_data(access_token)
        except Exception as e:
            logger.error(f"Failed to get user data from {provider}: {e}")
            return None


class AuthCapabilitiesService:
    """Builds the auth capabilities response based on current settings."""

    @staticmethod
    def get_capabilities():
        from stapel_auth.conf import auth_settings
        from stapel_auth.oauth.dto import (
            AuthCapabilities,
            LoginCapabilities,
            OAuthProviderInfo,
            RegistrationCapabilities,
        )
        from stapel_auth.oauth_providers import get_enabled_providers

        s = auth_settings
        phone_real = not s.USE_MOCK_SMS_OTP
        email_real = not s.USE_MOCK_EMAIL_OTP
        oauth_infos = [
            OAuthProviderInfo(id=p.id, name=p.display_name)
            for p in get_enabled_providers()
        ]
        return AuthCapabilities(
            registration=RegistrationCapabilities(
                phone=s.AUTH_PHONE_REGISTRATION and phone_real,
                email=s.AUTH_EMAIL_REGISTRATION and email_real,
                password=s.AUTH_PASSWORD_REGISTRATION,
                oauth=oauth_infos if s.AUTH_OAUTH_REGISTRATION else [],
                sso=s.AUTH_SSO_REGISTRATION,
                anonymous=s.AUTH_ANONYMOUS,
            ),
            login=LoginCapabilities(
                phone=s.AUTH_PHONE_LOGIN and phone_real,
                email=s.AUTH_EMAIL_LOGIN and email_real,
                password=s.AUTH_PASSWORD_LOGIN,
                oauth=oauth_infos if s.AUTH_OAUTH_LOGIN else [],
                sso=s.AUTH_SSO_LOGIN,
                qr=s.AUTH_QR_LOGIN,
                passkey=s.AUTH_PASSKEY_LOGIN,
                magic_link=s.AUTH_MAGIC_LINK_LOGIN,
            ),
        )
