"""
Stapel-auth app settings.

Configure via STAPEL_AUTH dict in Django settings:

    STAPEL_AUTH = {
        'FRONTEND_URL': 'https://app.example.com',
        'USE_MOCK_SMS_OTP': True,
    }

Each key falls back to: direct Django setting → env var → built-in default.
"""
import os
from django.test.signals import setting_changed

DEFAULTS = {
    # URLs
    'FRONTEND_URL': None,           # Required in production; falls back to env FRONTEND_URL
    'BACKEND_URL': None,            # Required for SAML/OIDC; falls back to env BACKEND_URL

    # OTP
    'USE_MOCK_SMS_OTP': False,
    'USE_MOCK_EMAIL_OTP': False,
    'MOCK_OTP_CODE': '0000',
    'OTP_TTL': 600,                 # seconds
    'OTP_MAX_ATTEMPTS': 5,
    'OTP_RATE_LIMIT_PER_HOUR': 3,

    # Magic links
    'MAGIC_LINK_TTL': 900,          # seconds (15 min)
    'MAGIC_LINK_RATE_LIMIT_PER_HOUR': 3,

    # QR auth
    'QR_TOKEN_TTL': 300,            # seconds (5 min)

    # Sessions
    'SESSION_TTL_DAYS': 30,

    # Anonymous users
    'ANONYMOUS_USER_LIFETIME_DAYS': 30,

    # JWT cookies (override if needed; usually inherited from stapel-core settings)
    'JWT_COOKIE_DOMAIN': None,

    # TOTP
    'TOTP_ISSUER': 'Stapel',

    # Passkeys (WebAuthn)
    'WEBAUTHN_RP_ID': None,         # Falls back to request host
    'WEBAUTHN_RP_NAME': 'Stapel',
    'WEBAUTHN_ORIGIN': None,        # Falls back to FRONTEND_URL

    # SSO
    'SSO_ENFORCED_REDIRECT_PATH': '/login',

    # Notifications (optional integration)
    'LOGIN_NOTIFICATION_ENABLED': False,

    # Service-to-service
    'INTERNAL_SERVICE_KEY': None,   # Falls back to env INTERNAL_SERVICE_KEY
}

# Env var fallbacks for settings that are commonly set via environment
_ENV_FALLBACKS = {
    'FRONTEND_URL': 'FRONTEND_URL',
    'BACKEND_URL': 'BACKEND_URL',
    'INTERNAL_SERVICE_KEY': 'INTERNAL_SERVICE_KEY',
    'JWT_COOKIE_DOMAIN': 'JWT_COOKIE_DOMAIN',
    'WEBAUTHN_RP_ID': 'WEBAUTHN_RP_ID',
    'WEBAUTHN_ORIGIN': 'WEBAUTHN_ORIGIN',
    'TOTP_ISSUER': 'TOTP_ISSUER',
}


class AuthSettings:
    """
    Lazy accessor for STAPEL_AUTH settings.

    Resolution order per key:
      1. STAPEL_AUTH['KEY'] in Django settings
      2. Direct Django setting (legacy / common.django.settings compat)
      3. Environment variable (for keys in _ENV_FALLBACKS)
      4. Built-in default
    """

    def __init__(self):
        self._cache: dict = {}

    def __getattr__(self, name: str):
        if name.startswith('_') or name not in DEFAULTS:
            raise AttributeError(f'Invalid stapel-auth setting: {name!r}')

        if name in self._cache:
            return self._cache[name]

        from django.conf import settings as django_settings

        user_settings = getattr(django_settings, 'STAPEL_AUTH', {})

        if name in user_settings:
            value = user_settings[name]
        elif hasattr(django_settings, name):
            # Legacy: setting defined directly (e.g. FRONTEND_URL = '...')
            value = getattr(django_settings, name)
        elif name in _ENV_FALLBACKS:
            value = os.getenv(_ENV_FALLBACKS[name], DEFAULTS[name])
        else:
            value = DEFAULTS[name]

        self._cache[name] = value
        return value

    def reload(self):
        self._cache.clear()


auth_settings = AuthSettings()


def _reload_on_change(*, setting, **kwargs):
    if setting == 'STAPEL_AUTH':
        auth_settings.reload()


setting_changed.connect(_reload_on_change)
