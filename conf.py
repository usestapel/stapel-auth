"""
Stapel-auth app settings.

Configure via STAPEL_AUTH dict in Django settings:

    STAPEL_AUTH = {
        'FRONTEND_URL': 'https://app.example.com',
        'USE_MOCK_SMS_OTP': True,
        'OAUTH_PROVIDERS': {
            'google': {'client_id': '...', 'client_secret': '...'},
        },
    }

Each key falls back to: direct Django setting → env var → built-in default.
"""
import os
from dataclasses import dataclass
from django.test.signals import setting_changed


@dataclass
class OAuthProviderConfig:
    """Credentials for a single OAuth provider.

    Attributes:
        client_id: OAuth app client ID. Example: abc123
        client_secret: OAuth app client secret. Example: secret
    """
    client_id: str
    client_secret: str = ''

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

    # GDPR integration: dotted path to the model that stores re-registration
    # hashes. Resolved lazily — stapel-gdpr is NOT a hard dependency.
    'REREGISTRATION_MODEL': 'stapel_gdpr.models.ReRegistrationHash',

    # Service-to-service
    'INTERNAL_SERVICE_KEY': None,   # Falls back to env INTERNAL_SERVICE_KEY

    # OAuth provider credentials (parsed into dict[str, OAuthProviderConfig])
    'OAUTH_PROVIDERS': {},

    # Dotted-path list of OAuthProvider subclasses to register on startup.
    # Extend in settings to add providers without modifying stapel-auth:
    #   STAPEL_AUTH = {'OAUTH_PROVIDER_CLASSES': [..., 'myapp.providers.YandexProvider']}
    'OAUTH_PROVIDER_CLASSES': [
        'stapel_auth.oauth_providers.GoogleProvider',
        'stapel_auth.oauth_providers.GitHubProvider',
        'stapel_auth.oauth_providers.ZoomProvider',
        'stapel_auth.oauth_providers.FacebookProvider',
        'stapel_auth.oauth_providers.AppleProvider',
        'stapel_auth.oauth_providers.TwitterProvider',
        'stapel_auth.oauth_providers.YandexProvider',
        'stapel_auth.oauth_providers.VKProvider',
        'stapel_auth.oauth_providers.SberProvider',
    ],

    # Registration method gates
    'AUTH_PHONE_REGISTRATION':    True,
    'AUTH_EMAIL_REGISTRATION':    True,
    'AUTH_OAUTH_REGISTRATION':    True,
    'AUTH_SSO_REGISTRATION':      True,
    'AUTH_PASSWORD_REGISTRATION': False,

    # Login method gates
    'AUTH_PHONE_LOGIN':      True,
    'AUTH_EMAIL_LOGIN':      True,
    'AUTH_OAUTH_LOGIN':      True,
    'AUTH_SSO_LOGIN':        True,
    'AUTH_PASSWORD_LOGIN':   False,
    'AUTH_QR_LOGIN':         True,
    'AUTH_PASSKEY_LOGIN':    True,
    'AUTH_MAGIC_LINK_LOGIN': True,

    # Step-up (TOTP challenge) on existing login flows.
    # OAuth: off by default — the provider already authenticated the user;
    # opt back in with OAUTH_STEP_UP=True.
    'OAUTH_STEP_UP': False,
    # Password login: on by default (a password alone is phishable) —
    # preserves the pre-0.3 behavior; opt out with PASSWORD_LOGIN_STEP_UP=False.
    'PASSWORD_LOGIN_STEP_UP': True,

    # Legacy step-up bridge (DEPRECATED, removed in 1.0). A successful
    # /totp/step-up/ additionally writes a server-side verification grant
    # (stapel_core.verification) for each of these scopes, so already-deployed
    # legacy frontends keep passing @requires_verification guards while the
    # backend migrates its sensitive actions off the hand-rolled
    # X-Step-Up-Token check. Set to [] to disable the bridge (issue the legacy
    # token only). See auth-stepup-unification.md.
    'LEGACY_STEP_UP_GRANT_SCOPES': ['sensitive'],
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

        if name == 'OAUTH_PROVIDERS' and isinstance(value, dict):
            value = {
                pid: OAuthProviderConfig(**cfg) if isinstance(cfg, dict) else cfg
                for pid, cfg in value.items()
            }

        self._cache[name] = value
        return value

    def reload(self):
        self.__dict__['_cache'] = {}


auth_settings = AuthSettings()


def _reload_on_change(*, setting, **kwargs):
    # Also reload when a flat (legacy) setting with the same name changes,
    # e.g. override_settings(USE_MOCK_SMS_OTP=False) in tests.
    if setting == 'STAPEL_AUTH' or setting in DEFAULTS:
        auth_settings.reload()


setting_changed.connect(_reload_on_change)
