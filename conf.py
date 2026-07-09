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

Built on ``stapel_core.conf.AppSettings`` — the shared per-app settings
namespace. Resolution order per key: ``settings.STAPEL_AUTH`` dict → flat
Django setting of the same name (legacy) → environment variable (except
``no_env`` keys, see below) → built-in default.
"""
from dataclasses import dataclass

from stapel_core.conf import AppSettings


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
    # Anonymous auth axis: gates POST /anonymous/ (own URL factory) and the
    # `anonymous` capability. Independent of the email/phone method gates.
    'AUTH_ANONYMOUS': True,

    # JWT cookies (override if needed; usually inherited from stapel-core settings)
    'JWT_COOKIE_DOMAIN': None,

    # TOTP
    'TOTP_ISSUER': 'Stapel',
    # TOTP axis: gates the /totp/* endpoints in get_mfa_urls (the same way
    # AUTH_PASSKEY_LOGIN gates the /passkey/* block) and the mfa.totp
    # capability. NB: step-up (PASSWORD_LOGIN_STEP_UP / OAUTH_STEP_UP)
    # relies on /totp/challenge/verify/ and /totp/step-up/ — leave AUTH_TOTP
    # on where step-up is on.
    'AUTH_TOTP': True,

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

    # Service-to-service key. no_env: set it via STAPEL_AUTH or a flat
    # Django setting — a stray same-named env var must not become the
    # service-to-service trust anchor silently.
    'INTERNAL_SERVICE_KEY': None,

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

# Keys that must never fall back to an environment variable (AppSettings
# ``no_env``). Classification rule, following stapel-core conventions
# (netintel/gateway/access conf):
#   * secrets and trust anchors (INTERNAL_SERVICE_KEY, OAUTH_PROVIDERS) — a
#     stray same-named env var must never become a trust decision silently;
#   * dotted-path seams (OAUTH_PROVIDER_CLASSES, REREGISTRATION_MODEL) and
#     scope lists — they decide what code runs / what grants are written;
#   * every boolean gate (AUTH_* method gates, step-up, mocks) — env vars are
#     strings, and any non-empty string is truthy, so "AUTH_PASSWORD_LOGIN=
#     false" in the environment would silently ENABLE password login.
# Everything else (URLs, TTLs, issuer names, …) stays env-readable — the
# deployment-convenience knobs the pre-AppSettings conf already read from env.
_NO_ENV = tuple(
    key for key, default in DEFAULTS.items() if isinstance(default, bool)
) + (
    'INTERNAL_SERVICE_KEY',
    'OAUTH_PROVIDERS',
    'OAUTH_PROVIDER_CLASSES',
    'REREGISTRATION_MODEL',
    'LEGACY_STEP_UP_GRANT_SCOPES',
    'MOCK_OTP_CODE',
)

# NB: OAUTH_PROVIDER_CLASSES / REREGISTRATION_MODEL are intentionally NOT in
# AppSettings ``import_strings``: their call sites resolve the dotted paths
# themselves — apps.py imports each provider class (and appends TestProvider
# under DEBUG), gdpr.py degrades gracefully with a warning when the optional
# stapel-gdpr model is absent. import_strings would import eagerly and raise.


class AuthSettings(AppSettings):
    """STAPEL_AUTH namespace (stapel_core.conf.AppSettings).

    Adds one auth-specific convenience on top of the shared pattern:
    ``OAUTH_PROVIDERS`` dict values are coerced into ``OAuthProviderConfig``
    dataclasses on access.
    """

    def __init__(self):
        super().__init__('STAPEL_AUTH', defaults=DEFAULTS, no_env=_NO_ENV)

    def __getattr__(self, key: str):
        value = super().__getattr__(key)
        if key == 'OAUTH_PROVIDERS' and isinstance(value, dict):
            value = {
                pid: OAuthProviderConfig(**cfg) if isinstance(cfg, dict) else cfg
                for pid, cfg in value.items()
            }
            self._cache[key] = value
        return value


auth_settings = AuthSettings()
