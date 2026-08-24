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
    # Generated OTP digit count (storage cap is otp.constants.OTP_CODE_LENGTH=8).
    # 6 is the industry default and what this ships with; 4 leaves a 10^4
    # space, which OTP_MAX_ATTEMPTS + OTP_RATE_LIMIT_PER_HOUR only narrow —
    # they do not make it big.
    'OTP_LENGTH': 6,
    'OTP_TTL': 600,                 # seconds — also the single source for the
                                     # AuthCapabilities.otp.ttl_seconds contract
                                     # value (otp/services.py wires this same
                                     # setting into the actual expiry, so the
                                     # two can't drift apart).
    'OTP_MAX_ATTEMPTS': 5,          # wrong codes before the block kicks in
    'OTP_BLOCK_DURATION': 600,      # seconds — how long that block lasts, and
                                    # therefore how long a NEW code cannot be
                                    # requested either (the send path refuses
                                    # while the latest verification is blocked)
    'OTP_RATE_LIMIT_PER_HOUR': 3,
    'OTP_RESEND_COOLDOWN': 30,      # seconds between OTP sends per phone/email
                                     # /device — same single-source relationship
                                     # as OTP_TTL above, surfaced as
                                     # AuthCapabilities.otp.resend_cooldown_seconds.

    # Magic links
    'MAGIC_LINK_TTL': 900,          # seconds (15 min)
    'MAGIC_LINK_RATE_LIMIT_PER_HOUR': 3,

    # QR auth
    'QR_TOKEN_TTL': 300,            # seconds (5 min)

    # Sessions
    'SESSION_TTL_DAYS': 30,
    # Refresh with a valid signature but no tracked UserSession row: deny.
    # Pre-0.21 this was allowed so tokens minted before session tracking
    # existed kept working — and it was the precondition that made a forged
    # refresh token exploitable (audit AUTH-02): "unknown jti" resolved to
    # "legacy token, let it through" for any user with no session row.
    # Turn it on only as a temporary migration aid for a deployment that
    # still has such tokens in the wild; those users otherwise re-login once.
    'ALLOW_UNTRACKED_REFRESH': False,

    # Anonymous users
    'ANONYMOUS_USER_LIFETIME_DAYS': 30,
    # How many NEW guest accounts one client may mint per hour. POST
    # /anonymous/ is unauthenticated and every call used to create a real
    # User row plus a JWT, with a caller-supplied device_id as the only
    # dedup — i.e. a table-growth faucet anyone could hold open. Reusing an
    # existing guest session (same device_id, or an anonymous JWT already in
    # hand) does not count against the budget; only creating a row does.
    # 0 disables the limit and restores the pre-0.21 behavior.
    'ANONYMOUS_RATE_LIMIT_PER_HOUR': 20,
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
    # relies on /totp/challenge/verify/ — leave AUTH_TOTP on where step-up
    # is on.
    'AUTH_TOTP': True,

    # Passkeys (WebAuthn)
    # Falls back to the FRONTEND_URL host — the rpId must be the origin's host
    # or a registrable suffix of it, and the origin below is FRONTEND_URL. Set
    # this explicitly only to share one credential across subdomains
    # (rp_id='example.com' for an origin of 'https://app.example.com').
    'WEBAUTHN_RP_ID': None,
    'WEBAUTHN_RP_NAME': 'Stapel',
    'WEBAUTHN_ORIGIN': None,        # Falls back to FRONTEND_URL

    # SSO
    'SSO_ENFORCED_REDIRECT_PATH': '/login',
    # SAML assertion validation (sso_service.SAMLService). Each of these was
    # an "absent ⇒ accept" branch until 0.21: an assertion with no validity
    # window, an assertion addressed to a different SP, and an unsolicited
    # IdP-initiated response that correlates to no request of ours. Absent
    # now means refuse; a deployment whose IdP cannot be made to comply flips
    # the one branch it needs, and only that one.
    'SAML_REQUIRE_CONDITIONS': True,   # Conditions + NotOnOrAfter must be present
    'SAML_REQUIRE_AUDIENCE': True,     # AudienceRestriction must name our SP
    'SAML_ALLOW_IDP_INITIATED': False,  # accept responses without InResponseTo
    # May an SSO assertion take over an account that already exists here,
    # purely because the email string matches? Off: an existing account is
    # claimed only through an existing org membership or the org's own
    # configured domain (see sso_service._may_claim_existing_account).
    'SSO_LINK_EXISTING_BY_EMAIL': False,

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

    # Which OAuth client IDs a CALLER-SUPPLIED access token may have been
    # issued to, per provider: {'google': ['<web>.apps.googleusercontent.com',
    # '<ios>.apps.googleusercontent.com']}.
    #
    # `POST /oauth/login/` takes an access token straight from the request
    # body and issues our session for whoever it resolves to. A token is a
    # bearer credential for the client it was minted for — so without this
    # pin, a token minted for SOMEBODY ELSE'S OAuth app against the victim's
    # provider account is accepted here as proof of identity. That is a login
    # takeover, and it is why the token-body endpoint is only safe once the
    # audiences are pinned (audit F-OAUTH).
    #
    # Unset for a provider = its own `client_id` from OAUTH_PROVIDERS, which
    # is the only audience we can infer. Declare the list explicitly whenever
    # the same account is reached through more than one client — Google issues
    # SEPARATE client IDs per platform (Web / iOS / Android) for one project,
    # so a mobile app's token legitimately carries a different `aud`.
    # `stapel_auth.W007` says so at boot; `stapel_auth.E008` fires when there
    # is nothing to pin to at all.
    #
    # The authorization-code flow (`/oauth/{provider}/authorize/` →
    # `/callback/`) is unaffected: that token comes from our own
    # client_secret exchange, so its audience is ours by construction.
    'OAUTH_ACCEPTED_AUDIENCES': {},

    # Path of the OAuth callback this service SENDS as `redirect_uri`,
    # relative to the host root ('{provider}' is substituted; the default
    # keeps the module's canonical v1 route).
    #
    # This is a contract with a THIRD PARTY: the value must be registered
    # verbatim in the provider's console, so it cannot be a library
    # implementation detail. Moving the module's urlconf onto /v1/ silently
    # re-pointed it and every live deployment started sending a redirect_uri
    # its Google/GitHub app had never seen — `Error 400:
    # redirect_uri_mismatch`, login dead, nothing in our logs (ironmemo
    # stand, 2026-07-25). Hosts that cannot re-register keep the old URI by
    # pinning it here (and routing that path to the current view).
    'OAUTH_CALLBACK_PATH': '/{url_prefix}api/v1/oauth/{provider}/callback',

    # Where the JWKS document really lives, as advertised by the OIDC
    # discovery document (`jwks_uri`). None = the module's own DRF route
    # (openid/views.py derives it with reverse('jwks'), so it follows the
    # mount). Set it only for the OTHER legitimate deployment: the static
    # jwks.json that stapel_core.django.openapi.openid.generate_jwks_to_dir()
    # writes into /var/www/.well-known/ at bootstrap for nginx to serve from
    # the HOST ROOT — `JWKS_URI = '/.well-known/jwks.json'`. That file is not
    # a Django route, so it is the deployment's claim to make, not ours.
    #
    # Why a knob and not a literal: discovery used to hardcode
    # `/{URL_PREFIX}.well-known/jwks.json` — the shape the pre-library
    # monolith mounted the view at (marketplace core/urls.py). In the library
    # the view sits under the module mount instead, so the advertised URL
    # matched neither the DRF route nor the nginx file, and every external
    # OIDC client that read discovery got a 404 (2026-07).
    'JWKS_URI': None,

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

    # What a CLOSED registration axis looks like from outside, on the two
    # enumerable surfaces (email/phone OTP request+verify). See
    # registration.py for the full argument; short version:
    #   'silent'  (default) — identical answer for known and unknown targets;
    #                         strangers simply never receive the code. No
    #                         existence oracle; a typo waits for nothing.
    #   'request' — 403 error.403.registration_closed at */request for an
    #               unknown target. Usable and honest, fully enumerable.
    #   'verify'  — code still sent, 403 at */verify. Enumerable AND mails
    #               strangers; smallest diff from the pre-#86 behavior.
    # Unknown values degrade to 'silent' (the closed end), and the knob is
    # no_env for the same reason the boolean gates are.
    'AUTH_REGISTRATION_CLOSED_BEHAVIOR': 'silent',

    # THE IDENTITY MODEL knob (owner directive 2026-07-20). By default a
    # password is a CREDENTIAL, not an identity: setting one on an anonymous
    # guest session only makes that SAME account portable (loginable from
    # another device) — it does NOT deanonymize/promote (register() returns
    # MODIFIED, the row stays anonymous). A deployment that deliberately wants
    # classic login/password accounts ("90s-style" — username+password IS the
    # account) flips this to True: a password-only register() on an anonymous
    # session then promotes it (auth_type="password", returns REGISTERED).
    # Pair it with the frontend's `registrationAnchors` including "password"
    # so the register surface actually offers the form. Independent of
    # AUTH_PASSWORD_REGISTRATION, which gates whether password can register at
    # all; this gates whether that registration DEANONYMIZES.
    'AUTH_PASSWORD_DEANONYMIZES':  False,

    # Login method gates
    'AUTH_PHONE_LOGIN':      True,
    'AUTH_EMAIL_LOGIN':      True,
    # Gates BOTH OAuth login doors, which are not equally safe by
    # construction:
    #   * `/oauth/{provider}/authorize/` -> `/callback/` — the authorization
    #     code flow. The access token is minted by OUR client_secret
    #     exchange, so it is ours by construction; nothing to pin.
    #   * `POST /oauth/login/` — the token-body endpoint: the CALLER hands us
    #     an access token. A token is a bearer credential for the OAuth
    #     client it was issued to, so one minted for somebody else's app
    #     against the victim's provider account would log us in as the
    #     victim. **This door is only safe once OAUTH_ACCEPTED_AUDIENCES
    #     pins which client IDs may vouch for an identity** — unpinned or
    #     unverifiable, it refuses (see checks W007/E008 and the audience
    #     notes on OAUTH_ACCEPTED_AUDIENCES above).
    # Turn this off entirely if you only ever use the redirect flow and want
    # the token-body route gone rather than merely pinned.
    'AUTH_OAUTH_LOGIN':      True,
    'AUTH_SSO_LOGIN':        True,
    'AUTH_PASSWORD_LOGIN':   False,
    'AUTH_QR_LOGIN':         True,
    'AUTH_PASSKEY_LOGIN':    True,
    'AUTH_MAGIC_LINK_LOGIN': True,
    # Login grant (workspaces-org-program §B3): POST /grant/exchange/ trades a
    # comm-minted single-use token (auth.issue_login_grant) for a JWT session.
    # Off by default — only deployments running the workspaces invite flow (or
    # another trusted grant issuer) should expose the exchange endpoint.
    'AUTH_LOGIN_GRANT':      False,
    # Legacy credential endpoint POST /token/ — the pre-0.4 alias of
    # /password/login/, kept for clients pinned to the TokenPair response
    # shape. Off by default: it is a second door onto password login, and a
    # deployment should have to say out loud that it still needs it. When on
    # it ALSO requires AUTH_PASSWORD_LOGIN and behaves like the dedicated
    # path (lockout + PASSWORD_LOGIN_STEP_UP); before 0.21 it was mounted
    # unconditionally and consulted none of the three.
    'AUTH_LEGACY_TOKEN_LOGIN': False,

    # Login method placement (UI composition — capability-config.md §1 sibling
    # axis to the *_LOGIN gates above): where the frontend renders each
    # method's trigger. One of 'main' (inline in the primary tab strip),
    # 'overflow' (behind the "more" / three-dot menu) or 'bottom' (bottom
    # row of secondary buttons — social/QR/passkey territory). Purely
    # presentational: it never gates availability (that's the *_LOGIN axis);
    # a hidden method's placement is simply not emitted (docs/capabilities.json
    # capabilities.py contract). Consumed by GET /auth/api/v1/capabilities/
    # (AuthCapabilitiesService.get_capabilities → AuthMethodInfo.placement).
    'AUTH_EMAIL_PLACEMENT':       'main',
    'AUTH_PHONE_PLACEMENT':       'main',
    'AUTH_PASSWORD_PLACEMENT':    'overflow',
    'AUTH_MAGIC_LINK_PLACEMENT':  'overflow',
    'AUTH_SSO_PLACEMENT':         'bottom',
    'AUTH_OAUTH_PLACEMENT':       'bottom',
    'AUTH_QR_PLACEMENT':          'bottom',
    'AUTH_PASSKEY_PLACEMENT':     'bottom',

    # Step-up (TOTP challenge) on existing login flows.
    # OAuth: off by default — the provider already authenticated the user;
    # opt back in with OAUTH_STEP_UP=True.
    'OAUTH_STEP_UP': False,
    # Password login: on by default (a password alone is phishable) —
    # preserves the pre-0.3 behavior; opt out with PASSWORD_LOGIN_STEP_UP=False.
    'PASSWORD_LOGIN_STEP_UP': True,

    # Which session-issuance paths the first-login policy flags
    # (password_change_required / mfa_enrollment_required) block. See
    # sessions/guard.py — the single gate inside the final session minter.
    #   '*'                      — every path (default): the flag is read as
    #                              "a mandatory step before ANY admission".
    #   ['password', ...]        — only the listed sessions.guard.SessionPath
    #                              labels; ['password', 'legacy_token'] is the
    #                              narrow "password admission only" reading,
    #                              which leaves OTP/magic-link/OAuth open to a
    #                              flagged account on purpose.
    # NB: this knob covers the FLAGS only. `is_active=False` is refused on
    # every path unconditionally and is not configurable.
    'FIRST_LOGIN_GATE_PATHS': '*',
}

# Keys that must never fall back to an environment variable (AppSettings
# ``no_env``). Classification rule, following stapel-core conventions
# (netintel/gateway/access conf):
#   * secrets and trust anchors (INTERNAL_SERVICE_KEY, OAUTH_PROVIDERS,
#     OAUTH_ACCEPTED_AUDIENCES) — a
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
    # The audience pin IS the trust anchor of the token-body login endpoint:
    # a stray env var must not be able to widen (or, as a string, mangle)
    # which OAuth clients may vouch for an identity.
    'OAUTH_ACCEPTED_AUDIENCES',
    'OAUTH_PROVIDER_CLASSES',
    'REREGISTRATION_MODEL',
    'MOCK_OTP_CODE',
    # Scope list, and a security one: a stray env var must not be able to
    # narrow which paths the first-login policy gate covers (and a list value
    # cannot survive the string round-trip anyway).
    'FIRST_LOGIN_GATE_PATHS',
    # Same class: a stray env var must not be able to turn a closed
    # registration into an account-existence oracle.
    'AUTH_REGISTRATION_CLOSED_BEHAVIOR',
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
