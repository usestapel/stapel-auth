"""Business flows of the auth service (stapel_core.flows).

Autodiscovered via INSTALLED_APPS by ``autodiscover_flows()`` (the
``check_flows`` / ``generate_flow_docs`` management commands run it).

HTTP steps are attached here, post-hoc, by decorating the already-imported
view methods: views must not import this module (flows.py imports the view
classes — the dependency points one way, so no import cycle), and
``@flow_step`` only annotates the callable, so decorating after class
creation is equivalent to stacking the decorator in the view module.

i18n (flow-system.md §2, reference migration): the literals below are the
canonical **English** source texts; every flow/step derives an implicit
i18n key (``flow.<id>.title`` / ``flow.<id>.description`` /
``flow.<id>.step.<order>.note``). The committed catalogs
``translations/flows.en.json`` / ``translations/flows.ru.json`` carry the
same key set (en mirrors the literals — enforced by tests); rendering in a
language resolves the keys via ``stapel_core.flows.i18n``.
"""
from stapel_core.flows import Flow, flow_step

from stapel_auth.mfa.views import MfaEnrollViewSet, TOTPViewSet
from stapel_auth.otp.views import AuthViewSet
from stapel_auth.password.views import PasswordViewSet
from stapel_auth.verification.views import VerificationPreferenceViewSet, VerificationViewSet

# ─────────────────────────────────────────────────────────────────────────────
# auth.passwordless_login
# ─────────────────────────────────────────────────────────────────────────────

PASSWORDLESS_LOGIN = Flow(
    "auth.passwordless_login",
    title="Passwordless login (email OTP)",
    description=(
        "An anonymous user receives a one-time code by email and exchanges it "
        "for a JWT session (cookies + a token pair in the response body). "
        "Requesting the code again is rate-limited (30 seconds between sends; "
        "429/422 when exceeded); after a series of wrong codes the address is "
        "temporarily locked. If the address was not registered, the first "
        "successful login creates a new user (status=REGISTERED instead of "
        "LOGGED_IN)."
    ),
    actors=["Anonymous user"],
)

PASSWORDLESS_LOGIN.human(order=0, note="The user enters their email on the login form")
flow_step(
    PASSWORDLESS_LOGIN, order=1,
    note="Request a one-time code by email; 429 on rate limit, 422 when the address is locked",
)(AuthViewSet.email_request)
flow_step(
    PASSWORDLESS_LOGIN, order=2,
    note="Exchange the code for a JWT session; a wrong code decrements the attempt counter",
)(AuthViewSet.email_verify)
PASSWORDLESS_LOGIN.action(
    "user.registered", order=3,
    note="Emitted on first login — the profile and workspace are created by subscribers",
)

# ─────────────────────────────────────────────────────────────────────────────
# auth.password_login
# ─────────────────────────────────────────────────────────────────────────────

PASSWORD_LOGIN = Flow(
    "auth.password_login",
    title="Password login (+ optional TOTP)",
    description=(
        "The user signs in with a login (email/username) and password. The "
        "endpoint is enabled by the AUTH_PASSWORD_LOGIN setting. Failed "
        "attempts lead to progressive lockout (423 with retry_after). If the "
        "user has TOTP enabled and the PASSWORD_LOGIN_STEP_UP setting is "
        "active (default: yes), TOTP_REQUIRED with a challenge_token is "
        "returned instead of tokens — the session is issued only after the "
        "authenticator code is verified."
    ),
    actors=["Anonymous user"],
)

PASSWORD_LOGIN.human(order=0, note="The user enters their login and password on the login form")
flow_step(
    PASSWORD_LOGIN, order=1,
    note=(
        "Verify the password; 423 when locked out; with TOTP enabled and "
        "PASSWORD_LOGIN_STEP_UP — a TOTP_REQUIRED response with a challenge_token"
    ),
)(PasswordViewSet.login)
flow_step(
    PASSWORD_LOGIN, order=2,
    note=(
        "Optional step (only on TOTP_REQUIRED): exchange the challenge_token "
        "and the authenticator code for a JWT session"
    ),
)(TOTPViewSet.challenge_verify)

# ─────────────────────────────────────────────────────────────────────────────
# auth.first_login — org-provisioned accounts (workspaces-org-program §C1-C2)
# ─────────────────────────────────────────────────────────────────────────────

FIRST_LOGIN = Flow(
    "auth.first_login",
    title="First login of an org-provisioned account",
    description=(
        "An organization admin provisioned the account (auth.provision_user: "
        "namespaced username org_slug/local, org-set or server-generated "
        "password, a first-login policy flag). The first password login "
        "returns FIRST_LOGIN_REQUIRED with a 10-minute challenge_token "
        "instead of a session: requires=password_change routes to the forced "
        "password change, requires=mfa_enroll to a limited enroll-only "
        "session in which only TOTP setup/confirm, passkey registration and "
        "logout are allowed. Completing the step clears the flag and yields "
        "a full session; when both flags are set, the password change chains "
        "straight into the mfa_enroll challenge."
    ),
    actors=["Org-provisioned user"],
)

FIRST_LOGIN.human(
    order=0,
    note=(
        "The org admin hands over the namespaced login (org_slug/username) "
        "and the initial password out of band"
    ),
)
flow_step(
    FIRST_LOGIN, order=1,
    note=(
        "Sign in with the provisioned credentials; while a first-login flag "
        "is up the response is FIRST_LOGIN_REQUIRED {requires, "
        "challenge_token} instead of tokens"
    ),
)(PasswordViewSet.login)
flow_step(
    FIRST_LOGIN, order=2,
    note=(
        "requires=password_change: set an own password (validated by the "
        "password canon); returns a full session — or the next "
        "FIRST_LOGIN_REQUIRED (requires=mfa_enroll) when both flags are set. "
        "A rejected password does not consume the challenge"
    ),
)(PasswordViewSet.forced_change)
flow_step(
    FIRST_LOGIN, order=3,
    note=(
        "requires=mfa_enroll: exchange the challenge_token for a limited "
        "enroll-only session (JWT claim enroll_only, access token only — "
        "no refresh); every endpoint outside the enrollment surface answers "
        "403 mfa_enrollment_required"
    ),
)(MfaEnrollViewSet.exchange)
flow_step(
    FIRST_LOGIN, order=4,
    note=(
        "Enroll the strong factor: confirming TOTP setup (or completing a "
        "passkey registration) clears the flag, emits user.mfa_enabled and "
        "returns the full-session token pair in the same response"
    ),
)(TOTPViewSet.confirm_setup)

# ─────────────────────────────────────────────────────────────────────────────
# auth.step_up_verification — THE reference flow for the verification contract
# ─────────────────────────────────────────────────────────────────────────────

STEP_UP_VERIFICATION = Flow(
    "auth.step_up_verification",
    title="Step-up verification on a protected endpoint (reference flow)",
    description=(
        "THE reference flow of the step-up verification contract "
        "(stapel_core.verification, see flows-and-verification.md §2) — "
        "clients of any service implement it once and reuse it for every "
        "endpoint protected by @requires_verification. The cycle: the "
        "protected endpoint responds 403 with a structured verification "
        "envelope (challenge_id, scope, factors, expires_at) → the client "
        "reads the challenge, picks an available factor (factors are "
        "interchangeable: otp_email, otp_phone, totp, passkey all close one "
        "challenge), initiates it and completes the check → repeats the "
        "original request. The grant is stored server-side (cache, user+scope "
        "key, TTL=max_age); stateless clients may instead send the "
        "X-Verification-Token header from the completion response. After "
        "MAX_ATTEMPTS wrong attempts the challenge burns out (423) — call the "
        "original endpoint again for a new challenge."
    ),
    actors=["Authenticated user"],
)

STEP_UP_VERIFICATION.human(
    order=0,
    note=(
        "The client calls the protected endpoint and receives 403 with a "
        "verification envelope: challenge_id, scope, factors, expires_at"
    ),
)
flow_step(
    STEP_UP_VERIFICATION, order=1,
    note=(
        "Read the challenge: the scope and the factors filtered down to those "
        "actually available to the user; 404 for a foreign/expired challenge"
    ),
)(VerificationViewSet.info)
flow_step(
    STEP_UP_VERIFICATION, order=2,
    note=(
        "Initiate the chosen factor: send a code (otp_email/otp_phone) or get "
        "WebAuthn options (passkey); totp needs no initiation"
    ),
)(VerificationViewSet.initiate)
flow_step(
    STEP_UP_VERIFICATION, order=3,
    note=(
        "Complete the challenge with the factor proof; success = "
        "{verified, verification_token} + a server-side grant; 400 on a wrong "
        "code, 423 when the challenge burned out from brute force"
    ),
)(VerificationViewSet.complete)
STEP_UP_VERIFICATION.human(
    order=4,
    note=(
        "Repeat the original request — the grant is already on the server; a "
        "stateless client sends the X-Verification-Token from the completion "
        "response"
    ),
)
flow_step(
    STEP_UP_VERIFICATION, order=5,
    note=(
        "Optional: view your step-up preferences — one {scope, enabled} row "
        "per scope the user has touched (enabled=false disables a default_on "
        "scope, enabled=true enables an opt_in scope; strict endpoints ignore "
        "the preferences)"
    ),
)(VerificationPreferenceViewSet.list_preferences)
flow_step(
    STEP_UP_VERIFICATION, order=6,
    note=(
        "Optional: change a {scope, enabled} preference. INVARIANT: disabling "
        "(enabled=false) is itself protected by "
        "@requires_verification(scope=verification.settings, level=default_on) "
        "— without a fresh grant a 403 with a verification envelope is "
        "returned; enabling requires no step-up confirmation. Both writes "
        "reset the policy cache in core"
    ),
)(VerificationPreferenceViewSet.set_preference)

__all__ = [
    "PASSWORDLESS_LOGIN",
    "PASSWORD_LOGIN",
    "FIRST_LOGIN",
    "STEP_UP_VERIFICATION",
]
