"""Session-issuance guard — the single precondition gate for a full session.

Why this module exists (org-program §P13). ``stapel-auth`` can mark an
account ``is_active=False`` and can hang first-login policies on it
(``password_change_required`` / ``mfa_enrollment_required``). Before this
module both were enforced *by the politeness of the caller*: the password
login path checked them, and the dozen other paths that mint a session —
OTP, OAuth, magic link, QR, passkey, login-grant, the instant-change
paths — did not. A deactivated account still got in through OTP, and a
forced password change was walked around with a magic link. That is one
defect, not two: an invariant with no single place that holds it.

The invariant lives here and is enforced in exactly one place:
:func:`stapel_auth.sessions.views._issue_session_tokens`, the final minter
every full-session path funnels through. It is deliberately **not** in
``create_tokens_for_user`` — that one is shared with the *intermediate*
paths (forced password change, the MFA enroll exchange, SSO), which must
stay outside the invariant: gating them would lock the user out of the
very step they are being forced to complete.

Two rules, with different shapes:

* ``is_active=False`` — **unconditional**, no next step, final refusal.
  The response deliberately carries no account detail (no enumeration
  oracle).
* first-login policy flags — refusal **with a next step**: the denial
  carries a freshly minted ``challenge_token`` plus the ``requires``
  label, so the caller can point the user at ``POST /password/forced-
  change/`` or ``POST /mfa/enroll/exchange/``. A flag must never produce a
  dead 403, or a flagged user who arrived by magic link is locked out
  forever.

Which paths the *flags* gate is a deployment choice, see
``FIRST_LOGIN_GATE_PATHS`` in :mod:`stapel_auth.conf` and
:func:`first_login_gate_applies`. ``is_active`` is not configurable.
"""

from stapel_core.django.api.errors import StapelServiceError

__all__ = [
    "SessionPath",
    "SessionIssuanceDenied",
    "account_disabled_error",
    "denial_redirect_url",
    "first_login_error",
    "first_login_gate_applies",
    "session_precondition_error",
]


class SessionPath:
    """Label for every code path that mints a FULL session.

    Every call site of ``_issue_session_tokens`` passes one of these. The
    labels are what ``FIRST_LOGIN_GATE_PATHS`` selects on, and they are the
    enumeration ``tests/test_session_issuance_gate.py`` walks — a new
    issuance path that does not appear here fails that suite instead of
    silently reopening the hole this module closes.
    """

    #: Legacy ``/token/`` username+password endpoint (sessions/views.py).
    LEGACY_TOKEN = "legacy_token"
    #: ``POST /password/login/`` (password/views.py).
    PASSWORD = "password"
    #: ``POST /password/register/`` (password/views.py).
    PASSWORD_REGISTER = "password_register"
    #: ``POST /password/forced-change/`` — the flag was just cleared.
    FORCED_PASSWORD_CHANGE = "forced_password_change"
    #: ``POST /totp/challenge/verify/`` — password/OAuth step-up.
    TOTP_CHALLENGE = "totp_challenge"
    #: ``POST /totp/setup/confirm/`` under an enroll-only session.
    TOTP_ENROLL_UPGRADE = "totp_enroll_upgrade"
    #: ``POST /passkey/register/complete/`` under an enroll-only session.
    PASSKEY_ENROLL_UPGRADE = "passkey_enroll_upgrade"
    #: ``POST /passkey/auth/complete/`` — passkey sign-in.
    PASSKEY_LOGIN = "passkey_login"
    #: ``POST /email/verify/`` — email OTP sign-in.
    OTP_EMAIL = "otp_email"
    #: ``POST /phone/verify/`` — phone OTP sign-in.
    OTP_PHONE = "otp_phone"
    #: ``POST /anonymous/`` — guest session.
    ANONYMOUS = "anonymous"
    #: ``POST /oauth/login/`` — provider access-token exchange.
    OAUTH_LOGIN = "oauth_login"
    #: ``GET /oauth/{provider}/callback/`` — browser redirect path.
    OAUTH_CALLBACK = "oauth_callback"
    #: ``POST /email/instant/verify-new/`` — authenticator change.
    EMAIL_INSTANT = "email_instant"
    #: ``POST /phone/instant/verify-new/`` — authenticator change.
    PHONE_INSTANT = "phone_instant"
    #: ``GET /magic-link/verify/`` — browser redirect path.
    MAGIC_LINK = "magic_link"
    #: ``POST /login-grant/exchange/``.
    LOGIN_GRANT = "login_grant"
    #: ``GET /qr/scan/`` session-share — browser redirect path.
    QR_SESSION_SHARE = "qr_session_share"
    #: SAML/OIDC assertion consumer — browser redirect path. NB: the org
    #: design doc misfiled this one as an *intermediate* path; it is a final
    #: minter (token pair + session row + audit + login notification), and
    #: leaving it out reproduced both holes verbatim on SSO.
    SSO = "sso"
    #: Fail-closed default for a caller that declares no path. Never
    #: exempt from the flag gate, whatever ``FIRST_LOGIN_GATE_PATHS`` says.
    UNSPECIFIED = "unspecified"


#: Every declared path. ``UNSPECIFIED`` is deliberately excluded — it is the
#: fallback for an undeclared caller, not a path a deployment may exempt.
SessionPath.ALL = frozenset(
    v
    for k, v in vars(SessionPath).items()
    if k.isupper() and isinstance(v, str) and v != SessionPath.UNSPECIFIED
)

#: The browser-redirect paths. They must map a denial to a front-end
#: redirect carrying the challenge, never to a JSON error body — a click in
#: an email that dead-ends on raw JSON is not a recoverable flow.
SessionPath.REDIRECT_PATHS = frozenset(
    {
        SessionPath.MAGIC_LINK,
        SessionPath.OAUTH_CALLBACK,
        SessionPath.QR_SESSION_SHARE,
        SessionPath.SSO,
    }
)


class SessionIssuanceDenied(StapelServiceError):
    """A full session was refused at the minter.

    A :class:`~stapel_core.django.api.errors.StapelServiceError` subclass on
    purpose: the stapel-core DRF exception handler already converts those to
    the structured error body, so every JSON path gets an identical response
    with no per-caller ``try/except``. The next-step payload travels in
    ``error_params`` (``requires`` / ``challenge_token`` / ``expires_in``)
    and is also available as attributes for the redirect paths, which build
    a front-end URL out of it instead of a body.

    ``requires is None`` means *no next step exists* (the account is
    disabled) — a final refusal.
    """

    def __init__(
        self,
        http_status: int,
        error_key: str,
        *,
        requires: str | None = None,
        challenge_token: str | None = None,
        expires_in: int | None = None,
    ):
        params: dict = {}
        if requires is not None:
            params["requires"] = requires
            params["challenge_token"] = challenge_token
            params["expires_in"] = expires_in
        super().__init__(http_status, error_key, params)
        self.requires = requires
        self.challenge_token = challenge_token
        self.expires_in = expires_in


def account_disabled_error(user) -> SessionIssuanceDenied | None:
    """Refusal for a deactivated account, or ``None``.

    Unconditional — no deployment switch, no path exemption, no next step.
    The error key carries no account detail so the response cannot be used
    to probe which accounts exist.
    """
    from stapel_auth.errors import ERR_401_ACCOUNT_DISABLED

    if getattr(user, "is_active", True):
        return None
    return SessionIssuanceDenied(401, ERR_401_ACCOUNT_DISABLED)


def first_login_gate_applies(path: str) -> bool:
    """Does the first-login flag gate cover *path*?

    Driven by ``STAPEL_AUTH['FIRST_LOGIN_GATE_PATHS']``:

    * ``'*'`` (the default) — the flag blocks a session on **every** path.
      A first-login flag is read as "a mandatory step before ANY admission",
      not "before a PASSWORD admission"; the narrow reading leaves exactly
      the hole this gate was built for (a flagged account walks in by OTP or
      magic link).
    * an explicit list of :class:`SessionPath` labels — the flag blocks only
      those. ``['password', 'legacy_token']`` is the narrow reading.

    ``SessionPath.UNSPECIFIED`` always gates: a caller that forgot to
    declare its path fails closed.
    """
    from stapel_auth.conf import auth_settings

    scope = auth_settings.FIRST_LOGIN_GATE_PATHS
    if scope == "*" or path == SessionPath.UNSPECIFIED:
        return True
    if not scope:
        return False
    return path in set(scope)


def first_login_error(
    user, *, path: str = SessionPath.UNSPECIFIED
) -> SessionIssuanceDenied | None:
    """Refusal for an outstanding first-login policy step, or ``None``.

    On refusal a challenge is minted, so the denial always carries a usable
    next step. Both resolvers (``/password/forced-change/`` and
    ``/mfa/enroll/exchange/``) are ``AllowAny`` and take nothing but the
    challenge token, so a challenge created on any path — including one
    created for a user who arrived by magic link and has no idea what their
    org-set password is — resolves normally.

    Self-healing is inherited from
    :meth:`~stapel_auth.password.services.FirstLoginPolicyService.required_intermediate`:
    an ``mfa_enrollment_required`` flag on an account that already carries a
    strong factor is cleared on the spot rather than dead-ending the login
    (this is what makes a passkey sign-in by a flagged user just work).
    """
    from stapel_auth.errors import (
        ERR_403_MFA_ENROLLMENT_REQUIRED,
        ERR_403_PASSWORD_CHANGE_REQUIRED,
    )
    from stapel_auth.password.services import FirstLoginPolicyService

    if not first_login_gate_applies(path):
        return None

    requires = FirstLoginPolicyService.required_intermediate(user)
    if requires is None:
        return None

    error_key = (
        ERR_403_PASSWORD_CHANGE_REQUIRED
        if requires == FirstLoginPolicyService.REQUIRES_PASSWORD_CHANGE
        else ERR_403_MFA_ENROLLMENT_REQUIRED
    )
    return SessionIssuanceDenied(
        403,
        error_key,
        requires=requires,
        challenge_token=FirstLoginPolicyService.create_challenge(user, requires),
        expires_in=FirstLoginPolicyService.CHALLENGE_TTL,
    )


def session_precondition_error(
    user, *, path: str = SessionPath.UNSPECIFIED
) -> SessionIssuanceDenied | None:
    """Why *user* may not be handed a full session on *path*, or ``None``.

    The whole invariant in one predicate. Order matters: a deactivated
    account is refused before any challenge is minted for it, so a disabled
    account never receives a live first-login challenge token.
    """
    return account_disabled_error(user) or first_login_error(user, path=path)


#: Front-end route a first-login denial on a redirect path lands on. Same
#: route the existing TOTP-challenge redirect uses (magic link), so a host
#: that already renders one challenge screen has somewhere to put this one.
FIRST_LOGIN_REDIRECT_PATH = "/login"


def denial_redirect_url(denial, *, frontend_url: str = "", next_url: str = "") -> str:
    """Front-end URL for a denial on a browser-redirect issuance path.

    Magic link, the OAuth callback, QR session-share and the SSO ACS all
    answer a *browser navigation*, not an XHR: rendering the structured JSON
    error there dead-ends the user on a raw error body in the address bar.
    They catch :class:`SessionIssuanceDenied` and redirect here instead.

    Shape (one contract for all four paths)::

        {frontend}/login?first_login=<requires>&challenge_token=<tok>&next=<n>

    which is the existing TOTP-challenge redirect shape plus a
    ``first_login`` discriminator, so a host can tell the two challenges
    apart on the same screen. The token is the same one the JSON paths put
    in ``params.challenge_token`` and resolves at the same two AllowAny
    endpoints.

    A denial with no next step (disabled account) carries no token — only
    ``?error=account_disabled``.
    """
    from urllib.parse import urlencode

    base = f"{frontend_url}{FIRST_LOGIN_REDIRECT_PATH}"
    if denial.requires is None:
        return f"{base}?{urlencode({'error': 'account_disabled'})}"
    params = {
        "first_login": denial.requires,
        "challenge_token": denial.challenge_token,
    }
    if next_url:
        params["next"] = next_url
    return f"{base}?{urlencode(params)}"
