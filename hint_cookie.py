"""Non-httponly companion cookie for the refresh-token JWT cookie.

`stapel_auth_hint` (bare value `"1"`) is set ALONGSIDE the httponly
refresh-token cookie by every flow that mints one — redirect-based logins
(QR `session_share` scan, magic-link verify, SSO SAML/OIDC callback, OAuth
social callback) most critically, but also the direct JSON-response login
endpoints, for consistency.

Why this exists (`@stapel/auth-react` incident write-up, 2026-07-19): a
bearer-mode SPA has NO cookie jar visibility — `document.cookie` can't see
httponly cookies — so it has no way to distinguish "a redirect just minted a
live session for me server-side" from "there was never a session" without
actually attempting a network refresh. A `session_share` QR scan is exactly
that case: fresh httponly cookies land via a plain HTTP redirect, entirely
outside the SPA's own login call. `auth-react`'s `bootstrapProbe: "auto"`
reads THIS cookie (a plain `document.cookie` check, JS-readable by design) to
decide whether a cold load is worth a refresh-probe at all, so a bearer-mode
host never pays a network round trip on a visitor who was never on a
cookie-issuing backend to begin with.

Non-sensitive by construction: the value carries no identity, no token, no
claim — it is a doorbell, not a credential. Deliberately given the SAME
lifetime/Secure/SameSite/domain/path as the refresh cookie it accompanies
(`set_jwt_cookies`'s own settings-derived config, mirrored here) so it never
outlives, or is readable under laxer conditions than, the session it points
at — and is cleared everywhere the session cookies are cleared (logout).
"""

HINT_COOKIE_NAME = "stapel_auth_hint"


def set_auth_hint_cookie(response) -> None:
    """Set the hint cookie with the same lifetime/Secure/SameSite/domain/path
    `set_jwt_cookies` (`stapel_core.django.jwt.utils`) uses for the refresh
    cookie it is minted next to. Call this immediately after
    `set_jwt_cookies` at every call site — see module docstring."""
    from django.conf import settings

    cookie_domain = getattr(settings, "JWT_COOKIE_DOMAIN", None)
    cookie_secure = getattr(settings, "JWT_COOKIE_SECURE", False)
    cookie_samesite = getattr(settings, "JWT_COOKIE_SAMESITE", "Lax")
    refresh_token_lifetime = getattr(settings, "JWT_REFRESH_TOKEN_LIFETIME", 604800)

    response.set_cookie(
        HINT_COOKIE_NAME,
        "1",
        max_age=refresh_token_lifetime,
        domain=cookie_domain,
        path="/",
        secure=cookie_secure,
        httponly=False,
        samesite=cookie_samesite,
    )


def clear_auth_hint_cookie(response) -> None:
    """Delete the hint cookie. Call wherever the JWT session cookies are
    cleared (logout, session revoke of the current session)."""
    from django.conf import settings

    cookie_domain = getattr(settings, "JWT_COOKIE_DOMAIN", None)
    cookie_samesite = getattr(settings, "JWT_COOKIE_SAMESITE", "Lax")

    response.delete_cookie(
        HINT_COOKIE_NAME,
        path="/",
        domain=cookie_domain,
        samesite=cookie_samesite,
    )
