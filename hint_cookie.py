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
lifetime/Secure/SameSite/domain/path as the refresh cookie it accompanies —
copied off that cookie, not re-derived — so it never outlives, or is readable
under laxer conditions than, the session it points at, and is cleared
everywhere the session cookies are cleared (logout).
"""

HINT_COOKIE_NAME = "stapel_auth_hint"


def set_auth_hint_cookie(response) -> None:
    """Set the hint cookie with the same lifetime/Secure/SameSite/domain/path
    as the refresh cookie it is minted next to. Call this immediately after
    `set_jwt_cookies` (`stapel_core.django.jwt.utils`) at every call site —
    see module docstring.

    The attributes are READ OFF the refresh cookie already on the response
    rather than re-derived from settings. Re-deriving meant this module kept
    its own copy of core's defaults, and a copy is only correct until one side
    moves: stapel-core 0.24.0 turned `JWT_COOKIE_SECURE` on by default, so a
    deployment that never declared the setting started sending a TLS-only
    refresh cookie next to a hint cookie this function still marked
    non-Secure — exactly the "readable under laxer conditions than the session
    it points at" the module docstring forbids. Copying makes the promise
    structural instead of a pair of literals that have to be kept in step.
    """
    from django.conf import settings

    refresh_cookie_name = getattr(
        settings, "JWT_REFRESH_COOKIE_NAME", "stapel_refresh_jwt"
    )
    minted = response.cookies.get(refresh_cookie_name)
    if minted is not None:
        max_age = minted["max-age"]
        response.set_cookie(
            HINT_COOKIE_NAME,
            "1",
            max_age=int(max_age) if max_age not in ("", None) else None,
            domain=minted["domain"] or None,
            path=minted["path"] or "/",
            secure=bool(minted["secure"]),
            # Non-httponly by design — this is the JS-readable signal, the one
            # attribute that must NOT be copied from the refresh cookie.
            httponly=False,
            samesite=minted["samesite"] or None,
        )
        return

    # No refresh cookie on this response (a bearer-mode deployment, or a path
    # that mints tokens without cookies). The hint still goes out for the
    # flows that always set it, so fall back to the settings core reads, with
    # core's own defaults.
    response.set_cookie(
        HINT_COOKIE_NAME,
        "1",
        max_age=getattr(settings, "JWT_REFRESH_TOKEN_LIFETIME", 604800),
        domain=getattr(settings, "JWT_COOKIE_DOMAIN", None),
        path="/",
        secure=getattr(settings, "JWT_COOKIE_SECURE", True),
        httponly=False,
        samesite=getattr(settings, "JWT_COOKIE_SAMESITE", "Lax"),
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
