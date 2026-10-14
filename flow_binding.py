"""Bind a browser-redirect flow to the browser that started it.

A redirect flow (OAuth authorization code, OIDC SSO) parks its state on the
server and hands the browser an opaque ``state`` to carry through the
provider. Server-side state alone proves only that *somebody* started the
flow. An attacker can start one, stop at the provider's callback URL with
their own ``code``, and get a victim's browser to follow it: the victim is
then signed in to the attacker's account (login CSRF), and with a guest
session in that browser the guest's data is merged into the attacker's
account.

The binding closes that: the start response sets an HttpOnly, SameSite=Lax
cookie holding a random nonce, the parked state keeps a digest of it, and the
callback refuses unless the browser presents the matching cookie. Lax is the
right strength — the provider sends the browser back with a top-level GET,
which carries Lax cookies, while a cross-site subrequest does not.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

__all__ = ["bind", "clear", "is_bound", "new_binding"]

_COOKIE_PREFIX = "stapel_flow_"


def _cookie_name(flow: str) -> str:
    return f"{_COOKIE_PREFIX}{flow}"


def _digest(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def new_binding() -> tuple[str, str]:
    """A fresh ``(nonce, digest)``: the nonce goes to the cookie, the digest
    into the parked state. The cache never holds the cookie's value."""
    nonce = secrets.token_urlsafe(32)
    return nonce, _digest(nonce)


def _cookie_kwargs() -> dict:
    from django.conf import settings

    return {
        "path": "/",
        "domain": getattr(settings, "JWT_COOKIE_DOMAIN", None),
        # Same default as the session cookies: TLS-only unless the
        # deployment explicitly says it runs without it (local http).
        "secure": getattr(settings, "JWT_COOKIE_SECURE", True),
        "httponly": True,
        "samesite": "Lax",
    }


def bind(response, flow: str, nonce: str, max_age: int) -> None:
    """Set the flow cookie on the response that starts *flow*."""
    response.set_cookie(_cookie_name(flow), nonce, max_age=max_age, **_cookie_kwargs())


def is_bound(request, flow: str, digest: str | None) -> bool:
    """Does this browser hold the nonce whose digest the state recorded?

    A state with no digest is refused: it was parked by a start that did not
    bind, and there is no way to tell whose browser this is.
    """
    presented = request.COOKIES.get(_cookie_name(flow), "")
    if not digest or not presented:
        return False
    return hmac.compare_digest(_digest(presented), str(digest))


def clear(response, flow: str) -> None:
    """Expire the flow cookie — one flow, one use."""
    kwargs = _cookie_kwargs()
    response.delete_cookie(
        _cookie_name(flow),
        path=kwargs["path"],
        domain=kwargs["domain"],
        samesite=kwargs["samesite"],
    )
