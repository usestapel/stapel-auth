"""Which host is this person on, and which hosts may we send them back to.

One build serves N hosts (``stapel_core.sites``), so ``FRONTEND_URL`` — a
single string chosen at deploy time — stopped being the answer to "where does
this link go?". A password-reset mail minted from a request that arrived on the
second brand's domain still carried the first brand's host: the person clicked
a link to a site they had never visited, on a domain whose cookie jar their
session does not live in.

Two helpers, and the whole per-host vocabulary of this module is in them:

``frontend_url_for(request)``
    The base URL for a link or a redirect being minted *while holding a
    request*. ``https://<host>`` when the request arrived on a registered site,
    ``FRONTEND_URL`` otherwise — an unmatched host is deliberately **not**
    promoted to the primary site's URL here, because the value ends up in an
    email and a link is only safe to mint for a host the registry recognises.

``allowed_return_origins()``
    The exact origins a ``redirect_after`` / ``return_to`` may name. Request-
    independent on purpose: the deployment serves all of them, and a person who
    started a flow on one brand may legitimately finish on another.

Code with **no request** — a Celery task, a beat job, a signal handler — keeps
``FRONTEND_URL``. That is the primary site by design: there is no host to
follow, and the registry's primary is what the deployment nominated as its
default face.
"""
from __future__ import annotations

from urllib.parse import urlsplit

__all__ = [
    "allowed_return_origins",
    "frontend_url_for",
    "origin_of",
    "safe_relative_path",
    "safe_return_target",
]

#: What a browser silently deletes from anywhere inside a URL before parsing it
#: (WHATWG URL, "remove all ASCII tab or newline"). A validator that does not
#: delete them too is checking a different string than the one navigated to:
#: ``/\t/evil.test`` is not ``//`` here and is ``//evil.test`` in the browser.
_URL_STRIPPED = str.maketrans("", "", "\t\r\n")


def _frontend_url() -> str:
    """``STAPEL_AUTH['FRONTEND_URL']``, normalised to a string."""
    from stapel_auth.conf import auth_settings

    return auth_settings.FRONTEND_URL or ""


def origin_of(url) -> str:
    """``scheme://netloc``, lowercased — or ``""`` for anything relative.

    Parsed, never sliced: the whole point of comparing origins rather than
    prefixes is that ``https://example.com.attacker.test/`` and
    ``https://attacker.test/?u=example.com`` both *contain* a registered host
    and are neither of them served by this deployment.
    """
    try:
        parts = urlsplit(str(url or "").strip())
    except ValueError:
        return ""
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def frontend_url_for(request) -> str:
    """The SPA base URL for the host *request* actually arrived on.

    Falls back to ``FRONTEND_URL`` for an unmatched host, for an empty registry
    (the single-host deployment, where nothing changes) and for ``request is
    None`` (a service call with no browser behind it).
    """
    default = _frontend_url()
    if request is None:
        return default
    from stapel_core.django.sites import site_frontend_url

    return site_frontend_url(request, default=default)


def allowed_return_origins() -> frozenset[str]:
    """Every origin a redirect target may name: ``FRONTEND_URL`` ∪ the registry.

    ``FRONTEND_URL`` stays in the set with **its own scheme**, which is what
    keeps ``http://localhost:3000`` working for local development while every
    registry origin remains ``https``-only. It is a set of exact origins, and
    membership is tested by equality — see :func:`origin_of`.
    """
    from stapel_core.django.sites import site_registry

    origins = set(site_registry().origins())
    frontend = origin_of(_frontend_url())
    if frontend:
        origins.add(frontend)
    return frozenset(origins)


def _normalised(value) -> str:
    """*value* as the browser will read it, or ``""`` when it is not a URL we
    are willing to reason about.

    Tabs and newlines are deleted (the browser does), surrounding spaces are
    trimmed (the browser does). Anything still carrying a control character or
    a backslash is refused outright: browsers treat ``\\`` as ``/`` in
    special schemes, so ``/\\evil.test`` is a scheme-relative URL to them.
    """
    if not value:
        return ""
    cleaned = str(value).translate(_URL_STRIPPED).strip()
    if not cleaned or "\\" in cleaned:
        return ""
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
        return ""
    return cleaned


def safe_relative_path(value) -> str:
    """*value* when it is a same-origin path (``/x``), else ``""``.

    Scheme-relative (``//host``), backslash and control-character variants
    are refused after the same normalisation a browser applies.
    """
    cleaned = _normalised(value)
    if cleaned.startswith("/") and not cleaned.startswith("//"):
        return cleaned
    return ""


def safe_return_target(value) -> str:
    """A path, or an absolute URL on an origin this deployment serves; else ``""``.

    The single validator behind every ``redirect_after`` / ``return_to`` this
    module honours. Absolute targets must be ``https`` (or ``FRONTEND_URL``'s
    own scheme, for local development), carry no userinfo, and name an origin
    in :func:`allowed_return_origins` by equality.
    """
    cleaned = _normalised(value)
    if not cleaned:
        return ""
    if cleaned.startswith("/"):
        return safe_relative_path(cleaned)
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return ""
    if parts.username is not None or parts.password is not None:
        return ""
    scheme = (parts.scheme or "").lower()
    dev_scheme = origin_of(_frontend_url()).split(":", 1)[0]
    if scheme != "https" and not (dev_scheme and scheme == dev_scheme):
        return ""
    if origin_of(cleaned) in allowed_return_origins():
        return cleaned
    return ""
