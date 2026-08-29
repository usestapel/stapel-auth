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

__all__ = ["allowed_return_origins", "frontend_url_for", "origin_of"]


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
