"""Everything the OIDC discovery document promises must actually resolve.

Incident (2026-07). ``/.well-known/openid-configuration`` is a contract with
parties we do not control: an external OIDC client reads it once and then
calls whatever URLs it found. The document was built from literals carried
over from the pre-library monolith (marketplace ``core/urls.py`` mounted the
views directly under ``{URL_PREFIX}``):

    token_endpoint          /auth/api/v1/auth/token/          <- extra "auth/"
    token_refresh_endpoint  /auth/api/v1/auth/token/refresh/  <- extra "auth/"
    userinfo_endpoint       /auth/api/v1/auth/me/             <- extra "auth/"
    jwks_uri                /auth/.well-known/jwks.json       <- neither route

As a library the module mounts at ``/auth/api/v1/…``; none of those four
paths exist. Every external client that trusted discovery got a 404, and the
suite could not notice because it ran against the un-mounted inner urlconf
(fixed: ``tests/conftest_urls.py``).

So this file does not compare the document against another set of literals —
that is the same bug with a different string. It takes every URL the document
hands out and puts it back through ``resolve()`` on the mounted urlconf: what
we promise outside must be routable inside. Move the mount, rename a route,
re-nest the version segment, and this goes red before the deployment does.
"""

from urllib.parse import urlsplit

import pytest
from django.test import override_settings
from django.urls import Resolver404, resolve, reverse
from rest_framework.test import APIClient

#: Discovery keys whose value is a URL into this service. A new such key must
#: be added here — test_no_url_key_escapes_the_guard fails otherwise, so the
#: next endpoint we advertise cannot skip the resolve() check.
URL_KEYS = (
    "jwks_uri",
    "token_endpoint",
    "token_refresh_endpoint",
    "userinfo_endpoint",
)

#: Host mount from conftest_urls.py + the v1/ segment urls.py contributes.
MOUNT = "/auth/api/v1"


def _discovery():
    resp = APIClient().get(reverse("openid-configuration"))
    assert resp.status_code == 200, resp.content
    return resp.data


@pytest.mark.django_db
def test_every_advertised_url_resolves():
    """The guard: no URL leaves this service pointing at a 404."""
    doc = _discovery()
    for key in URL_KEYS:
        assert key in doc, f"discovery stopped advertising {key}"
        path = urlsplit(doc[key]).path
        try:
            resolve(path)
        except Resolver404:
            pytest.fail(f"discovery advertises {key}={doc[key]!r}, which routes nowhere")


@pytest.mark.django_db
def test_advertised_urls_carry_the_mount():
    """Derived, not hardcoded: the URLs must follow the deployment's mount.

    Pins the shape the incident got wrong — the mount prefix is present and
    there is exactly one ``auth/`` segment (the host's), never a second one
    from a literal inside the module.
    """
    doc = _discovery()
    for key in URL_KEYS:
        path = urlsplit(doc[key]).path
        assert path.startswith(f"{MOUNT}/"), f"{key}={path} is outside the mount"
        assert "/auth/token" not in path and "/auth/me" not in path, (
            f"{key}={path} carries the monolith's duplicated auth/ segment"
        )


@pytest.mark.django_db
def test_the_incident_paths_are_not_routed():
    """The exact 404s of the incident, kept explicit.

    If someone re-adds a compatibility route for these, it should be a
    deliberate, visible change — not a silent widening of the contract.
    """
    for path in (
        f"{MOUNT}/auth/token/",
        f"{MOUNT}/auth/token/refresh/",
        f"{MOUNT}/auth/me/",
        "/auth/.well-known/jwks.json",
    ):
        with pytest.raises(Resolver404):
            resolve(path)


@pytest.mark.django_db
def test_advertised_urls_match_the_named_routes():
    """Same routes the rest of the service uses — no parallel URL truth."""
    doc = _discovery()
    for key, name in (
        ("jwks_uri", "jwks"),
        ("token_endpoint", "token_obtain_pair"),
        ("token_refresh_endpoint", "token_refresh"),
        ("userinfo_endpoint", "me"),
    ):
        assert resolve(urlsplit(doc[key]).path).view_name == name


@pytest.mark.django_db
def test_no_url_key_escapes_the_guard():
    """Any http(s) value in the document must be one of URL_KEYS (or issuer).

    Without this, adding ``introspection_endpoint`` (or any future endpoint)
    would re-open exactly the hole this file closes: an advertised URL that
    nothing ever resolves.
    """
    doc = _discovery()
    advertised = {
        key
        for key, value in doc.items()
        if isinstance(value, str) and value.startswith(("http://", "https://", "/"))
    }
    assert advertised <= {*URL_KEYS, "issuer"}, (
        f"unguarded URL keys in discovery: {sorted(advertised - {*URL_KEYS, 'issuer'})}"
    )


@pytest.mark.django_db
def test_jwks_uri_defaults_to_the_mounted_drf_route():
    """Two JWKS deployments exist; the default one is ours and it resolves.

    stapel_core.django.openapi.openid.generate_jwks_to_dir() writes a static
    jwks.json for nginx to serve from the HOST ROOT — a legitimate second
    home, but not a Django route and not the default. Unset, discovery
    advertises the route this module actually mounts.
    """
    assert urlsplit(_discovery()["jwks_uri"]).path == reverse("jwks")


@override_settings(STAPEL_AUTH={"JWKS_URI": "/.well-known/jwks.json"})
@pytest.mark.django_db
def test_jwks_uri_honours_the_nginx_static_deployment():
    """The nginx-static home is an explicit deployment claim, not a guess.

    Deliberately exempt from the resolve() guard above: this target is served
    by nginx from /var/www/.well-known/, outside Django's urlconf entirely —
    which is precisely why it must be opted into instead of hardcoded.
    """
    doc = _discovery()
    assert doc["jwks_uri"] == "http://testserver/.well-known/jwks.json"
    with pytest.raises(Resolver404):
        resolve("/.well-known/jwks.json")


@pytest.mark.django_db
def test_unmounted_route_is_omitted_not_advertised():
    """A feature-gated route that is not mounted must drop out of discovery.

    Hosts assemble their own URLconf from the ``urls_v1`` factories, so
    ``me`` (otp factory) can be absent. Advertising it anyway would hand out
    another guaranteed 404 — and reverse() would raise, 500-ing discovery.
    """
    import sys
    import types

    from stapel_auth.urls_v1 import get_openid_urls, get_sessions_urls

    name = "_stapel_auth_partial_urlconf"
    module = types.ModuleType(name)
    module.urlpatterns = get_openid_urls(enabled=True) + get_sessions_urls(enabled=True)
    sys.modules[name] = module

    with override_settings(ROOT_URLCONF=name):
        resp = APIClient().get(reverse("openid-configuration"))
        assert resp.status_code == 200, resp.content
        assert "userinfo_endpoint" not in resp.data
        assert resp.data["token_endpoint"] == "http://testserver/token/"
