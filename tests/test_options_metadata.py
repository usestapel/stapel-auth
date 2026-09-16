"""Every route this package mounts must answer OPTIONS, not 500.

The defect (measured on a client stand, 2026-09-09): `OPTIONS
/auth/api/v1/anonymous/` and `OPTIONS /auth/api/v1/token/refresh/` answered
500 with a traceback. DRF's `SimpleMetadata` builds the `actions` block by
instantiating the view's serializer, every viewset here is a `GenericViewSet`
whose serializers are per-action seams, and `GenericAPIView.get_serializer_class`
answers a missing `serializer_class` with `AssertionError` — which is not an
`APIException`, so nothing caught it. Those two are also exactly what a
cross-origin client's CORS preflight hits before it can sign in.

This file is the gate for the CLASS, not for those two routes: it walks the
mounted URLconf, issues a real `OPTIONS` at every pattern, and fails on any
5xx. A new view that forgets its serializer seam turns it red on the day it
is written.
"""
import re

import pytest
from django.contrib.auth import get_user_model
from django.urls import get_resolver
from django.urls.resolvers import URLPattern, URLResolver
from rest_framework.test import APIClient

User = get_user_model()

#: Sample values for the path converters this module's URLconf uses, so a
#: parameterised route can be requested at all.
_SAMPLES = {
    "int": "1",
    "str": "sample",
    "slug": "sample",
    "uuid": "00000000-0000-0000-0000-000000000000",
    "path": "sample",
}

_PARAM = re.compile(r"<(?:(?P<conv>[^:>]+):)?(?P<name>[^>]+)>")


def _concrete(route: str) -> str:
    """`sessions/<str:session_id>/` -> `sessions/sample/`."""
    return _PARAM.sub(lambda m: _SAMPLES.get(m.group("conv") or "str", "sample"), route)


#: This package's own import root. The walk below is scoped to it because the
#: gate's claim is about the surface THIS package owns (see the module
#: docstring: "Every route this package mounts"). The suite's URLconf also
#: mounts `stapel_gdpr` — the other half of the contract this module emits —
#: and those views have their own package, their own suite and their own
#: gates. A gate that graded them here would make one library's red the
#: consequence of another library's code, which is how a broken mount stays
#: broken: fixing it looks like breaking two gates.
OWN_PACKAGE = "stapel_auth."


def _owning_module(pattern) -> str:
    """The dotted module of the view a `URLPattern` dispatches to.

    `as_view()` copies the class's `__module__` onto the returned function
    (`functools.update_wrapper`), and DRF additionally pins `view.cls`. Read
    the class when it is there and fall back to the function, so a plain
    function-based view is still classified rather than silently dropped.
    """
    callback = pattern.callback
    view_cls = getattr(callback, "cls", None) or getattr(callback, "view_class", None)
    return getattr(view_cls or callback, "__module__", "")


def _routes(resolver=None, prefix=""):
    """Every mounted `path()` route THIS package owns, as a concrete URL."""
    resolver = resolver or get_resolver()
    for entry in resolver.url_patterns:
        route = getattr(entry.pattern, "_route", None)
        if route is None:  # a re_path — none in this module's URLconf
            continue
        if isinstance(entry, URLResolver):
            yield from _routes(entry, prefix + route)
        elif isinstance(entry, URLPattern):
            if not _owning_module(entry).startswith(OWN_PACKAGE):
                continue
            yield "/" + _concrete(prefix + route)


@pytest.fixture(scope="module")
def routes():
    found = sorted(set(_routes()))
    # A guard on the walk itself: an empty list would make every assertion
    # below pass while proving nothing.
    assert len(found) > 30, found
    return found


@pytest.mark.django_db
def test_the_walk_is_scoped_to_this_package(routes):
    """The scoping is a claim about coverage, so it is asserted both ways.

    Downward: no route in the sweep belongs to another package — without this
    the filter could be a no-op and the gate would be grading `stapel_gdpr`'s
    surface again the next time the suite URLconf grows a mount.

    Upward: the sweep still reaches the two routes named in the incident this
    file exists for — without this a typo in `OWN_PACKAGE` would empty the
    walk past the `> 30` guard's notice by dropping everything except a
    coincidental few.
    """
    from django.urls import resolve

    foreign = sorted(
        {
            url
            for url in routes
            if not resolve(url).func.__module__.startswith(OWN_PACKAGE)
        }
    )
    assert foreign == [], foreign
    assert "/auth/api/v1/anonymous/" in routes
    assert "/auth/api/v1/token/refresh/" in routes


def _options(client, url):
    return client.options(url)


class TestNoRouteAnswersFiveHundred:
    """The class gate. A 401/403/404 is a fine answer; a 500 is the defect.

    ``raise_request_exception=False`` on purpose: the default test client
    re-raises the view's exception, which stops the sweep at the first broken
    route and reports one name. Letting the 500 through collects every route
    that is broken, which is what a gate for a CLASS of defect has to say.
    """

    @pytest.mark.django_db
    def test_anonymous_options_never_500s(self, routes):
        client = APIClient(raise_request_exception=False)
        broken = []
        for url in routes:
            response = _options(client, url)
            if response.status_code >= 500:
                broken.append((url, response.status_code))
        assert broken == []

    @pytest.mark.django_db
    def test_authenticated_options_never_500s(self, routes):
        """The pass that actually reaches the metadata code.

        DRF's metadata skips the `actions` block when `check_permissions`
        refuses, so an anonymous sweep leaves every authenticated route
        untested — the exact hole that let this survive on all but the two
        pre-auth routes.
        """
        user = User.objects.create_user(
            username="options-sweep", email="options-sweep@example.com",
            password="x", is_staff=True, is_superuser=True,
        )
        client = APIClient(raise_request_exception=False)
        client.force_authenticate(user=user)
        broken = []
        for url in routes:
            response = _options(client, url)
            if response.status_code >= 500:
                broken.append((url, response.status_code))
        assert broken == []


class TestThePreAuthRoutesTheClientPreflights:
    """The two routes named in the incident, asserted in full."""

    @pytest.mark.django_db
    def test_anonymous_mint_describes_its_post_body(self):
        from stapel_auth.otp.serializers import AnonymousAuthSerializer

        response = APIClient().options("/auth/api/v1/anonymous/")

        assert response.status_code == 200
        assert "POST" in response["Allow"]
        assert response["Content-Type"].startswith("application/json")

        body = response.json()
        # Not just a status code: the body must be the metadata document, and
        # its POST block must be THIS endpoint's real request serializer.
        assert set(body) >= {"name", "renders", "parses", "actions"}
        assert set(body["actions"]) == {"POST"}
        assert set(body["actions"]["POST"]) == set(AnonymousAuthSerializer().fields)

    @pytest.mark.django_db
    def test_token_refresh_describes_its_post_body(self):
        response = APIClient().options("/auth/api/v1/token/refresh/")

        assert response.status_code == 200
        assert "POST" in response["Allow"]
        assert response["Content-Type"].startswith("application/json")

        body = response.json()
        assert set(body["actions"]) == {"POST"}
        # `refresh` is optional — the token may ride in a cookie — and OPTIONS
        # must say so rather than describing a body the client cannot build.
        assert body["actions"]["POST"]["refresh"]["required"] is False


class TestTheSeamIsWhatAnswers:
    """`get_serializer_class()` derives from the seams, per action."""

    @pytest.mark.django_db
    def test_each_action_gets_its_own_request_serializer(self):
        from stapel_auth.otp.serializers import (
            EmailAuthRequestSerializer,
            EmailAuthVerifySerializer,
        )

        request_fields = {}
        for url in ("/auth/api/v1/email/request/", "/auth/api/v1/email/verify/"):
            request_fields[url] = set(
                APIClient().options(url).json()["actions"]["POST"]
            )

        assert request_fields["/auth/api/v1/email/request/"] == set(
            EmailAuthRequestSerializer().fields
        )
        assert request_fields["/auth/api/v1/email/verify/"] == set(
            EmailAuthVerifySerializer().fields
        )
        # Two actions on ONE viewset, two different bodies — which is the whole
        # point of deriving per action instead of naming one serializer_class.
        assert (
            request_fields["/auth/api/v1/email/request/"]
            != request_fields["/auth/api/v1/email/verify/"]
        )

    def test_an_action_with_no_declared_body_says_so_rather_than_raising(self):
        from rest_framework import viewsets

        from stapel_auth.utils import EmptyRequestSerializer, SerializerSeamsMixin

        class Bodiless(SerializerSeamsMixin, viewsets.GenericViewSet):
            pass

        view = Bodiless()
        view.action = "ping"
        assert view.get_serializer_class() is EmptyRequestSerializer
        assert EmptyRequestSerializer().fields == {}

    def test_a_host_subclass_still_overrides_the_seam(self):
        from stapel_auth.otp.views import AuthViewSet
        from stapel_auth.otp.serializers import AnonymousAuthSerializer

        class MyAnonymousSerializer(AnonymousAuthSerializer):
            pass

        class HostAuthViewSet(AuthViewSet):
            anonymous_request_serializer_class = MyAnonymousSerializer

        view = HostAuthViewSet()
        view.action = "anonymous"
        assert view.get_serializer_class() is MyAnonymousSerializer

    def test_a_view_wide_serializer_class_still_wins_over_the_empty_fallback(self):
        from rest_framework import viewsets

        from stapel_auth.otp.serializers import EmailAuthRequestSerializer
        from stapel_auth.utils import SerializerSeamsMixin

        class Declared(SerializerSeamsMixin, viewsets.GenericViewSet):
            serializer_class = EmailAuthRequestSerializer

        view = Declared()
        view.action = "whatever"
        assert view.get_serializer_class() is EmailAuthRequestSerializer
