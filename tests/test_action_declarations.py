"""An ``@action(permission_classes=...)`` is applied only when a router builds
the route. ``urls_v1`` mounts every viewset with ``as_view({...})``, which
never reads the action's kwargs — so such a declaration is dead text that
reads like a gate. ``me`` and ``logout`` carried one (``IsAuthenticated``)
while the handler answered for itself.

Two genres: a roster over every mounted viewset route (no action declares a
permission the mount does not apply), and the behaviour of ``me``/``logout``
for an anonymous and an authenticated caller.
"""
import uuid

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.urls import get_resolver, reverse
from rest_framework.test import APITestCase

from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.views import _issue_session_tokens

User = get_user_model()

_ACTION_ONLY_KWARGS = ("permission_classes", "authentication_classes", "throttle_classes")


def _viewset_routes(resolver=None, prefix=""):
    resolver = resolver or get_resolver()
    for pattern in resolver.url_patterns:
        if hasattr(pattern, "url_patterns"):
            yield from _viewset_routes(pattern, prefix + str(pattern.pattern))
            continue
        callback = pattern.callback
        actions = getattr(callback, "actions", None)
        cls = getattr(callback, "cls", None)
        if actions and cls is not None:
            yield prefix + str(pattern.pattern), callback, cls, actions


_EFFECTIVE = {
    "permission_classes": "get_permissions",
    "authentication_classes": "get_authenticators",
    "throttle_classes": "get_throttles",
}


def _effective_classes(callback, cls, name, kwarg):
    """The classes the mounted view really runs for action *name* — through
    its ``get_*`` hook, which may pick per action (password, qr)."""
    view = cls(**(getattr(callback, "initkwargs", {}) or {}))
    view.action = name
    view.action_map = getattr(callback, "actions", {})
    return {type(obj) for obj in getattr(view, _EFFECTIVE[kwarg])()}


def dead_action_declarations():
    """``[(route, Class.action, kwarg)]`` whose declared classes do not all run.

    A declaration the mount applies stricter (a superset) is not dead; one
    naming a class that never runs reads like a gate that is not there.
    """
    dead = []
    for route, callback, cls, actions in _viewset_routes():
        for name in set(actions.values()):
            declared = getattr(getattr(cls, name, None), "kwargs", {}) or {}
            for kwarg in _ACTION_ONLY_KWARGS:
                if kwarg not in declared:
                    continue
                if not set(declared[kwarg]) <= _effective_classes(callback, cls, name, kwarg):
                    dead.append((route, f"{cls.__name__}.{name}", kwarg))
    return sorted(dead)


class NoDeadActionDeclarations(SimpleTestCase):
    def test_the_roster_sees_the_mounted_viewsets(self):
        names = {f"{cls.__name__}.{n}" for _r, _c, cls, a in _viewset_routes() for n in a.values()}
        self.assertIn("AuthViewSet.me", names)
        self.assertIn("SessionViewSet.revoke_all", names)

    def test_no_action_declares_a_permission_its_mount_ignores(self):
        self.assertEqual(dead_action_declarations(), [])

    def test_inversion_a_dead_declaration_is_found(self):
        from rest_framework import permissions

        from stapel_auth.otp.views import AuthViewSet

        AuthViewSet.me.kwargs["permission_classes"] = [permissions.IsAuthenticated]
        try:
            self.assertIn("AuthViewSet.me", {d[1] for d in dead_action_declarations()})
        finally:
            del AuthViewSet.me.kwargs["permission_classes"]


@override_settings(URL_PREFIX="")
class MeAndLogoutBehaviour(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            email=f"{uuid.uuid4().hex[:8]}@example.com",
            username=uuid.uuid4().hex[:12],
            password="testpass123",
        )
        self.access, self.refresh = _issue_session_tokens(self.user, None, path=SessionPath.PASSWORD)

    def test_me_anonymous_is_the_handlers_401(self):
        response = self.client.get(reverse("me"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["localizable_error"], "error.401.unauthorized")
        self.assertIn("Accept-CH", response)  # set by the handler, not by a permission

    def test_me_authenticated(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.get(reverse("me"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(str(response.json()["id"]), str(self.user.pk))

    def test_logout_anonymous_with_only_a_refresh_token(self):
        """An expired access token must not stop a logout."""
        response = self.client.post(reverse("logout"), {"refresh_token": self.refresh}, format="json")
        self.assertEqual(response.status_code, 200)
        refused = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        self.assertEqual(refused.status_code, 401)

    def test_logout_anonymous_without_anything(self):
        self.assertEqual(self.client.post(reverse("logout"), {}, format="json").status_code, 200)

    def test_logout_authenticated(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.post(reverse("logout"), {"refresh_token": self.refresh}, format="json")
        self.assertEqual(response.status_code, 200)
