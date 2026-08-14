"""An action nobody classified must be closed, not public.

Two viewsets resolved permissions from an allowlist of AUTHENTICATED actions
and answered ``AllowAny`` for everything else (``PasswordViewSet``,
``QRAuthViewSet``), and the admin broker declared ``AllowAny`` at class level
with the real staff/service-key rule written inside one handler's body
(``AdminUserViewSet``). No open endpoint came out of it — every action that
existed was classified — but the failure mode of *adding* one was "public",
and that is a defect of shape, not of the current inventory.

``MfaEnrollViewSet``/``TOTPViewSet`` already had the inverted, correct shape:
name the anonymous actions, require a session for the rest. These tests pin
that shape on the three that did not, in the only way that survives someone
adding an action next year: they ask the viewset about an action name that
does not exist, which is what "the action I add tomorrow" looks like today.
"""
import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework import permissions
from rest_framework.test import APITestCase

from stapel_auth.admin.views import AdminUserViewSet
from stapel_auth.password.views import PasswordViewSet
from stapel_auth.permissions import DenyEnrollOnly, IsStaffOrServiceAPIKey
from stapel_auth.qr.views import QRAuthViewSet

User = get_user_model()


def _classes(viewset_cls, action):
    view = viewset_cls()
    view.action = action
    return [type(p) for p in view.get_permissions()]


class UnlistedActionsDenyByDefaultTests(TestCase):
    """The question is about the action nobody wrote down."""

    def test_password_viewset_denies_an_unlisted_action(self):
        self.assertEqual(
            _classes(PasswordViewSet, "an_action_added_next_year"),
            [permissions.IsAuthenticated, DenyEnrollOnly],
        )

    def test_qr_viewset_denies_an_unlisted_action(self):
        self.assertEqual(
            _classes(QRAuthViewSet, "an_action_added_next_year"),
            [permissions.IsAuthenticated, DenyEnrollOnly],
        )

    def test_the_admin_broker_is_closed_at_class_level(self):
        """Not "closed inside create_user" — closed for the whole viewset."""
        self.assertEqual(
            AdminUserViewSet.permission_classes,
            [IsStaffOrServiceAPIKey, DenyEnrollOnly],
        )
        self.assertNotIn(permissions.AllowAny, AdminUserViewSet.permission_classes)

    def test_the_public_actions_are_the_ones_declared_public(self):
        """The allowlists still work — deny-by-default is not deny-always."""
        for action in PasswordViewSet._public_actions:
            self.assertEqual(
                _classes(PasswordViewSet, action), [permissions.AllowAny], action
            )
        for action in QRAuthViewSet._public_actions:
            self.assertEqual(
                _classes(QRAuthViewSet, action), [permissions.AllowAny], action
            )

    def test_every_declared_public_action_actually_exists(self):
        """An allowlist entry for a renamed action is a silent hole."""
        for cls in (PasswordViewSet, QRAuthViewSet):
            for action in cls._public_actions:
                self.assertTrue(
                    callable(getattr(cls, action, None)),
                    f"{cls.__name__}._public_actions names a missing action {action!r}",
                )


class AuthenticatedSurfacesStayAuthenticatedTests(APITestCase):
    """End to end: the endpoints that were already closed answer the same."""

    def test_password_methods_still_requires_a_session(self):
        resp = self.client.get(reverse("password_methods"))
        self.assertIn(resp.status_code, (401, 403))

    def test_qr_confirm_still_requires_a_session(self):
        resp = self.client.post(reverse("qr_confirm", args=["nokey"]))
        self.assertIn(resp.status_code, (401, 403))

    def test_the_admin_broker_refuses_an_anonymous_caller_with_403(self):
        resp = self.client.post(
            reverse("admin-users"), {"email": "x@example.com"}, format="json"
        )
        self.assertEqual(resp.status_code, 403, resp.content)
        self.assertFalse(User.objects.filter(email="x@example.com").exists())

    def test_the_admin_broker_refuses_an_ordinary_authenticated_caller(self):
        from stapel_core.django.jwt.provider import jwt_provider

        civilian = User.objects.create_user(
            email=f"civ-{uuid.uuid4().hex[:8]}@example.com",
            username=f"civ_{uuid.uuid4().hex[:8]}",
            password="x",
        )
        access, _ = jwt_provider.create_tokens(civilian)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        resp = self.client.post(
            reverse("admin-users"), {"email": "y@example.com"}, format="json"
        )
        self.assertEqual(resp.status_code, 403, resp.content)
        self.assertFalse(User.objects.filter(email="y@example.com").exists())
