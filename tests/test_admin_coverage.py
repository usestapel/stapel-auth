"""Coverage tests for the auth admin surfaces.

Targets:
- ``stapel_auth.admin`` (top-level Django ModelAdmin registrations). These now
  live in ``admin/__init__.py``; previously they were stranded in a top-level
  ``admin.py`` that the ``admin/`` package shadowed, so they never loaded in
  production. We import the package normally and assert the registrations.
- ``stapel_auth.admin.views`` (ServiceAPIKeyViewSet, AdminUserViewSet).
- ``stapel_auth.admin.serializers`` (AdminUserCreateRequestSerializer, phone
  normalization, ServiceAPIKeySerializer via the viewset).
"""
import uuid
from unittest.mock import patch

from django.contrib import admin as dj_admin
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from stapel_core.django.jwt.provider import jwt_provider

from stapel_auth.models import (
    AuthenticatorChangeRequest,
    EmailVerification,
    LoginAttempt,
    PhoneVerification,
    RefreshTokenTracker,
    ServiceAPIKey,
)

User = get_user_model()

_ADMIN_MODELS = (
    PhoneVerification,
    EmailVerification,
    ServiceAPIKey,
    RefreshTokenTracker,
    AuthenticatorChangeRequest,
    LoginAttempt,
)


def _make_user(**kwargs):
    defaults = dict(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


class FlatAdminRegistrationTests(TestCase):
    """admin/__init__.py: model registrations + ServiceAPIKeyAdmin.save_model."""

    def test_all_models_registered(self):
        import stapel_auth.admin as admin_module

        for model in _ADMIN_MODELS:
            self.assertIn(model, dj_admin.site._registry)
        # sanity: the admin classes are exposed on the package
        self.assertTrue(hasattr(admin_module, "ServiceAPIKeyAdmin"))

    def test_save_model_generates_key_on_create(self):
        import stapel_auth.admin as admin_module

        admin_obj = admin_module.ServiceAPIKeyAdmin(ServiceAPIKey, dj_admin.site)
        obj = ServiceAPIKey(name=f"create-{uuid.uuid4().hex[:6]}")
        admin_obj.save_model(request=None, obj=obj, form=None, change=False)
        self.assertTrue(obj.key.startswith("sk_"))
        self.assertTrue(ServiceAPIKey.objects.filter(pk=obj.pk).exists())

    def test_save_model_keeps_key_on_change(self):
        import stapel_auth.admin as admin_module

        admin_obj = admin_module.ServiceAPIKeyAdmin(ServiceAPIKey, dj_admin.site)
        existing_key = f"sk_manual_{uuid.uuid4().hex}"
        obj = ServiceAPIKey.objects.create(
            name=f"edit-{uuid.uuid4().hex[:6]}", key=existing_key
        )
        obj.name = "edited-name"
        admin_obj.save_model(request=None, obj=obj, form=None, change=True)
        obj.refresh_from_db()
        self.assertEqual(obj.key, existing_key)
        self.assertEqual(obj.name, "edited-name")


class AdminUserCreateSerializerTests(TestCase):
    """admin/serializers.py: validate() + _normalize_phone branches."""

    def _serializer(self, **data):
        from stapel_auth.admin.serializers import AdminUserCreateRequestSerializer

        return AdminUserCreateRequestSerializer(data=data)

    def test_requires_email_phone_or_username(self):
        ser = self._serializer()
        self.assertFalse(ser.is_valid())
        self.assertIn("email_or_phone_required", str(ser.errors))

    def test_valid_phone_is_normalized_to_e164(self):
        ser = self._serializer(phone="+1 415-555-2671")
        self.assertTrue(ser.is_valid(), ser.errors)
        self.assertEqual(ser.validated_data["phone"], "+14155552671")

    def test_unparseable_phone_raises(self):
        ser = self._serializer(phone="not-a-phone")
        self.assertFalse(ser.is_valid())
        self.assertIn("invalid_phone_format", str(ser.errors))

    def test_invalid_phone_number_raises(self):
        # Parseable (country code 1) but not a valid number.
        ser = self._serializer(phone="+12345")
        self.assertFalse(ser.is_valid())
        self.assertIn("invalid_phone", str(ser.errors))

    def test_normalize_phone_helper_direct(self):
        from stapel_auth.admin.serializers import _normalize_phone

        self.assertEqual(_normalize_phone("+14155552671"), "+14155552671")


class ServiceAPIKeyViewSetTests(APITestCase):
    """admin/views.py: ServiceAPIKeyViewSet.perform_create (key generation)."""

    def setUp(self):
        self.staff = _make_user(is_staff=True, is_superuser=True)
        access, _ = jwt_provider.create_tokens(self.staff)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def test_create_generates_key(self):
        resp = self.client.post(
            reverse("service-keys-list"),
            {"name": f"svc-{uuid.uuid4().hex[:6]}"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED, resp.content)
        key = ServiceAPIKey.objects.get(name=resp.data["name"]).key
        self.assertTrue(key.startswith("sk_"))

    def test_create_requires_admin(self):
        client = self.client_class()  # unauthenticated
        resp = client.post(
            reverse("service-keys-list"), {"name": "nope"}, format="json"
        )
        self.assertIn(
            resp.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )


class CapabilitiesViewTests(APITestCase):
    """admin/views.py: CapabilitiesView.get (public, no auth)."""

    def test_capabilities_public(self):
        resp = self.client.get(reverse("capabilities"))
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)


class AdminUserBrokerTests(APITestCase):
    """admin/views.py: AdminUserViewSet.create_user branches."""

    def _staff_client(self):
        staff = _make_user(is_staff=True)
        access, _ = jwt_provider.create_tokens(staff)
        client = self.client_class()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        return client

    def test_forbidden_without_staff_or_service_key(self):
        client = self.client_class()  # anonymous
        resp = client.post(
            reverse("admin-users"), {"email": "x@example.com"}, format="json"
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_validation_error_without_identifiers(self):
        resp = self._staff_client().post(reverse("admin-users"), {}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_creates_user_with_display_name_and_password(self):
        email = f"{uuid.uuid4().hex[:8]}@example.com"
        resp = self._staff_client().post(
            reverse("admin-users"),
            {
                "email": email,
                "display_name": "Alice",
                "password": "supersecret1",
                "mark_verified": True,
            },
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED, resp.content)
        user = User.objects.get(email=email)
        self.assertEqual(user.first_name, "Alice")
        self.assertTrue(user.is_email_verified)
        self.assertTrue(user.check_password("supersecret1"))

    def test_send_welcome_success(self):
        email = f"{uuid.uuid4().hex[:8]}@example.com"
        with patch("stapel_core.notifications.request_notification") as mock_notify:
            resp = self._staff_client().post(
                reverse("admin-users"),
                {"email": email, "send_welcome": True},
                format="json",
            )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED, resp.content)
        mock_notify.assert_called_once()

    def test_send_welcome_notification_failure_is_swallowed(self):
        email = f"{uuid.uuid4().hex[:8]}@example.com"
        with patch(
            "stapel_core.notifications.request_notification",
            side_effect=Exception("boom"),
        ):
            resp = self._staff_client().post(
                reverse("admin-users"),
                {"email": email, "send_welcome": True},
                format="json",
            )
        # Failure to notify must NOT fail user creation.
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED, resp.content)
        self.assertTrue(User.objects.filter(email=email).exists())

    def test_creates_user_via_service_api_key(self):
        svc = ServiceAPIKey.objects.create(
            name=f"svc-{uuid.uuid4().hex[:6]}", key=f"sk_{uuid.uuid4().hex}"
        )
        client = self.client_class()  # no JWT; authenticate by service key header
        phone = "+14155552671"
        resp = client.post(
            reverse("admin-users"),
            {"phone": phone, "mark_verified": True},
            format="json",
            **{"HTTP_X_API_KEY": svc.key},
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED, resp.content)
        user = User.objects.get(phone=phone)
        self.assertTrue(user.is_phone_verified)
