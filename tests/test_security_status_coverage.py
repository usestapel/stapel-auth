"""Coverage tests for stapel_auth.security.views.

Targets the gaps left by tests/test_extra.py:
- SecurityStatusViewSet.status (security-status endpoint) — every factor branch.
- AdminAuditLogViewSet.list_logs (admin audit log with all filters).
- AuditLogViewSet.get_log filter branches (event_type / date_from / date_to).
- RevokeSuspiciousView edge branches: user DoesNotExist, no-email skip,
  notification-send exception swallowed.
"""
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.signing import TimestampSigner
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

User = get_user_model()


def _make_user(**kwargs):
    defaults = dict(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


def _auth(client, user):
    from stapel_core.django.jwt.provider import jwt_provider

    access, _ = jwt_provider.create_tokens(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")


# =============================================================================
# SecurityStatusViewSet.status — the security-status endpoint (lines 46-97)
# =============================================================================


class SecurityStatusTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        _auth(self.client, self.user)

    def test_requires_auth(self):
        self.client.credentials()
        resp = self.client.get(reverse("security_status"))
        self.assertEqual(resp.status_code, 401)

    def test_status_minimal_user_shape(self):
        resp = self.client.get(reverse("security_status"))
        self.assertEqual(resp.status_code, 200)
        data = resp.data
        # Full posture shape is present.
        for key in (
            "password",
            "totp",
            "email",
            "phone",
            "oauth",
            "sessions",
            "passkeys",
        ):
            self.assertIn(key, data)
        self.assertEqual(data["totp"]["is_enabled"], False)
        self.assertEqual(data["sessions"]["active_count"], 0)
        self.assertEqual(data["passkeys"]["count"], 0)
        self.assertEqual(data["oauth"]["connected_providers"], [])
        # Email is set on the user → masked, not None.
        self.assertIsNotNone(data["email"]["value"])
        self.assertIn("***@", data["email"]["value"])
        # Phone is absent → masked to None.
        self.assertIsNone(data["phone"]["value"])

    def test_status_with_all_factors(self):
        from stapel_auth.models import PasskeyCredential

        # A phone + oauth provider on the user.
        User.objects.filter(pk=self.user.pk).update(
            phone="+12025550199",
            is_phone_verified=True,
            is_email_verified=True,
            oauth_provider="google",
        )
        # An active passkey.
        PasskeyCredential.objects.create(
            user=self.user,
            credential_id=uuid.uuid4().bytes,
            public_key=b"fakepublickeybytes",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            is_active=True,
        )
        with patch(
            "stapel_auth.services.SessionService.get_active"
        ) as mock_active, patch(
            "stapel_auth.services.TOTPService.is_enabled", return_value=True
        ), patch(
            "stapel_auth.services.TOTPService.backup_codes_remaining", return_value=6
        ):
            mock_active.return_value.count.return_value = 3
            resp = self.client.get(reverse("security_status"))
        self.assertEqual(resp.status_code, 200)
        data = resp.data
        self.assertEqual(data["totp"]["is_enabled"], True)
        self.assertEqual(data["totp"]["backup_codes_remaining"], 6)
        self.assertEqual(data["sessions"]["active_count"], 3)
        self.assertEqual(data["passkeys"]["count"], 1)
        self.assertEqual(data["oauth"]["connected_providers"], ["google"])
        # Phone is now set → masked value present.
        self.assertIsNotNone(data["phone"]["value"])
        self.assertIn("***", data["phone"]["value"])
        self.assertTrue(data["phone"]["is_verified"])

    def test_status_no_email_masks_to_none(self):
        # Cover the mask_email early-return (falsy email) branch. Mint the token
        # after clearing the email so the authenticated identity has no email.
        user = _make_user()
        User.objects.filter(pk=user.pk).update(email="")
        user.refresh_from_db()
        _auth(self.client, user)
        resp = self.client.get(reverse("security_status"))
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.data["email"]["value"])


# =============================================================================
# AuditLogViewSet.get_log — filter branches (lines 140, 142, 144)
# =============================================================================


class AuditLogFilterTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        _auth(self.client, self.user)
        from stapel_auth.models import AuthAuditLog

        self.entry = AuthAuditLog.objects.create(
            user=self.user,
            event_type="login_success",
            ip_address="1.2.3.4",
            user_agent="UA",
            metadata={},
        )

    def test_filter_by_event_type(self):
        resp = self.client.get(
            reverse("security_audit") + "?event_type=login_success"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["count"], 1)

    def test_filter_by_event_type_no_match(self):
        resp = self.client.get(reverse("security_audit") + "?event_type=logout")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["count"], 0)

    def test_filter_by_date_range(self):
        past = (timezone.now() - timedelta(days=1)).date().isoformat()
        future = (timezone.now() + timedelta(days=1)).date().isoformat()
        resp = self.client.get(
            reverse("security_audit") + f"?date_from={past}&date_to={future}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["count"], 1)

    def test_filter_by_date_from_excludes_past(self):
        future = (timezone.now() + timedelta(days=2)).date().isoformat()
        resp = self.client.get(reverse("security_audit") + f"?date_from={future}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["count"], 0)


# =============================================================================
# AdminAuditLogViewSet.list_logs — admin audit log (lines 191-225)
# =============================================================================


class AdminAuditLogTests(APITestCase):
    def setUp(self):
        self.admin = _make_user(is_staff=True, is_superuser=True)
        self.other = _make_user()
        _auth(self.client, self.admin)
        from stapel_auth.models import AuthAuditLog

        AuthAuditLog.objects.create(
            user=self.admin,
            event_type="login_success",
            ip_address="1.1.1.1",
            user_agent="UA",
            metadata={},
        )
        AuthAuditLog.objects.create(
            user=self.other,
            event_type="logout",
            ip_address="2.2.2.2",
            user_agent="UA",
            metadata={},
        )

    def test_non_admin_forbidden(self):
        _auth(self.client, self.other)
        resp = self.client.get(reverse("admin-audit"))
        self.assertIn(resp.status_code, (401, 403))

    def test_admin_sees_all_users(self):
        resp = self.client.get(reverse("admin-audit"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["count"], 2)

    def test_admin_filter_by_user_id(self):
        resp = self.client.get(
            reverse("admin-audit") + f"?user_id={self.other.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["count"], 1)
        self.assertEqual(resp.data["results"][0]["event_type"], "logout")

    def test_admin_filter_by_event_type(self):
        resp = self.client.get(reverse("admin-audit") + "?event_type=logout")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["count"], 1)

    def test_admin_filter_by_date_range(self):
        past = (timezone.now() - timedelta(days=1)).date().isoformat()
        future = (timezone.now() + timedelta(days=1)).date().isoformat()
        resp = self.client.get(
            reverse("admin-audit") + f"?date_from={past}&date_to={future}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["count"], 2)

    def test_admin_pagination_next(self):
        from stapel_auth.models import AuthAuditLog

        # Push total over the 50-row page size.
        for _ in range(55):
            AuthAuditLog.objects.create(
                user=self.admin,
                event_type="login_success",
                ip_address="3.3.3.3",
                user_agent="UA",
                metadata={},
            )
        resp = self.client.get(reverse("admin-audit") + "?page=1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data["results"]), 50)
        self.assertEqual(resp.data["next"], 2)


# =============================================================================
# RevokeSuspiciousView — DoesNotExist, no-email, notification-error branches
# =============================================================================


class RevokeSuspiciousEdgeTests(TestCase):
    def _token(self, user_id, session_id):
        return TimestampSigner().sign(f"{user_id}:{session_id}")

    def test_invalid_token_redirects_to_error(self):
        resp = self.client.get(reverse("revoke_suspicious") + "?token=badtoken")
        self.assertIn(resp.status_code, (301, 302))
        self.assertIn("invalid_link", resp["Location"])

    def test_unknown_user_returns_404(self):
        token = self._token(uuid.uuid4(), uuid.uuid4())
        resp = self.client.get(reverse("revoke_suspicious") + f"?token={token}")
        self.assertEqual(resp.status_code, 404)

    def test_user_without_email_skips_notification(self):
        from stapel_auth.models import UserSession

        user = _make_user()
        User.objects.filter(pk=user.pk).update(email="")
        session = UserSession.objects.create(
            user=user,
            jti=uuid.uuid4().hex,
            device_name="Test",
            device_type="desktop",
            expires_at=timezone.now() + timedelta(days=30),
        )
        token = self._token(user.id, session.id)
        with patch(
            "stapel_core.notifications.request_notification"
        ) as mock_notify, patch("stapel_auth.services.AuditService.log"):
            resp = self.client.get(
                reverse("revoke_suspicious") + f"?token={token}"
            )
        self.assertIn(resp.status_code, (301, 302))
        self.assertIn("sessions_revoked", resp["Location"])
        mock_notify.assert_not_called()
        session.refresh_from_db()
        self.assertTrue(session.is_revoked)

    def test_notification_exception_is_swallowed(self):
        from stapel_auth.models import UserSession

        user = _make_user()
        session = UserSession.objects.create(
            user=user,
            jti=uuid.uuid4().hex,
            device_name="Test",
            device_type="desktop",
            expires_at=timezone.now() + timedelta(days=30),
        )
        token = self._token(user.id, session.id)
        with patch(
            "stapel_core.notifications.request_notification",
            side_effect=Exception("boom"),
        ), patch("stapel_auth.services.AuditService.log"):
            resp = self.client.get(
                reverse("revoke_suspicious") + f"?token={token}"
            )
        # Redirect still succeeds despite the notification failure.
        self.assertIn(resp.status_code, (301, 302))
        self.assertIn("sessions_revoked", resp["Location"])
        session.refresh_from_db()
        self.assertTrue(session.is_revoked)
