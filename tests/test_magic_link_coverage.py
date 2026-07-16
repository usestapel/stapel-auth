"""Coverage tests for the magic_link package.

Exercises the REAL MagicLinkService (token create/peek/consume, rate limiting,
send) against the LocMemCache, the redirect-url serializer validation branches,
and the remaining view branches (DoesNotExist + TOTP-enabled paths).

Regression note: ``MagicLinkService.send`` used to reference ``AuditService``
without importing it (NameError on every real call, masked by end-to-end mocks
in the old suite). The module now imports it at module scope; tests of the real
``send`` patch it there — a mock of the audit boundary only.
"""
import uuid
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_auth.magic_link import services as ml_services
from stapel_auth.magic_link.serializers import MagicLinkRequestBodySerializer
from stapel_auth.magic_link.services import MagicLinkService

User = get_user_model()


def _make_user(**kwargs):
    defaults = dict(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


# =============================================================================
# MagicLinkService — real implementation against LocMemCache
# =============================================================================

class MagicLinkServiceTests(TestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_key_helpers(self):
        self.assertEqual(MagicLinkService._token_key("abc"), "magic_link:abc")
        # rate key lowercases the email
        self.assertEqual(
            MagicLinkService._rate_key("Foo@Example.COM"),
            "magic_link_rate:foo@example.com",
        )

    def test_create_returns_token_and_stores_payload(self):
        user = _make_user()
        token = MagicLinkService.create(user, redirect_url="/home")
        self.assertIsInstance(token, str)
        self.assertTrue(token)
        stored = cache.get(MagicLinkService._token_key(token))
        self.assertEqual(stored, {"user_id": str(user.id), "redirect_url": "/home"})
        # rate counter bumped
        self.assertEqual(cache.get(MagicLinkService._rate_key(user.email)), 1)

    def test_create_defaults_empty_redirect_to_slash(self):
        user = _make_user()
        token = MagicLinkService.create(user, redirect_url="")
        stored = cache.get(MagicLinkService._token_key(token))
        self.assertEqual(stored["redirect_url"], "/")

    def test_create_rate_limited_returns_none(self):
        user = _make_user()
        # Pre-fill the rate counter at the limit.
        cache.set(
            MagicLinkService._rate_key(user.email),
            MagicLinkService.RATE_LIMIT,
            MagicLinkService.RATE_WINDOW,
        )
        self.assertIsNone(MagicLinkService.create(user))

    def test_create_honours_rate_limit_after_repeated_calls(self):
        user = _make_user()
        tokens = [MagicLinkService.create(user) for _ in range(MagicLinkService.RATE_LIMIT)]
        self.assertTrue(all(tokens))
        # Next one over the limit.
        self.assertIsNone(MagicLinkService.create(user))

    def test_peek_returns_data_without_consuming(self):
        user = _make_user()
        token = MagicLinkService.create(user, redirect_url="/x")
        peeked = MagicLinkService.peek(token)
        self.assertEqual(peeked["user_id"], str(user.id))
        # Still present after peek.
        self.assertIsNotNone(MagicLinkService.peek(token))

    def test_peek_missing_token_returns_none(self):
        self.assertIsNone(MagicLinkService.peek("does-not-exist"))

    def test_consume_returns_data_then_removes_token(self):
        user = _make_user()
        token = MagicLinkService.create(user, redirect_url="/y")
        data = MagicLinkService.consume(token)
        self.assertEqual(data, {"user_id": str(user.id), "redirect_url": "/y"})
        # Second consume finds nothing.
        self.assertIsNone(MagicLinkService.consume(token))
        self.assertIsNone(cache.get(MagicLinkService._token_key(token)))

    def test_consume_missing_token_returns_none(self):
        self.assertIsNone(MagicLinkService.consume("nope"))

    @override_settings(FRONTEND_URL="https://app.example.com")
    def test_send_creates_token_and_enqueues_notification(self):
        user = _make_user()
        audit = MagicMock()
        with patch("stapel_core.notifications.request_notification") as notify, \
                patch.object(ml_services, "AuditService", audit, create=True):
            result = MagicLinkService.send(user, redirect_url="/dash")
        self.assertTrue(result)
        notify.assert_called_once()
        kwargs = notify.call_args.kwargs
        self.assertEqual(kwargs["notification_type"], "magic_link_login")
        self.assertEqual(kwargs["email"], user.email)
        self.assertIn("/auth/api/v1/magic/verify/?token=", kwargs["variables"]["link"])
        self.assertTrue(kwargs["variables"]["link"].startswith("https://app.example.com"))
        audit.log.assert_called_once()

    def test_send_rate_limited_returns_false(self):
        user = _make_user()
        cache.set(
            MagicLinkService._rate_key(user.email),
            MagicLinkService.RATE_LIMIT,
            MagicLinkService.RATE_WINDOW,
        )
        with patch("stapel_core.notifications.request_notification") as notify:
            self.assertFalse(MagicLinkService.send(user))
        notify.assert_not_called()


# =============================================================================
# MagicLinkRequestBodySerializer — redirect_url validation branches
# =============================================================================

class MagicLinkRedirectUrlValidationTests(TestCase):
    def _validate(self, redirect_url):
        ser = MagicLinkRequestBodySerializer(
            data={"email": "user@example.com", "redirect_url": redirect_url}
        )
        return ser

    def test_blank_and_slash_normalise_to_slash(self):
        for value in ("", "/"):
            ser = self._validate(value)
            self.assertTrue(ser.is_valid(), ser.errors)
            self.assertEqual(ser.validated_data["redirect_url"], "/")

    def test_valid_relative_path_passes(self):
        ser = self._validate("/app/meeting/abc")
        self.assertTrue(ser.is_valid(), ser.errors)
        self.assertEqual(ser.validated_data["redirect_url"], "/app/meeting/abc")

    def test_absolute_url_rejected(self):
        ser = self._validate("https://evil.com")
        self.assertFalse(ser.is_valid())
        self.assertIn("redirect_url", ser.errors)

    def test_protocol_relative_slashes_rejected(self):
        ser = self._validate("//evil.com")
        self.assertFalse(ser.is_valid())
        self.assertIn("redirect_url", ser.errors)

    def test_backslash_protocol_relative_rejected(self):
        ser = self._validate("/\\evil.com")
        self.assertFalse(ser.is_valid())
        self.assertIn("redirect_url", ser.errors)


# =============================================================================
# Views — request_link + verify remaining branches (real service)
# =============================================================================

@override_settings(FRONTEND_URL="https://app.example.com")
class MagicLinkViewCoverageTests(APITestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_request_link_real_send_returns_200(self):
        user = _make_user()
        audit = MagicMock()
        with patch("stapel_core.notifications.request_notification") as notify, \
                patch.object(ml_services, "AuditService", audit, create=True):
            resp = self.client.post(
                reverse("magic_request"),
                {"email": user.email, "redirect_url": "/dash"},
                format="json",
            )
        self.assertEqual(resp.status_code, 200)
        notify.assert_called_once()

    def test_verify_user_deleted_redirects_to_error(self):
        """consume() succeeds but the referenced user no longer exists -> DoesNotExist."""
        user = _make_user()
        token = MagicLinkService.create(user, redirect_url="/home")
        user.delete()
        resp = self.client.get(reverse("magic_verify") + f"?token={token}")
        self.assertIn(resp.status_code, [301, 302])
        self.assertIn("invalid_link", resp["Location"])

    def test_verify_totp_enabled_redirects_to_challenge(self):
        user = _make_user()
        token = MagicLinkService.create(user, redirect_url="/home")
        with patch.object(User, "totp_enabled", True, create=True), \
                patch(
                    "stapel_auth.mfa.services.TOTPService.create_challenge",
                    return_value="challenge-xyz",
                ):
            resp = self.client.get(reverse("magic_verify") + f"?token={token}")
        self.assertIn(resp.status_code, [301, 302])
        self.assertIn("challenge_token=challenge-xyz", resp["Location"])
        self.assertIn("next=%2Fhome", resp["Location"])

    def test_verify_valid_token_real_flow_sets_cookies(self):
        user = _make_user()
        token = MagicLinkService.create(user, redirect_url="/home")
        resp = self.client.get(reverse("magic_verify") + f"?token={token}")
        self.assertIn(resp.status_code, [301, 302])
        self.assertEqual(resp["Location"], "/home")
        # token consumed
        self.assertIsNone(MagicLinkService.peek(token))
