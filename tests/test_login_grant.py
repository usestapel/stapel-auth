"""Login grant primitive (workspaces-org-program §B3).

Covers the full contract of the ``login_grant/`` package + the
``auth.issue_login_grant`` comm function:

* issue → exchange happy path for an existing user (LOGGED_IN, JWT session);
* ``create_if_missing`` provisioning (auth_type=email, verified address,
  unusable password, REGISTERED, ``user.registered`` with the language hint);
* single-use (second exchange 400) and TTL expiry;
* the ``AUTH_LOGIN_GRANT`` gate (default off): factory yields no URLs / 404,
  always-on mount 403s per-request;
* comm function registration, payload schema validation, committed schema
  file identity;
* privacy: neither the grant token nor the email ever reaches the logs.
"""
import json
import logging
import sys
import types
import uuid
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from unittest import mock

from stapel_auth.login_grant.services import LoginGrantService, issue_login_grant

User = get_user_model()

_GRANT_ON = {'AUTH_LOGIN_GRANT': True}


def _make_user(**kwargs):
    defaults = dict(
        email=f"grant-{uuid.uuid4().hex[:10]}@example.com",
        username=f"grant_{uuid.uuid4().hex[:10]}",
        password="testpass123",
        is_email_verified=True,
        auth_type="email",
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


def _build_urlconf(name: str) -> str:
    """Materialize a urlconf from the flag-consulting factory (host-style)."""
    from stapel_auth import urls_v1 as auth_urls

    mod = types.ModuleType(name)
    mod.urlpatterns = [*auth_urls.get_login_grant_urls()]
    sys.modules[name] = mod
    return name


# ─────────────────────────────────────────────────────────────────────────────
# Service mechanics: create/peek/consume, single-use, TTL
# ─────────────────────────────────────────────────────────────────────────────


class LoginGrantServiceTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_issue_and_peek_normalizes_email(self):
        token = issue_login_grant(email="  MiXeD@Example.COM ", language="ru")
        data = LoginGrantService.peek(token)
        self.assertEqual(data["email"], "mixed@example.com")
        self.assertTrue(data["verified_email"])
        self.assertFalse(data["create_if_missing"])
        self.assertEqual(data["language"], "ru")

    def test_consume_is_single_use(self):
        token = issue_login_grant(email="once@example.com")
        self.assertIsNotNone(LoginGrantService.consume(token))
        self.assertIsNone(LoginGrantService.consume(token))
        self.assertIsNone(LoginGrantService.peek(token))

    def test_unknown_token_is_none(self):
        self.assertIsNone(LoginGrantService.consume("nope"))
        self.assertIsNone(LoginGrantService.exchange("nope"))

    def test_ttl_expiry(self):
        with mock.patch.object(LoginGrantService, "TTL", -1):
            token = issue_login_grant(email="late@example.com")
        self.assertIsNone(LoginGrantService.consume(token))

    def test_exchange_existing_user_logs_in(self):
        user = _make_user()
        token = issue_login_grant(email=user.email.upper())
        result = LoginGrantService.exchange(token)
        self.assertEqual(result, (user, False))

    def test_exchange_inactive_user_is_rejected(self):
        user = _make_user(is_active=False)
        token = issue_login_grant(email=user.email, create_if_missing=True)
        self.assertIsNone(LoginGrantService.exchange(token))
        # ... and the account was NOT duplicated by create_if_missing.
        self.assertEqual(User.objects.filter(email=user.email).count(), 1)

    def test_exchange_without_create_if_missing_needs_a_user(self):
        token = issue_login_grant(email="ghost@example.com")
        self.assertIsNone(LoginGrantService.exchange(token))
        self.assertFalse(User.objects.filter(email="ghost@example.com").exists())

    def test_exchange_create_if_missing_provisions_verified_user(self):
        token = issue_login_grant(
            email="new@example.com", create_if_missing=True, language="ru"
        )
        with mock.patch("stapel_auth.otp.views._notify_user_registered") as notify:
            user, created = LoginGrantService.exchange(token)
        self.assertTrue(created)
        self.assertEqual(user.email, "new@example.com")
        self.assertEqual(user.auth_type, "email")
        self.assertTrue(user.is_email_verified)
        self.assertFalse(user.has_usable_password())
        notify.assert_called_once_with(user, language="ru")

    def test_exchange_create_respects_unverified_hint(self):
        token = issue_login_grant(
            email="soft@example.com", verified_email=False, create_if_missing=True
        )
        user, created = LoginGrantService.exchange(token)
        self.assertTrue(created)
        self.assertFalse(user.is_email_verified)

    def test_created_user_emits_user_registered_with_language(self):
        token = issue_login_grant(
            email="evt@example.com", create_if_missing=True, language="ru"
        )
        with mock.patch("stapel_core.comm.emit") as emit:
            user, _created = LoginGrantService.exchange(token)
        action, payload = emit.call_args[0][0], emit.call_args[0][1]
        self.assertEqual(action, "user.registered")
        self.assertEqual(payload["user_id"], str(user.id))
        self.assertEqual(payload["auth_type"], "email")
        self.assertEqual(payload["language"], "ru")


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint: POST /grant/exchange/
# ─────────────────────────────────────────────────────────────────────────────


@override_settings(STAPEL_AUTH=_GRANT_ON)
class LoginGrantExchangeEndpointTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.url = reverse("grant_exchange")

    def test_exchange_existing_user_happy_path(self):
        user = _make_user()
        token = issue_login_grant(email=user.email)
        response = self.client.post(self.url, {"grant_token": token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "LOGGED_IN")
        self.assertEqual(str(response.data["user"]["id"]), str(user.id))
        self.assertTrue(response.data["tokens"]["access"])
        self.assertTrue(response.data["tokens"]["refresh"])
        # Full JWT session: cookies set like every other login flow.
        self.assertIn("stapel_jwt", response.cookies)
        self.assertIn("stapel_refresh_jwt", response.cookies)

    def test_exchange_create_if_missing_registers(self):
        token = issue_login_grant(
            email="fresh@example.com", create_if_missing=True
        )
        response = self.client.post(self.url, {"grant_token": token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "REGISTERED")
        user = User.objects.get(email="fresh@example.com")
        self.assertTrue(user.is_email_verified)
        self.assertFalse(user.has_usable_password())

    def test_second_exchange_is_400(self):
        user = _make_user()
        token = issue_login_grant(email=user.email)
        first = self.client.post(self.url, {"grant_token": token})
        self.assertEqual(first.status_code, status.HTTP_200_OK)
        second = self.client.post(self.url, {"grant_token": token})
        self.assertEqual(second.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(second.data["localizable_error"], "error.400.grant_invalid")

    def test_expired_grant_is_400(self):
        user = _make_user()
        with mock.patch.object(LoginGrantService, "TTL", -1):
            token = issue_login_grant(email=user.email)
        response = self.client.post(self.url, {"grant_token": token})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["localizable_error"], "error.400.grant_invalid")

    def test_unknown_grant_is_400(self):
        response = self.client.post(self.url, {"grant_token": "bogus"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["localizable_error"], "error.400.grant_invalid")

    def test_unresolvable_grant_is_400_not_registration(self):
        token = issue_login_grant(email="nobody@example.com")  # no create_if_missing
        response = self.client.post(self.url, {"grant_token": token})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(email="nobody@example.com").exists())


# ─────────────────────────────────────────────────────────────────────────────
# AUTH_LOGIN_GRANT gate (default off)
# ─────────────────────────────────────────────────────────────────────────────


class LoginGrantGateTests(APITestCase):
    def test_default_off_factory_yields_no_urls(self):
        from stapel_auth import urls_v1 as auth_urls

        self.assertEqual(auth_urls.get_login_grant_urls(), [])

    @override_settings(STAPEL_AUTH=_GRANT_ON)
    def test_on_factory_yields_exchange_url(self):
        from stapel_auth import urls_v1 as auth_urls

        names = [p.name for p in auth_urls.get_login_grant_urls()]
        self.assertEqual(names, ["grant_exchange"])

    def test_gate_registered_in_gate_registry(self):
        from stapel_auth.urls import GATE_REGISTRY

        entry = GATE_REGISTRY["login_grant"]
        self.assertEqual(entry.flags, ("AUTH_LOGIN_GRANT",))
        self.assertEqual([p.name for p in entry.patterns], ["grant_exchange"])

    def test_default_off_endpoint_404s_on_factory_mount(self):
        urlconf = _build_urlconf("tests._urlconf_login_grant_off")
        with override_settings(ROOT_URLCONF=urlconf):
            response = self.client.post("/grant/exchange/", {"grant_token": "x"})
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_default_off_view_403s_on_always_on_mount(self):
        # include('stapel_auth.urls') keeps every path mounted; the
        # per-request gate inside the view is the enforcement there.
        response = self.client.post(reverse("grant_exchange"), {"grant_token": "x"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# ─────────────────────────────────────────────────────────────────────────────
# auth.issue_login_grant comm function
# ─────────────────────────────────────────────────────────────────────────────


class IssueLoginGrantFunctionTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_function_registered_in_ready(self):
        from stapel_core.comm.registry import function_registry

        self.assertIn("auth.issue_login_grant", function_registry.names())

    def test_issue_roundtrip(self):
        from stapel_core.comm import call

        user = _make_user()
        result = call("auth.issue_login_grant", {"email": user.email})
        token = result["grant_token"]
        self.assertIsInstance(token, str)
        self.assertEqual(LoginGrantService.exchange(token), (user, False))

    def test_issue_with_all_hints(self):
        from stapel_core.comm import call

        result = call("auth.issue_login_grant", {
            "email": "invitee@example.com",
            "verified_email": True,
            "create_if_missing": True,
            "language": "ru",
        })
        data = LoginGrantService.peek(result["grant_token"])
        self.assertEqual(data, {
            "email": "invitee@example.com",
            "verified_email": True,
            "create_if_missing": True,
            "language": "ru",
        })

    @override_settings(STAPEL_COMM={"VALIDATE_SCHEMAS": True})
    def test_schema_rejects_bad_payload(self):
        from stapel_core.comm import call
        from stapel_core.comm.exceptions import SchemaValidationError

        with self.assertRaises(SchemaValidationError):
            call("auth.issue_login_grant", {})
        with self.assertRaises(SchemaValidationError):
            call("auth.issue_login_grant", {"email": 42})
        with self.assertRaises(SchemaValidationError):
            call("auth.issue_login_grant",
                 {"email": "a@b.c", "create_if_missing": "yes"})
        with self.assertRaises(SchemaValidationError):
            call("auth.issue_login_grant", {"email": "a@b.c", "extra": "no"})

    def test_committed_schema_file_matches_registered_schema(self):
        import stapel_auth
        from stapel_auth.functions import ISSUE_LOGIN_GRANT_SCHEMA

        schema_file = (
            Path(stapel_auth.__file__).parent
            / "schemas" / "functions" / "auth.issue_login_grant.json"
        )
        committed = json.loads(schema_file.read_text())
        for key in ("type", "properties", "required", "additionalProperties"):
            self.assertEqual(committed[key], ISSUE_LOGIN_GRANT_SCHEMA[key], key)


# ─────────────────────────────────────────────────────────────────────────────
# Privacy: the token (and the email alongside it) never reaches the logs
# ─────────────────────────────────────────────────────────────────────────────


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@override_settings(STAPEL_AUTH=_GRANT_ON)
class LoginGrantPrivacyTests(APITestCase):
    def setUp(self):
        cache.clear()

    def test_token_and_email_never_logged(self):
        email = "privacy-probe@example.com"
        handler = _CaptureHandler()
        root = logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            token = issue_login_grant(email=email, create_if_missing=True)
            response = self.client.post(
                reverse("grant_exchange"), {"grant_token": token}
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
        joined = "\n".join(handler.messages)
        self.assertNotIn(token, joined, "grant token leaked into logs")
        self.assertNotIn(email, joined, "grant email leaked into logs")
