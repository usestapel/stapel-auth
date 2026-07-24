"""auth.provision_user + auth.mfa_status comm functions (org-program §C1-C2).

Covers: user creation (provided/generated password), namespaced-username
validation (utils helpers + the function's structured failures), duplicate
username, the strength canon on the registered verification factors, the
mfa_status matrix, the user.registered emit with the display_name hint —
and the privacy gate: the password (provided or generated) never reaches a
log line and never rides an outbox payload.
"""
import json
import logging
import uuid
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase

from stapel_core.comm import call
from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.errors import (
    ERR_400_USERNAME_NAMESPACE_INVALID,
    ERR_409_USERNAME_TAKEN,
)
from stapel_auth.utils import parse_namespaced_login, validate_local_username

User = get_user_model()


def _slug() -> str:
    return f"org{uuid.uuid4().hex[:8]}"


# ─────────────────────────────────────────────────────────────────────────────
# utils.py helpers
# ─────────────────────────────────────────────────────────────────────────────


class NamespacedLoginHelperTests(TestCase):
    def test_parse_namespaced(self):
        self.assertEqual(parse_namespaced_login("acme/alice"), ("acme", "alice"))

    def test_parse_bare_username(self):
        self.assertEqual(parse_namespaced_login("alice"), (None, "alice"))

    def test_parse_rejects_double_slash(self):
        for bad in ("a/b/c", "/alice", "acme/", "//", ""):
            with self.assertRaises(ValueError, msg=bad):
                parse_namespaced_login(bad)

    def test_validate_local_username(self):
        self.assertTrue(validate_local_username("alice"))
        self.assertTrue(validate_local_username("a.b+c@d-e_f"))
        self.assertFalse(validate_local_username("has/slash"))
        self.assertFalse(validate_local_username("has space"))
        self.assertFalse(validate_local_username(""))
        self.assertFalse(validate_local_username(None))


# ─────────────────────────────────────────────────────────────────────────────
# auth.provision_user
# ─────────────────────────────────────────────────────────────────────────────


class ProvisionUserTests(TestCase):
    def test_created_with_provided_password(self):
        username = f"{_slug()}/alice"
        result = call("auth.provision_user", {
            "username": username,
            "password": "correct-horse-battery-staple-9",
            "display_name": "Alice A.",
            "first_login_policy": "password_change",
        })
        self.assertNotIn("error", result)
        self.assertNotIn("generated_password", result)

        user = User.objects.get(pk=result["user_id"])
        self.assertEqual(user.username, username)
        self.assertEqual(user.auth_type, "login")
        self.assertIsNone(user.email)
        self.assertEqual(user.first_name, "Alice A.")
        self.assertTrue(user.password_change_required)
        self.assertFalse(user.mfa_enrollment_required)
        self.assertTrue(user.check_password("correct-horse-battery-staple-9"))

    def test_generated_password_returned_once(self):
        result = call("auth.provision_user", {
            "username": f"{_slug()}/bob",
            "first_login_policy": "mfa_enroll",
        })
        self.assertNotIn("error", result)
        generated = result["generated_password"]
        self.assertGreaterEqual(len(generated), 16)  # ~128 bits urlsafe

        user = User.objects.get(pk=result["user_id"])
        self.assertTrue(user.check_password(generated))
        self.assertFalse(user.password_change_required)
        self.assertTrue(user.mfa_enrollment_required)

    def test_duplicate_username_structured_failure(self):
        username = f"{_slug()}/carol"
        first = call("auth.provision_user", {
            "username": username, "first_login_policy": "password_change",
        })
        self.assertNotIn("error", first)
        dup = call("auth.provision_user", {
            "username": username, "first_login_policy": "password_change",
        })
        self.assertEqual(dup, {"error": ERR_409_USERNAME_TAKEN})
        self.assertEqual(User.objects.filter(username=username).count(), 1)

    def test_invalid_namespace_structured_failure(self):
        for bad in ("bare", "a/b/c", "/alice", "acme/", "acme/has space"):
            result = call("auth.provision_user", {
                "username": bad, "first_login_policy": "password_change",
            })
            self.assertEqual(
                result, {"error": ERR_400_USERNAME_NAMESPACE_INVALID}, bad
            )
        self.assertFalse(User.objects.filter(username="bare").exists())

    def test_weak_provided_password_structured_failure(self):
        from django.test import override_settings

        from stapel_core.django.api.errors import ERR_400_BAD_REQUEST

        with override_settings(AUTH_PASSWORD_VALIDATORS=[{
            "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        }]):
            result = call("auth.provision_user", {
                "username": f"{_slug()}/dave",
                "password": "short",
                "first_login_policy": "password_change",
            })
        self.assertEqual(result, {"error": ERR_400_BAD_REQUEST})

    def test_user_registered_emitted_with_display_name(self):
        username = f"{_slug()}/erin"
        result = call("auth.provision_user", {
            "username": username,
            "display_name": "Erin",
            "first_login_policy": "password_change",
        })
        payloads = [
            json.loads(row.event_json)["payload"]
            for row in OutboxEvent.objects.filter(topic="user.registered")
        ]
        mine = [p for p in payloads if p["user_id"] == result["user_id"]]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["auth_type"], "login")
        self.assertEqual(mine[0]["display_name"], "Erin")
        self.assertIsNone(mine[0]["email"])

        import jsonschema

        import stapel_auth

        schema = json.loads(
            (Path(stapel_auth.__file__).parent / "schemas" / "emits"
             / "user.registered.json").read_text()
        )
        jsonschema.validate(mine[0], schema)


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class ProvisionPasswordPrivacyTests(TestCase):
    """The password NEVER reaches logs or event payloads (privacy canon)."""

    def _capture_all_logs(self):
        handler = _CaptureHandler()
        root = logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, old_level)
        return handler

    def test_provided_password_not_logged_and_not_in_outbox(self):
        handler = self._capture_all_logs()
        secret = "extremely-secret-password-42!"
        call("auth.provision_user", {
            "username": f"{_slug()}/frank",
            "password": secret,
            "first_login_policy": "password_change",
        })
        for message in handler.messages:
            self.assertNotIn(secret, message)
        for row in OutboxEvent.objects.all():
            self.assertNotIn(secret, row.event_json)

    def test_generated_password_not_logged_and_not_in_outbox(self):
        handler = self._capture_all_logs()
        result = call("auth.provision_user", {
            "username": f"{_slug()}/grace",
            "first_login_policy": "mfa_enroll",
        })
        generated = result["generated_password"]
        for message in handler.messages:
            self.assertNotIn(generated, message)
        for row in OutboxEvent.objects.all():
            self.assertNotIn(generated, row.event_json)


# ─────────────────────────────────────────────────────────────────────────────
# Factor strength registration + auth.mfa_status matrix
# ─────────────────────────────────────────────────────────────────────────────


class FactorStrengthTests(TestCase):
    def test_registry_strengths(self):
        from stapel_core.verification import factor_registry

        strengths = {e["id"]: e["strength"] for e in factor_registry.describe()}
        self.assertEqual(strengths.get("totp"), "strong")
        self.assertEqual(strengths.get("passkey"), "strong")
        self.assertEqual(strengths.get("otp_phone"), "strong")
        self.assertEqual(strengths.get("otp_email"), "weak")


def _make_user(**kw):
    d = dict(
        email=f"{uuid.uuid4().hex[:10]}@example.com",
        username=f"u_{uuid.uuid4().hex[:10]}",
        password="testpass123!",
    )
    d.update(kw)
    return User.objects.create_user(**d)


class MfaStatusTests(TestCase):
    def _status(self, user_id):
        return call("auth.mfa_status", {"user_id": str(user_id)})

    def test_unknown_user(self):
        self.assertEqual(
            self._status(uuid.uuid4()), {"has_strong_mfa": False, "factors": []}
        )

    def test_email_only_user_is_weak(self):
        user = _make_user(is_email_verified=True)
        status = self._status(user.pk)
        self.assertFalse(status["has_strong_mfa"])
        self.assertEqual(
            status["factors"], [{"id": "otp_email", "strength": "weak"}]
        )

    def test_verified_phone_counts_as_strong(self):
        user = _make_user(phone="+79991234567", is_phone_verified=True)
        status = self._status(user.pk)
        self.assertTrue(status["has_strong_mfa"])
        self.assertIn({"id": "otp_phone", "strength": "strong"}, status["factors"])

    def test_totp_counts_as_strong(self):
        from stapel_auth.models import TOTPDevice

        user = _make_user()
        TOTPDevice.objects.create(user=user, secret="A" * 32, is_active=True)
        status = self._status(user.pk)
        self.assertTrue(status["has_strong_mfa"])
        self.assertIn({"id": "totp", "strength": "strong"}, status["factors"])

    def test_passkey_counts_as_strong(self):
        from stapel_auth.models import PasskeyCredential

        user = _make_user()
        PasskeyCredential.objects.create(
            user=user, credential_id=b"cred-1", public_key=b"pk", sign_count=0
        )
        status = self._status(user.pk)
        self.assertTrue(status["has_strong_mfa"])
        self.assertIn({"id": "passkey", "strength": "strong"}, status["factors"])


# ─────────────────────────────────────────────────────────────────────────────
# Committed schema files stay in sync with the registered schemas
# ─────────────────────────────────────────────────────────────────────────────


class CommittedSchemaSyncTests(TestCase):
    def _committed(self, name):
        import stapel_auth

        path = Path(stapel_auth.__file__).parent / "schemas" / "functions" / name
        return json.loads(path.read_text())

    def test_provision_user_schema_file(self):
        from stapel_auth.functions import PROVISION_USER_SCHEMA

        committed = self._committed("auth.provision_user.json")
        for key in ("type", "properties", "required", "additionalProperties"):
            self.assertEqual(committed[key], PROVISION_USER_SCHEMA[key], key)

    def test_mfa_status_schema_file(self):
        from stapel_auth.functions import MFA_STATUS_SCHEMA

        committed = self._committed("auth.mfa_status.json")
        for key in ("type", "properties", "required", "additionalProperties"):
            self.assertEqual(committed[key], MFA_STATUS_SCHEMA[key], key)
