"""Every account birth announces ``user.registered``.

Profiles, workspaces and notifications provision on that event only. The
phone-OTP door, the admin broker (``POST /admin/users/``) and SSO provisioning
created users without it, so a phone-first product's users had no profile row
(Follow answered 404) and no personal workspace. All creation sites now go
through ``stapel_auth.accounts.create_account``; the architecture test below
refuses a bare ``User.objects.create`` anywhere else in the package.
"""
import json
import re
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from stapel_core.django.outbox.models import OutboxEvent

User = get_user_model()

PACKAGE = Path(__file__).resolve().parent.parent
CREATION = re.compile(
    r"\b(?:User|U|user_model|get_user_model\(\))\.objects\."
    r"(?:create|create_user|create_superuser|get_or_create|update_or_create|bulk_create)\("
)


def _registered_ids():
    return [
        json.loads(row.event_json)["payload"]["user_id"]
        for row in OutboxEvent.objects.filter(topic="user.registered")
    ]


@override_settings(URL_PREFIX="")
class PhoneRegistrationAnnouncesTests(APITestCase):
    @patch("stapel_auth.otp.services.PhoneVerificationService.verify_code")
    def test_a_new_phone_account_emits_user_registered(self, mock_verify):
        mock_verify.return_value = {"success": True}
        resp = APIClient().post(
            reverse("phone_verify"), {"phone": "+12025559876", "code": "1234"}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)
        self.assertEqual(resp.data["status"], "REGISTERED")
        user = User.objects.get(phone="+12025559876")
        self.assertEqual(_registered_ids().count(str(user.id)), 1)


@override_settings(URL_PREFIX="")
class AdminBrokerAnnouncesTests(APITestCase):
    def test_admin_created_account_emits_user_registered(self):
        from stapel_auth.models import ServiceAPIKey

        ServiceAPIKey.objects.create(name="svc", key="svc-key-birth", is_active=True)
        resp = APIClient().post(
            reverse("admin-users"),
            {"email": "brokered@example.com", "display_name": "Bro"},
            HTTP_X_API_KEY="svc-key-birth",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED, resp.content)
        user = User.objects.get(email="brokered@example.com")
        self.assertEqual(_registered_ids().count(str(user.id)), 1)


class SSOProvisionAnnouncesTests(TestCase):
    def test_sso_created_account_emits_user_registered(self):
        from stapel_auth.sso_service import SSOUserService

        user, created = SSOUserService._provision(
            None,
            {"email": "sso-new@example.com", "first_name": "S"},
            None,
            None,
            promote_anonymous_session=lambda *a, **k: None,
        )
        self.assertTrue(created)
        self.assertEqual(_registered_ids().count(str(user.id)), 1)


class NoBareAccountCreationTests(TestCase):
    def test_only_accounts_py_creates_user_rows(self):
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            rel = path.relative_to(PACKAGE)
            if rel.parts[0] in {"tests", "migrations", ".venv", "build"} or "migrations" in rel.parts:
                continue
            if rel.as_posix() == "accounts.py":
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if CREATION.search(line):
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
        self.assertEqual(offenders, [], "create accounts through accounts.create_account")

    def test_the_pattern_sees_a_bare_create(self):
        self.assertTrue(CREATION.search("    user = User.objects.create(phone=p)"))
        self.assertTrue(CREATION.search("return U.objects.create("))
        self.assertFalse(CREATION.search("Session.objects.create(user=u)"))
