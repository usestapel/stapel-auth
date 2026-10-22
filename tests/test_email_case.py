"""One mailbox is one account, whatever the letter case.

The OTP and password doors matched email exactly: ``Alice@x.com`` and
``alice@x.com`` became two accounts, and a password login raised
``MultipleObjectsReturned`` (a 500) once both existed.
"""
import json
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

User = get_user_model()


@override_settings(URL_PREFIX="")
class EmailOTPIsCaseInsensitiveTests(TestCase):
    @patch("stapel_auth.otp.services.EmailVerificationService.verify_code")
    def test_a_case_variant_signs_into_the_existing_account(self, mock_verify):
        owner = User.objects.create_user(
            username="alice", email="alice@example.com", is_email_verified=True,
        )
        mock_verify.return_value = {"success": True}
        resp = APIClient().post(
            reverse("email_verify"), {"email": "Alice@Example.com", "code": "123456"}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)
        self.assertEqual(resp.data["status"], "LOGGED_IN")
        self.assertEqual(str(resp.data["user"]["id"]), str(owner.id))
        self.assertEqual(User.objects.filter(email__iexact="alice@example.com").count(), 1)


@override_settings(URL_PREFIX="", STAPEL_AUTH={"AUTH_PASSWORD_REGISTRATION": True})
class PasswordDoorsAreCaseInsensitiveTests(TestCase):
    def test_register_refuses_a_case_variant_of_a_taken_address(self):
        User.objects.create_user(username="bob", email="bob@example.com")
        resp = APIClient().post(
            reverse("password_register"),
            {"email": "BOB@example.com", "password": "Strong-pass-123!"},
        )
        self.assertEqual(resp.status_code, status.HTTP_409_CONFLICT, resp.content)

    def test_password_login_with_existing_duplicates_is_not_a_500(self):
        from stapel_auth.password.services import PasswordService

        User.objects.create_user(username="c1", email="carol@example.com", password="First-pass-1!")
        second = User.objects.create_user(
            username="c2", email="Carol@example.com", password="Second-pass-2!"
        )
        self.assertEqual(PasswordService.login("CAROL@example.com", "Second-pass-2!"), second)
        self.assertIsNone(PasswordService.login("carol@example.com", "wrong"))


class DuplicatesReportTests(TestCase):
    def test_lists_case_variant_groups_without_writing(self):
        User.objects.create_user(username="d1", email="dave@example.com")
        User.objects.create_user(username="d2", email="Dave@Example.com")
        User.objects.create_user(username="e1", email="erin@example.com")
        out = StringIO()
        call_command("auth_email_duplicates", "--json", stdout=out)
        report = json.loads(out.getvalue())
        self.assertEqual([g["mailbox"] for g in report], ["dave@example.com"])
        self.assertEqual(len(report[0]["accounts"]), 2)
        self.assertEqual(User.objects.count(), 3)
