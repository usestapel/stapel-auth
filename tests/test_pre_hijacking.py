"""A password registration does not prove the address it types.

``POST /password/register/`` marked a caller-supplied email/phone as verified.
An attacker registered the victim's address with a password of their own;
the victim's later email sign-in landed in that same row, where the attacker
was signed in and held the password. The anchors are now stored unverified,
and the first proof of the anchor (an OTP, a magic link, a verified OAuth
email) takes the account over: other sessions end and the credentials the
other party could have set are removed.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

User = get_user_model()

VICTIM = "victim@example.com"


@override_settings(URL_PREFIX="", STAPEL_AUTH={"AUTH_PASSWORD_REGISTRATION": True})
class PasswordRegisterDoesNotVerifyTests(TestCase):
    def _squat(self):
        resp = APIClient().post(
            reverse("password_register"),
            {"email": VICTIM, "password": "Attacker-pass-123!"},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)
        return User.objects.get(email=VICTIM)

    def test_registered_anchor_is_not_verified(self):
        user = self._squat()
        self.assertFalse(user.is_email_verified)
        self.assertFalse(user.is_phone_verified)

    def test_registered_phone_is_not_verified(self):
        resp = APIClient().post(
            reverse("password_register"),
            {"phone": "+12025550001", "password": "Attacker-pass-123!"},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)
        self.assertFalse(User.objects.get(phone="+12025550001").is_phone_verified)

    @patch("stapel_auth.otp.services.EmailVerificationService.verify_code")
    def test_the_mailbox_owner_takes_the_account_over(self, mock_verify):
        from stapel_auth.models import UserSession

        squatter = self._squat()
        self.assertTrue(UserSession.objects.filter(user=squatter, is_revoked=False).exists())
        self.assertTrue(squatter.has_usable_password())

        mock_verify.return_value = {"success": True}
        resp = APIClient().post(reverse("email_verify"), {"email": VICTIM, "code": "123456"})
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)
        self.assertEqual(resp.data["status"], "LOGGED_IN")

        user = User.objects.get(pk=squatter.pk)
        self.assertTrue(user.is_email_verified)
        self.assertFalse(user.has_usable_password())
        live = UserSession.objects.filter(user=user, is_revoked=False)
        # Only the session the owner just received is alive.
        self.assertEqual(live.count(), 1)


class ClaimByProofTests(TestCase):
    def test_a_proven_anchor_is_left_alone(self):
        from stapel_auth.accounts import claim_by_proof

        user = User.objects.create_user(
            username="owner1", email="o1@example.com", password="pw-1234567!",
            is_email_verified=True,
        )
        self.assertFalse(claim_by_proof(user, "is_email_verified"))
        user.refresh_from_db()
        self.assertTrue(user.has_usable_password())

    def test_an_issued_login_account_keeps_its_credentials(self):
        from stapel_auth.accounts import claim_by_proof

        user = User.objects.create_user(
            username="issued1", email="i1@example.com", password="pw-1234567!",
            auth_type="login",
        )
        self.assertFalse(claim_by_proof(user, "is_email_verified"))
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)
        self.assertTrue(user.has_usable_password())

    def test_a_squatted_account_loses_the_other_partys_passkeys(self):
        from stapel_auth.accounts import claim_by_proof
        from stapel_auth.models import PasskeyCredential

        user = User.objects.create_user(
            username="squat2", email="s2@example.com", password="pw-1234567!",
        )
        PasskeyCredential.objects.create(
            user=user, credential_id=b"cred-1", public_key=b"pk", sign_count=0,
        )
        self.assertTrue(claim_by_proof(user, "is_email_verified"))
        self.assertFalse(PasskeyCredential.objects.filter(user=user).exists())
