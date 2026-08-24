"""A code to a NEW address cannot overwrite an address the account proved.

Audit F4, confirmed in production in both code paths. ``POST /email/verify/``
and ``POST /phone/verify/`` took an authenticated non-anonymous session, an
OTP delivered to whatever address the caller named, and wrote::

    request_user.email = email
    request_user.is_email_verified = True
    request_user.save()

Possession of the NEW address proves the caller controls the new address. It
says nothing about the one already on the account — so anyone holding a live
session (a stolen JWT, a borrowed unlocked phone, an XSS) could point the
recovery address at themselves and lock the real owner out permanently. The
request-old → verify-old → ``change_token`` machinery that proves the CURRENT
authenticator lives in the very same module and was simply bypassed.

The line drawn here: SET a first authenticator in one step (there is nothing
to prove yet), CHANGE a verified one only through the change flow. There is
no configuration axis — a deployment cannot opt back into the takeover.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()

MOCK_OTP = dict(
    URL_PREFIX="", USE_MOCK_SMS_OTP=True, USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="0000"
)

CHANGE_REQUIRES_CURRENT = "error.403.change_requires_current"


@override_settings(**MOCK_OTP)
class RewritingAVerifiedEmailIsRefusedTests(APITestCase):
    def setUp(self):
        from stapel_auth.otp.services import EmailVerificationService

        self.user = User.objects.create_user(
            username="owner",
            email="owner@example.com",
            is_email_verified=True,
        )
        self.client.force_authenticate(user=self.user)
        self.svc = EmailVerificationService()

    def test_verify_refuses_a_different_address(self):
        """The regression test: this used to return 200 MODIFIED."""
        self.svc.send_verification_code("attacker@example.com")
        response = self.client.post(
            reverse("email_verify"),
            {"email": "attacker@example.com", "code": "0000"},
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN, response.data)
        self.assertEqual(response.data["localizable_error"], CHANGE_REQUIRES_CURRENT)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "owner@example.com")
        self.assertTrue(self.user.is_email_verified)

    def test_request_refuses_before_spending_a_send(self):
        """No point delivering a code that can never be applied."""
        with patch(
            "stapel_auth.otp.services.EmailVerificationService.send_verification_code"
        ) as send:
            response = self.client.post(
                reverse("email_request"), {"email": "attacker@example.com"}
            )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN, response.data)
        self.assertEqual(response.data["localizable_error"], CHANGE_REQUIRES_CURRENT)
        send.assert_not_called()

    def test_the_same_address_is_still_verifiable(self):
        """Re-proving the address already on the account changes nothing."""
        self.svc.send_verification_code("owner@example.com")
        response = self.client.post(
            reverse("email_verify"), {"email": "owner@example.com", "code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["status"], "MODIFIED")

    def test_case_and_whitespace_do_not_make_it_a_different_address(self):
        self.svc.send_verification_code("Owner@Example.com")
        response = self.client.post(
            reverse("email_verify"), {"email": "Owner@Example.com", "code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)


@override_settings(**MOCK_OTP)
class RewritingAVerifiedPhoneIsRefusedTests(APITestCase):
    def setUp(self):
        from stapel_auth.otp.services import PhoneVerificationService

        self.user = User.objects.create_user(
            username="phoneowner",
            phone="+12025551100",
            is_phone_verified=True,
        )
        self.client.force_authenticate(user=self.user)
        self.svc = PhoneVerificationService()

    def test_verify_refuses_a_different_number(self):
        """The regression test: this used to return 200 MODIFIED."""
        self.svc.send_verification_code("+13125559999")
        response = self.client.post(
            reverse("phone_verify"), {"phone": "+13125559999", "code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN, response.data)
        self.assertEqual(response.data["localizable_error"], CHANGE_REQUIRES_CURRENT)
        self.user.refresh_from_db()
        self.assertEqual(self.user.phone, "+12025551100")
        self.assertTrue(self.user.is_phone_verified)

    def test_request_refuses_before_spending_an_sms(self):
        with patch(
            "stapel_auth.otp.services.PhoneVerificationService.send_verification_code"
        ) as send:
            response = self.client.post(
                reverse("phone_request"), {"phone": "+13125559999"}
            )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN, response.data)
        self.assertEqual(response.data["localizable_error"], CHANGE_REQUIRES_CURRENT)
        send.assert_not_called()

    def test_the_same_number_is_still_verifiable(self):
        self.svc.send_verification_code("+12025551100")
        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12025551100", "code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["status"], "MODIFIED")


@override_settings(**MOCK_OTP)
class SettingAFirstAuthenticatorStillWorksTests(APITestCase):
    """The legitimate single-step case — there is no prior proof to bypass."""

    def test_a_phone_only_account_can_add_an_email(self):
        from stapel_auth.otp.services import EmailVerificationService

        user = User.objects.create_user(
            username="phoneonly", phone="+12025551200", is_phone_verified=True
        )
        self.client.force_authenticate(user=user)
        EmailVerificationService().send_verification_code("first@example.com")

        response = self.client.post(
            reverse("email_verify"), {"email": "first@example.com", "code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["status"], "MODIFIED")
        user.refresh_from_db()
        self.assertEqual(user.email, "first@example.com")
        self.assertTrue(user.is_email_verified)

    def test_an_email_only_account_can_add_a_phone(self):
        from stapel_auth.otp.services import PhoneVerificationService

        user = User.objects.create_user(
            username="emailonly", email="e@example.com", is_email_verified=True
        )
        self.client.force_authenticate(user=user)
        PhoneVerificationService().send_verification_code("+12025551201")

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12025551201", "code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        user.refresh_from_db()
        self.assertEqual(user.phone, "+12025551201")

    def test_an_unverified_address_is_not_a_proven_one(self):
        """An address the account never proved protects nothing.

        Hosts seed ``email`` from imports, admin edits and OAuth profiles
        without a verification ever happening. Freezing such a value would
        lock those users out of the only flow that can prove an address,
        with no change flow available to them either — ``request_old_otp``
        refuses an account with nothing verified to send to.
        """
        from stapel_auth.otp.services import EmailVerificationService

        user = User.objects.create_user(
            username="seeded", email="seeded@example.com", is_email_verified=False
        )
        self.client.force_authenticate(user=user)
        EmailVerificationService().send_verification_code("real@example.com")

        response = self.client.post(
            reverse("email_verify"), {"email": "real@example.com", "code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        user.refresh_from_db()
        self.assertEqual(user.email, "real@example.com")
        self.assertTrue(user.is_email_verified)


@override_settings(**MOCK_OTP)
class TheChangeFlowStillRewritesTests(APITestCase):
    """The supported route: prove the current authenticator, then swap it."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="changer",
            email="before@example.com",
            phone="+12025551300",
            is_email_verified=True,
            is_phone_verified=True,
        )
        self.client.force_authenticate(user=self.user)

    def _change_token(self, kind):
        self.client.post(reverse(f"{kind}_instant_request_old"), {})
        resp = self.client.post(
            reverse(f"{kind}_instant_verify_old"), {"code": "0000"}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.data)
        return resp.data["change_token"]

    def test_email_change_flow_end_to_end(self):
        token = self._change_token("email")
        self.client.post(
            reverse("email_instant_request_new"),
            {"email": "after@example.com", "change_token": token},
        )
        resp = self.client.post(
            reverse("email_instant_verify_new"),
            {"email": "after@example.com", "code": "0000", "change_token": token},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.data)
        self.assertEqual(resp.data["status"], "MODIFIED")
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "after@example.com")

    def test_phone_change_flow_end_to_end(self):
        token = self._change_token("phone")
        self.client.post(
            reverse("phone_instant_request_new"),
            {"phone": "+13125550099", "change_token": token},
        )
        resp = self.client.post(
            reverse("phone_instant_verify_new"),
            {"phone": "+13125550099", "code": "0000", "change_token": token},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.data)
        self.user.refresh_from_db()
        self.assertEqual(self.user.phone, "+13125550099")


@override_settings(**MOCK_OTP)
class UnauthenticatedAndGuestPathsAreUntouchedTests(APITestCase):
    """The guard only speaks for an authenticated non-anonymous session."""

    def test_login_to_an_existing_account_still_works(self):
        from stapel_auth.otp.services import EmailVerificationService

        User.objects.create_user(
            username="loginer", email="loginer@example.com", is_email_verified=True
        )
        EmailVerificationService().send_verification_code("loginer@example.com")
        response = self.client.post(
            reverse("email_verify"), {"email": "loginer@example.com", "code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["status"], "LOGGED_IN")

    def test_a_guest_still_promotes_to_a_real_account(self):
        from stapel_auth.otp.services import EmailVerificationService

        guest = User.create_anonymous_user()
        self.client.force_authenticate(user=guest)
        EmailVerificationService().send_verification_code("guest@example.com")
        response = self.client.post(
            reverse("email_verify"), {"email": "guest@example.com", "code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["status"], "REGISTERED")


class TheGuardPredicateTests(APITestCase):
    """Unit-level truth table for the shared predicate."""

    def _guard(self, **kwargs):
        from stapel_auth.otp.views import _rewrites_a_verified_authenticator

        return _rewrites_a_verified_authenticator(**kwargs)

    def test_truth_table(self):
        verified = User(email="a@example.com", is_email_verified=True)
        unverified = User(email="a@example.com", is_email_verified=False)
        empty = User(email="", is_email_verified=True)

        cases = [
            (verified, "b@example.com", True),
            (verified, "a@example.com", False),
            (verified, "A@Example.com", False),
            (unverified, "b@example.com", False),
            (empty, "b@example.com", False),
        ]
        for user, incoming, expected in cases:
            with self.subTest(email=user.email, incoming=incoming):
                self.assertEqual(
                    self._guard(
                        user=user,
                        field="email",
                        verified_flag="is_email_verified",
                        new_value=incoming,
                    ),
                    expected,
                )

    def test_phone_is_compared_exactly(self):
        user = User(phone="+12025551400", is_phone_verified=True)
        self.assertTrue(
            self._guard(
                user=user,
                field="phone",
                verified_flag="is_phone_verified",
                new_value="+12025551401",
            )
        )
        self.assertFalse(
            self._guard(
                user=user,
                field="phone",
                verified_flag="is_phone_verified",
                new_value="+12025551400",
            )
        )
