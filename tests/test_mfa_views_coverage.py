"""Coverage tests for stapel_auth.mfa.views (TOTP + Passkey viewsets).

Drives each MFA API endpoint with an authenticated JWT client, mocking the
service layer (TOTPService / PasskeyService / PhoneVerificationService) so both
success and error/400 branches of the *view* code are exercised. Service
internals are owned by test_mfa_services_coverage.py and are not touched here.
"""

import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_core.django.jwt.provider import jwt_provider

User = get_user_model()


def _make_user(**kw):
    d = dict(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )
    d.update(kw)
    return User.objects.create_user(**d)


class _AuthedMixin:
    def setUp(self):
        self.user = _make_user()
        access, _ = jwt_provider.create_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")


# =============================================================================
# TOTPViewSet
# =============================================================================


class TOTPSetupTests(_AuthedMixin, APITestCase):
    def test_setup_returns_secret_and_uri(self):
        with patch(
            "stapel_auth.mfa.services.TOTPService.setup",
            return_value={"secret": "SECRET123", "qr_uri": "otpauth://x"},
        ):
            resp = self.client.post(reverse("totp_setup"), {}, format="json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["secret"], "SECRET123")
        self.assertEqual(resp.data["qr_uri"], "otpauth://x")


class TOTPConfirmSetupTests(_AuthedMixin, APITestCase):
    def test_confirm_missing_code_returns_400(self):
        resp = self.client.post(reverse("totp_setup_confirm"), {}, format="json")
        self.assertEqual(resp.status_code, 400)

    def test_confirm_success_returns_backup_codes(self):
        with patch(
            "stapel_auth.mfa.services.TOTPService.confirm",
            return_value=["AAAA-BBBB", "CCCC-DDDD"],
        ):
            resp = self.client.post(
                reverse("totp_setup_confirm"), {"code": "123456"}, format="json"
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["backup_codes"], ["AAAA-BBBB", "CCCC-DDDD"])

    def test_confirm_invalid_code_returns_400(self):
        with patch(
            "stapel_auth.mfa.services.TOTPService.confirm",
            side_effect=ValueError("invalid_code"),
        ):
            resp = self.client.post(
                reverse("totp_setup_confirm"), {"code": "000000"}, format="json"
            )
        self.assertEqual(resp.status_code, 400)

    def test_confirm_not_pending_returns_400(self):
        with patch(
            "stapel_auth.mfa.services.TOTPService.confirm",
            side_effect=ValueError("no_pending_device"),
        ):
            resp = self.client.post(
                reverse("totp_setup_confirm"), {"code": "000000"}, format="json"
            )
        self.assertEqual(resp.status_code, 400)


class TOTPDisableRequestOtpTests(_AuthedMixin, APITestCase):
    def test_no_verified_contact_returns_400(self):
        # Fresh user has no verified phone.
        resp = self.client.post(reverse("totp_disable_otp_request"), {}, format="json")
        self.assertEqual(resp.status_code, 400)

    def test_sends_code_when_phone_verified(self):
        User.objects.filter(pk=self.user.pk).update(
            phone="+14155552671", is_phone_verified=True
        )
        with patch(
            "stapel_auth.services.PhoneVerificationService.send_verification_code"
        ) as send, patch(
            "stapel_auth.services.PasswordService.mask_phone", return_value="+1***2671"
        ):
            resp = self.client.post(
                reverse("totp_disable_otp_request"), {}, format="json"
            )
        self.assertEqual(resp.status_code, 200)
        send.assert_called_once()
        self.assertEqual(resp.data["target"], "+1***2671")


class TOTPDisableTests(_AuthedMixin, APITestCase):
    def _verify_phone(self):
        User.objects.filter(pk=self.user.pk).update(
            phone="+14155552671", is_phone_verified=True
        )

    def test_disable_totp_success(self):
        with patch(
            "stapel_auth.mfa.services.TOTPService.disable", return_value=True
        ), patch("stapel_auth.services.AuditService.log"):
            resp = self.client.post(
                reverse("totp_disable"),
                {"method": "totp", "code": "123456"},
                format="json",
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "disabled")

    def test_disable_totp_bad_code_returns_400(self):
        with patch("stapel_auth.mfa.services.TOTPService.disable", return_value=False):
            resp = self.client.post(
                reverse("totp_disable"),
                {"method": "totp", "code": "000000"},
                format="json",
            )
        self.assertEqual(resp.status_code, 400)

    def test_disable_backup_success(self):
        with patch(
            "stapel_auth.mfa.services.TOTPService.disable", return_value=True
        ), patch("stapel_auth.services.AuditService.log"):
            resp = self.client.post(
                reverse("totp_disable"),
                {"method": "backup", "backup_code": "AAAA-BBBB"},
                format="json",
            )
        self.assertEqual(resp.status_code, 200)

    def test_disable_backup_bad_code_returns_400(self):
        with patch("stapel_auth.mfa.services.TOTPService.disable", return_value=False):
            resp = self.client.post(
                reverse("totp_disable"),
                {"method": "backup", "backup_code": "ZZZZ-ZZZZ"},
                format="json",
            )
        self.assertEqual(resp.status_code, 400)

    def test_disable_otp_no_verified_contact_returns_400(self):
        resp = self.client.post(
            reverse("totp_disable"),
            {"method": "otp", "otp_code": "0000"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_disable_otp_bad_code_returns_400(self):
        self._verify_phone()
        with patch(
            "stapel_auth.services.PhoneVerificationService.verify_code",
            return_value={"success": False},
        ):
            resp = self.client.post(
                reverse("totp_disable"),
                {"method": "otp", "otp_code": "9999"},
                format="json",
            )
        self.assertEqual(resp.status_code, 400)

    def test_disable_otp_success(self):
        self._verify_phone()
        with patch(
            "stapel_auth.services.PhoneVerificationService.verify_code",
            return_value={"success": True},
        ), patch(
            "stapel_auth.mfa.services.TOTPService.force_disable", return_value=True
        ), patch("stapel_auth.services.AuditService.log"):
            resp = self.client.post(
                reverse("totp_disable"),
                {"method": "otp", "otp_code": "0000"},
                format="json",
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "disabled")

    def test_disable_unknown_method_returns_400(self):
        resp = self.client.post(
            reverse("totp_disable"), {"method": "bogus"}, format="json"
        )
        self.assertEqual(resp.status_code, 400)


class TOTPChallengeVerifyTests(APITestCase):
    """challenge_verify is unauthenticated (AllowAny)."""

    def test_missing_challenge_token_returns_400(self):
        resp = self.client.post(
            reverse("totp_challenge_verify"), {"code": "123456"}, format="json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_locked_returns_423(self):
        with patch(
            "stapel_auth.security.services.LockoutService.check",
            return_value=(True, 30),
        ):
            resp = self.client.post(
                reverse("totp_challenge_verify"),
                {"challenge_token": "tok", "code": "123456"},
                format="json",
            )
        self.assertEqual(resp.status_code, 423)

    def test_invalid_code_returns_400(self):
        with patch(
            "stapel_auth.security.services.LockoutService.check",
            return_value=(False, None),
        ), patch(
            "stapel_auth.security.services.LockoutService.record_failure",
            return_value=1,
        ), patch(
            "stapel_auth.security.services.LockoutService.apply_lockout",
            return_value=None,
        ), patch(
            "stapel_auth.mfa.services.TOTPService.resolve_challenge",
            return_value=None,
        ):
            resp = self.client.post(
                reverse("totp_challenge_verify"),
                {"challenge_token": "tok", "code": "000000"},
                format="json",
            )
        self.assertEqual(resp.status_code, 400)

    def test_success_issues_tokens(self):
        user = _make_user()
        with patch(
            "stapel_auth.security.services.LockoutService.check",
            return_value=(False, None),
        ), patch(
            "stapel_auth.security.services.LockoutService.clear"
        ), patch(
            "stapel_auth.mfa.services.TOTPService.resolve_challenge",
            return_value=user,
        ), patch(
            "stapel_auth.sessions.views._issue_session_tokens",
            return_value=("acc", "ref"),
        ):
            resp = self.client.post(
                reverse("totp_challenge_verify"),
                {"challenge_token": "tok", "code": "123456"},
                format="json",
            )
        self.assertEqual(resp.status_code, 200)


class TOTPStepUpTests(_AuthedMixin, APITestCase):
    def test_step_up_missing_code_returns_400(self):
        resp = self.client.post(reverse("totp_step_up"), {}, format="json")
        self.assertEqual(resp.status_code, 400)


# =============================================================================
# PasskeyViewSet
# =============================================================================


def _make_passkey(user, **kw):
    from stapel_auth.models import PasskeyCredential

    d = dict(
        user=user,
        credential_id=uuid.uuid4().bytes,
        public_key=b"fakepublickeybytes",
        sign_count=0,
        aaguid="00000000-0000-0000-0000-000000000000",
        device_name="Test Key",
    )
    d.update(kw)
    return PasskeyCredential.objects.create(**d)


class PasskeyListTests(_AuthedMixin, APITestCase):
    def test_list_includes_registered_passkey(self):
        pc = _make_passkey(self.user)
        resp = self.client.get(reverse("passkey_list"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data["passkeys"]), 1)
        self.assertEqual(resp.data["passkeys"][0]["id"], str(pc.id))


class PasskeyDestroyTests(_AuthedMixin, APITestCase):
    def test_destroy_success_when_password_present(self):
        # Fresh user was created with a usable password → not the last method.
        pc = _make_passkey(self.user)
        with patch("stapel_auth.services.AuditService.log"):
            resp = self.client.delete(
                reverse("passkey_destroy", kwargs={"pk": str(pc.id)})
            )
        self.assertEqual(resp.status_code, 204)
        pc.refresh_from_db()
        self.assertFalse(pc.is_active)


class PasskeyRegisterCompleteTests(_AuthedMixin, APITestCase):
    def test_invalid_credential_returns_400(self):
        with patch(
            "stapel_auth.mfa.services.PasskeyService.registration_complete",
            side_effect=ValueError("invalid"),
        ):
            resp = self.client.post(
                reverse("passkey_register_complete"),
                {"credential": {}, "device_name": "X"},
                format="json",
            )
        self.assertEqual(resp.status_code, 400)

    def test_unexpected_error_returns_400(self):
        with patch(
            "stapel_auth.mfa.services.PasskeyService.registration_complete",
            side_effect=Exception("boom"),
        ):
            resp = self.client.post(
                reverse("passkey_register_complete"),
                {"credential": {}, "device_name": "X"},
                format="json",
            )
        self.assertEqual(resp.status_code, 400)

    def test_success_returns_passkey(self):
        pc = _make_passkey(self.user, device_name="My Phone")
        with patch(
            "stapel_auth.mfa.services.PasskeyService.registration_complete",
            return_value=pc,
        ):
            resp = self.client.post(
                reverse("passkey_register_complete"),
                {"credential": {"id": "abc"}, "device_name": "My Phone"},
                format="json",
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["device_name"], "My Phone")


class PasskeyAuthBeginTests(APITestCase):
    def test_auth_begin_unknown_email_still_returns_options(self):
        with patch(
            "stapel_auth.mfa.services.PasskeyService.authentication_begin",
            return_value=("sk", {"challenge": "c"}),
        ):
            resp = self.client.post(
                reverse("passkey_auth_begin"),
                {"email": "nobody@example.com"},
                format="json",
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["session_key"], "sk")


class PasskeyAuthCompleteTests(APITestCase):
    def test_unexpected_error_returns_400(self):
        with patch(
            "stapel_auth.mfa.services.PasskeyService.authentication_complete",
            side_effect=Exception("boom"),
        ):
            resp = self.client.post(
                reverse("passkey_auth_complete"),
                {"session_key": "k", "credential": {}},
                format="json",
            )
        self.assertEqual(resp.status_code, 400)
