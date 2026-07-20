"""Anon-promotion / orphan-fix tests (THE IDENTITY MODEL owner directive).

Covers:
- `otp.services.promote_anonymous_session` — the extracted primitive.
- The promote primitive fires on every anchor-establishing path when
  `request.user.is_anonymous`: email/phone verify (regression-covered by the
  existing `test_auth.py` anonymous-registers tests — untouched here),
  the password module's OTP-verify-contact path (bug a), oauth (bug b),
  sso (bug b).
- Credential-only paths (password set/change, no anchor) do NOT promote —
  the account stays anonymous but is portable.
- The orphan fix: an anonymous `request.user` establishing a fresh anchor
  reuses the SAME row instead of creating (and abandoning) a new one.
- `/capabilities/` methods[] carry per-method `can_login`/`can_register`.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from stapel_auth.models import Organization
from stapel_auth.oauth_providers import OAuthUserData
from stapel_auth.otp.services import promote_anonymous_session
from stapel_auth.sso_service import SSOUserService

User = get_user_model()


def _bearer_client_for(user) -> APIClient:
    from stapel_core.django.jwt.provider import jwt_provider

    access, _ = jwt_provider.create_tokens(user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client


# ── The primitive itself ─────────────────────────────────────────────────────


class PromoteAnonymousSessionUnitTests(TestCase):
    def test_flips_anonymous_and_upgrades_username(self):
        user = User.create_anonymous_user()
        self.assertTrue(user.username.startswith("anon_"))
        promote_anonymous_session(user, auth_type="email")
        self.assertFalse(user.is_anonymous)
        self.assertEqual(user.auth_type, "email")
        self.assertTrue(user.username.startswith("user_"))

    def test_does_not_save(self):
        user = User.create_anonymous_user()
        promote_anonymous_session(user, auth_type="phone")
        user.refresh_from_db()
        # Nothing persisted — the caller is responsible for the single save.
        self.assertTrue(user.is_anonymous)


# ── Password-module OTP-verify-contact path (bug a) ─────────────────────────


class PasswordOtpVerifyAnonPromoteTests(APITestCase):
    """Defensive fix: change_via_otp promotes IF it ever runs on a still-
    anonymous user with an already-verified contact (normally unreachable —
    is_email_verified/is_phone_verified being True already implies
    is_anonymous False in every real path — but the primitive is applied
    defensively per the owner directive)."""

    def setUp(self):
        self.user = User.create_anonymous_user()
        self.user.email = "guest@example.com"
        self.user.is_email_verified = True
        self.user.save()
        self.client = _bearer_client_for(self.user)

    @patch("stapel_auth.otp.services.EmailVerificationService.verify_code")
    def test_promotes_and_returns_auth_response(self, mock_verify):
        mock_verify.return_value = {"success": True}
        response = self.client.post(
            reverse("password_change_otp_verify"),
            {"method": "email", "code": "1234", "new_password": "brandnew456!"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # AuthResponse carries `user` (unlike the ordinary SimpleStatusResponse
        # path) so the client's session.adopt() sees the flip.
        self.assertIn("user", response.data)
        self.assertEqual(response.data["status"], "REGISTERED")
        self.assertFalse(response.data["user"]["is_anonymous"])
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_anonymous)
        self.assertEqual(self.user.auth_type, "email")
        self.assertTrue(self.user.check_password("brandnew456!"))

    @patch("stapel_auth.otp.services.EmailVerificationService.verify_code")
    def test_not_anonymous_still_returns_plain_status(self, mock_verify):
        """Regression guard: an ordinary (non-anonymous) caller is unaffected —
        still the bare SimpleStatusResponse, no promotion, no `user` key.
        A FRESH (never-anonymous) user + freshly minted token — the JWT
        auth backend syncs is_anonymous/auth_type FROM the token's own
        claims on every request (stapel-core's `_get_or_create_user_from_jwt`),
        so reusing `self.user`'s anon-minted token after mutating the DB row
        would just have the claim resync it back; a separate user/token
        sidesteps that entirely rather than fighting it."""
        registered = User.objects.create_user(
            username="alreadyregistered",
            email="already@example.com",
            phone="+79991234567",
            is_email_verified=True,
            is_phone_verified=True,
        )
        client = _bearer_client_for(registered)
        mock_verify.return_value = {"success": True}
        response = client.post(
            reverse("password_change_otp_verify"),
            {"method": "email", "code": "1234", "new_password": "brandnew456!"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("status"), "password_changed")
        self.assertNotIn("user", response.data)


# ── Credential-only paths never promote ──────────────────────────────────────


class PasswordSetDoesNotPromoteTests(APITestCase):
    def test_change_direct_does_not_promote_anonymous_user(self):
        user = User.create_anonymous_user()
        user.set_password("oldpass123!")
        user.save()
        client = _bearer_client_for(user)
        response = client.post(
            reverse("password_change"),
            {"old_password": "oldpass123!", "new_password": "newpass456!"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertTrue(user.is_anonymous)
        # Portable: the SAME guest account can now be signed into elsewhere.
        self.assertTrue(user.check_password("newpass456!"))

    @override_settings(STAPEL_AUTH={"AUTH_PASSWORD_REGISTRATION": True})
    def test_register_password_only_stays_anonymous_reuses_row(self):
        """register() with a password + arbitrary username (no email/phone —
        no anchor; the endpoint requires at least one of the three) on an
        anonymous session must not promote, and must not orphan: same row,
        now just portable (THE IDENTITY MODEL)."""
        anon = User.create_anonymous_user()
        client = _bearer_client_for(anon)
        before_count = User.objects.count()
        response = client.post(
            reverse("password_register"),
            {"password": "brandnew456!", "username": "portable_anon_1"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "MODIFIED")
        self.assertEqual(response.data["user"]["id"], str(anon.id))
        self.assertEqual(User.objects.count(), before_count)  # no orphan row
        anon.refresh_from_db()
        self.assertTrue(anon.is_anonymous)
        self.assertTrue(anon.check_password("brandnew456!"))

    @override_settings(
        STAPEL_AUTH={
            "AUTH_PASSWORD_REGISTRATION": True,
            "AUTH_PASSWORD_DEANONYMIZES": True,
        }
    )
    def test_register_password_only_promotes_when_deanonymizes_optin(self):
        """Opt-in (THE IDENTITY MODEL knob): a deployment running classic
        login/password accounts sets AUTH_PASSWORD_DEANONYMIZES=True, and then
        a password-only register() on an anonymous session PROMOTES the same
        row (auth_type="password", REGISTERED) instead of staying a portable
        guest — the mirror of the default test above."""
        anon = User.create_anonymous_user()
        client = _bearer_client_for(anon)
        before_count = User.objects.count()
        response = client.post(
            reverse("password_register"),
            {"password": "brandnew456!", "username": "classic_user_1"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "REGISTERED")
        self.assertEqual(response.data["user"]["id"], str(anon.id))
        self.assertFalse(response.data["user"]["is_anonymous"])
        self.assertEqual(User.objects.count(), before_count)  # no orphan row
        anon.refresh_from_db()
        self.assertFalse(anon.is_anonymous)
        self.assertEqual(anon.auth_type, "password")
        self.assertTrue(anon.check_password("brandnew456!"))

    @override_settings(STAPEL_AUTH={"AUTH_PASSWORD_REGISTRATION": True})
    def test_register_with_email_on_anonymous_session_promotes_same_row(self):
        anon = User.create_anonymous_user()
        client = _bearer_client_for(anon)
        before_count = User.objects.count()
        response = client.post(
            reverse("password_register"),
            {"email": "fresh@example.com", "password": "brandnew456!"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "REGISTERED")
        self.assertEqual(response.data["user"]["id"], str(anon.id))
        self.assertEqual(User.objects.count(), before_count)  # no orphan row
        anon.refresh_from_db()
        self.assertFalse(anon.is_anonymous)
        self.assertEqual(anon.email, "fresh@example.com")
        self.assertEqual(anon.auth_type, "email")


# ── OAuth orphan fix (bug b) ──────────────────────────────────────────────────


class OAuthAnonPromoteTests(APITestCase):
    @patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_fresh_oauth_identity_promotes_same_row_no_orphan(self, mock_get_user_data):
        anon = User.create_anonymous_user()
        client = _bearer_client_for(anon)
        mock_get_user_data.return_value = OAuthUserData(
            id="provider-uid-1",
            email="oauthguest@example.com",
            username="oauthguest",
            avatar=None,
            email_verified=True,
        )
        before_count = User.objects.count()
        response = client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "tok"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["user"]["id"], str(anon.id))
        self.assertEqual(User.objects.count(), before_count)  # no orphan row
        anon.refresh_from_db()
        self.assertFalse(anon.is_anonymous)
        self.assertEqual(anon.auth_type, "oauth")
        self.assertEqual(anon.oauth_provider, "google")
        self.assertEqual(anon.email, "oauthguest@example.com")

    @patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_collision_with_existing_account_ignores_anon_request_user(
        self, mock_get_user_data
    ):
        """Pre-existing collision handling is left exactly as it was — the
        anon guest row is simply not touched (a genuine merge is a
        follow-up, not built here)."""
        existing = User.objects.create_user(
            username="existingoauth", email="claimed@example.com", password="x"
        )
        anon = User.create_anonymous_user()
        client = _bearer_client_for(anon)
        mock_get_user_data.return_value = OAuthUserData(
            id="provider-uid-2",
            email="claimed@example.com",
            username="claimed",
            avatar=None,
            email_verified=True,
        )
        response = client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "tok"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["user"]["id"], str(existing.id))
        anon.refresh_from_db()
        self.assertTrue(anon.is_anonymous)  # untouched, not deleted


# ── SSO orphan fix (bug b) ────────────────────────────────────────────────────


class SsoAnonPromoteTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            name="Acme Corp", slug="acmecorp", domain="acmecorp.com"
        )

    def test_fresh_email_on_anon_request_user_promotes_same_row(self):
        anon = User.create_anonymous_user()
        before_count = User.objects.count()
        attrs = {
            "email": "ssoguest@acmecorp.com",
            "first_name": "SSO",
            "last_name": "Guest",
            "subject_id": "sub-1",
        }
        user, created = SSOUserService.get_or_create_user(
            self.org, attrs, request_user=anon
        )
        self.assertTrue(created)
        self.assertEqual(user.pk, anon.pk)
        self.assertEqual(User.objects.count(), before_count)  # no orphan row
        self.assertFalse(user.is_anonymous)
        self.assertEqual(user.auth_type, "sso")
        self.assertEqual(user.email, "ssoguest@acmecorp.com")

    def test_collision_with_existing_account_ignores_anon_request_user(self):
        existing = User.objects.create_user(
            email="claimed@acmecorp.com", username="claimedsso", password="x"
        )
        anon = User.create_anonymous_user()
        attrs = {
            "email": "claimed@acmecorp.com",
            "first_name": "",
            "last_name": "",
            "subject_id": "sub-2",
        }
        user, created = SSOUserService.get_or_create_user(
            self.org, attrs, request_user=anon
        )
        self.assertFalse(created)
        self.assertEqual(user.pk, existing.pk)
        anon.refresh_from_db()
        self.assertTrue(anon.is_anonymous)  # untouched, not deleted

    def test_no_request_user_behaves_as_before(self):
        attrs = {
            "email": "plain@acmecorp.com",
            "first_name": "",
            "last_name": "",
            "subject_id": "sub-3",
        }
        user, created = SSOUserService.get_or_create_user(self.org, attrs)
        self.assertTrue(created)
        self.assertFalse(user.is_anonymous)


# ── Per-method capability shape ──────────────────────────────────────────────


@override_settings(URL_PREFIX="")
class MethodCapabilityShapeTests(APITestCase):
    def test_methods_carry_can_login_and_can_register(self):
        response = self.client.get(reverse("capabilities"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        methods = {m["id"]: m for m in response.data["methods"]}
        for method_id in (
            "email", "phone", "password", "passkey", "qr", "magic_link", "sso", "oauth",
        ):
            self.assertIn(method_id, methods)
            self.assertIn("can_login", methods[method_id])
            self.assertIn("can_register", methods[method_id])

    def test_passkey_qr_magic_link_never_register(self):
        response = self.client.get(reverse("capabilities"))
        methods = {m["id"]: m for m in response.data["methods"]}
        self.assertFalse(methods["passkey"]["can_register"])
        self.assertFalse(methods["qr"]["can_register"])
        self.assertFalse(methods["magic_link"]["can_register"])

    def test_can_login_mirrors_enabled(self):
        response = self.client.get(reverse("capabilities"))
        for m in response.data["methods"]:
            self.assertEqual(m["can_login"], m["enabled"])

    @override_settings(STAPEL_AUTH={"AUTH_PASSWORD_REGISTRATION": True})
    def test_password_can_register_reflects_setting(self):
        response = self.client.get(reverse("capabilities"))
        methods = {m["id"]: m for m in response.data["methods"]}
        self.assertTrue(methods["password"]["can_register"])
