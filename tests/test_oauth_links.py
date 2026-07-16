"""Tests for OAuth account links (security-profile inventory):
GET/POST /oauth/links/, DELETE /oauth/links/{provider}/ (oauth/views.py,
oauth/services.py::OAuthLinkService, models.LinkedOAuthAccount).
"""
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_auth.models import LinkedOAuthAccount
from stapel_auth.oauth_providers import OAuthUserData

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


@override_settings(URL_PREFIX="")
class OAuthLinksListTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        _auth(self.client, self.user)

    def test_requires_auth(self):
        self.client.credentials()
        resp = self.client.get(reverse("oauth_links"))
        self.assertEqual(resp.status_code, 401)

    def test_empty_when_no_links(self):
        resp = self.client.get(reverse("oauth_links"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["links"], [])

    def test_primary_provider_listed_first(self):
        self.user.oauth_provider = "google"
        self.user.oauth_id = "g-123"
        self.user.save(update_fields=["oauth_provider", "oauth_id"])
        LinkedOAuthAccount.objects.create(
            user=self.user, provider="github", provider_user_id="gh-1"
        )
        resp = self.client.get(reverse("oauth_links"))
        self.assertEqual(resp.status_code, 200)
        providers = [link["provider"] for link in resp.data["links"]]
        self.assertEqual(providers, ["google", "github"])
        self.assertTrue(resp.data["links"][0]["primary"])
        self.assertFalse(resp.data["links"][1]["primary"])


@override_settings(URL_PREFIX="")
class OAuthLinksLinkTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        _auth(self.client, self.user)

    def test_requires_auth(self):
        self.client.credentials()
        resp = self.client.post(reverse("oauth_links"), {"provider": "google", "access_token": "tok"})
        self.assertEqual(resp.status_code, 401)

    @patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_link_success(self, mock_get_user_data):
        mock_get_user_data.return_value = OAuthUserData(
            id="g-1", email="linked@example.com", username="linked_user",
            avatar=None, email_verified=True,
        )
        resp = self.client.post(reverse("oauth_links"), {"provider": "google", "access_token": "tok"})
        self.assertEqual(resp.status_code, 200)
        providers = [link["provider"] for link in resp.data["links"]]
        self.assertIn("google", providers)
        self.assertTrue(
            LinkedOAuthAccount.objects.filter(user=self.user, provider="google").exists()
        )

    @patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_link_failed_token(self, mock_get_user_data):
        mock_get_user_data.return_value = None
        resp = self.client.post(reverse("oauth_links"), {"provider": "google", "access_token": "bad"})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data["localizable_error"], "error.400.oauth_failed")

    def test_link_already_linked_as_primary(self):
        self.user.oauth_provider = "google"
        self.user.oauth_id = "g-123"
        self.user.save(update_fields=["oauth_provider", "oauth_id"])
        resp = self.client.post(reverse("oauth_links"), {"provider": "google", "access_token": "tok"})
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.data["localizable_error"], "error.409.oauth_already_linked")

    def test_link_already_linked_as_secondary(self):
        LinkedOAuthAccount.objects.create(
            user=self.user, provider="google", provider_user_id="g-1"
        )
        resp = self.client.post(reverse("oauth_links"), {"provider": "google", "access_token": "tok"})
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.data["localizable_error"], "error.409.oauth_already_linked")

    @patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_link_conflicts_with_another_users_primary(self, mock_get_user_data):
        _make_user(oauth_provider="google", oauth_id="g-1")
        mock_get_user_data.return_value = OAuthUserData(
            id="g-1", email="x@example.com", username="x",
            avatar=None, email_verified=True,
        )
        resp = self.client.post(reverse("oauth_links"), {"provider": "google", "access_token": "tok"})
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.data["localizable_error"], "error.409.oauth_account_linked_elsewhere")

    @patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_link_conflicts_with_another_users_secondary(self, mock_get_user_data):
        other = _make_user()
        LinkedOAuthAccount.objects.create(
            user=other, provider="google", provider_user_id="g-1"
        )
        mock_get_user_data.return_value = OAuthUserData(
            id="g-1", email="x@example.com", username="x",
            avatar=None, email_verified=True,
        )
        resp = self.client.post(reverse("oauth_links"), {"provider": "google", "access_token": "tok"})
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.data["localizable_error"], "error.409.oauth_account_linked_elsewhere")


@override_settings(URL_PREFIX="")
class OAuthLinksUnlinkTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        _auth(self.client, self.user)

    def test_requires_auth(self):
        self.client.credentials()
        resp = self.client.delete(reverse("oauth_link_unlink", args=["google"]))
        self.assertEqual(resp.status_code, 401)

    def test_unlink_not_found(self):
        resp = self.client.delete(reverse("oauth_link_unlink", args=["google"]))
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.data["localizable_error"], "error.404.oauth_link_not_found")

    def test_unlink_success_with_password_remaining(self):
        LinkedOAuthAccount.objects.create(
            user=self.user, provider="google", provider_user_id="g-1"
        )
        resp = self.client.delete(reverse("oauth_link_unlink", args=["google"]))
        self.assertEqual(resp.status_code, 204)
        self.assertFalse(
            LinkedOAuthAccount.objects.filter(user=self.user, provider="google").exists()
        )

    def test_unlink_last_auth_method_blocked(self):
        user = User.objects.create(
            email=f"{uuid.uuid4().hex[:8]}@example.com",
            username=uuid.uuid4().hex[:12],
        )
        user.set_unusable_password()
        user.save()
        _auth(self.client, user)
        LinkedOAuthAccount.objects.create(
            user=user, provider="google", provider_user_id="g-1"
        )
        resp = self.client.delete(reverse("oauth_link_unlink", args=["google"]))
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data["localizable_error"], "error.400.last_auth_method")
        self.assertTrue(
            LinkedOAuthAccount.objects.filter(user=user, provider="google").exists()
        )

    def test_unlink_last_auth_method_allowed_with_other_link(self):
        user = User.objects.create(
            email=f"{uuid.uuid4().hex[:8]}@example.com",
            username=uuid.uuid4().hex[:12],
        )
        user.set_unusable_password()
        user.save()
        _auth(self.client, user)
        LinkedOAuthAccount.objects.create(
            user=user, provider="google", provider_user_id="g-1"
        )
        LinkedOAuthAccount.objects.create(
            user=user, provider="github", provider_user_id="gh-1"
        )
        resp = self.client.delete(reverse("oauth_link_unlink", args=["google"]))
        self.assertEqual(resp.status_code, 204)

    def test_unlink_only_removes_secondary_not_primary(self):
        self.user.oauth_provider = "google"
        self.user.oauth_id = "g-123"
        self.user.save(update_fields=["oauth_provider", "oauth_id"])
        resp = self.client.delete(reverse("oauth_link_unlink", args=["google"]))
        # No secondary LinkedOAuthAccount row for google -> not_found, primary untouched.
        self.assertEqual(resp.status_code, 404)
        self.user.refresh_from_db()
        self.assertEqual(self.user.oauth_provider, "google")
