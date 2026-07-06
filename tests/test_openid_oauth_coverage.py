"""Coverage tests for ``stapel_auth.openid.views`` and ``stapel_auth.oauth_providers``.

Targets the JWKS RS256 branch + TokenIntrospectView (openid/views.py) and the
GitHub/Zoom email/username resolution branches plus the not-yet-implemented
providers (oauth_providers.py).
"""

import uuid
from unittest.mock import patch

from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from stapel_core.django.jwt.provider import jwt_provider


def _make_response(status_code=200, json_data=None):
    """Build a stand-in for ``requests.Response`` with the bits providers use."""
    from unittest.mock import MagicMock

    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    return resp


def _rsa_keypair():
    """Generate a throwaway RSA keypair as PEM strings for RS256 tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


# =============================================================================
# JWKS endpoint (openid/views.py :: JWKSView.jwks)
# =============================================================================

@override_settings(URL_PREFIX="")
class JWKSViewCoverageTests(APITestCase):
    """Exercise the HS256 and RS256 code paths of the JWKS endpoint."""

    def setUp(self):
        self.client = APIClient()
        # Whatever an RS256 test does to the global provider, put it back to the
        # test default (HS256) so later tests keep working.
        self.addCleanup(jwt_provider.reset)

    def test_hs256_returns_empty_keys_with_info(self):
        """Default HS256 config: no shareable key, but algorithm/issuer info."""
        response = self.client.get(reverse("jwks"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["keys"], [])
        self.assertEqual(response.data["_info"]["algorithm"], "HS256")

    def test_rs256_returns_public_key(self):
        """RS256 with a public key: JWKS emits exactly one RSA JWK."""
        private_pem, public_pem = _rsa_keypair()
        with override_settings(
            JWT_ALGORITHM="RS256",
            JWT_PRIVATE_KEY=private_pem,
            JWT_PUBLIC_KEY=public_pem,
        ):
            jwt_provider.reset()
            response = self.client.get(reverse("jwks"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["keys"]), 1)
        jwk = response.data["keys"][0]
        self.assertEqual(jwk["kty"], "RSA")
        self.assertEqual(jwk["alg"], "RS256")
        self.assertIn("n", jwk)
        self.assertIn("e", jwk)

    def test_rs256_without_public_key_returns_empty(self):
        """RS256 with only a private key -> get_jwks() None -> keys empty + error.

        JWTConfig requires at least one key for RS256, so a private-key-only
        config is the reachable way to hit the "no public key" JWKS branch.
        """
        private_pem, _ = _rsa_keypair()
        with override_settings(
            JWT_ALGORITHM="RS256",
            JWT_PRIVATE_KEY=private_pem,
            JWT_PUBLIC_KEY=None,
        ):
            jwt_provider.reset()
            response = self.client.get(reverse("jwks"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["keys"], [])
        self.assertEqual(response.data["error"], "Public key not available")

    def test_rs256_jwks_exception_returns_500(self):
        """A failure while building the JWKS surfaces as a 500 with the error."""
        private_pem, public_pem = _rsa_keypair()
        with override_settings(
            JWT_ALGORITHM="RS256",
            JWT_PRIVATE_KEY=private_pem,
            JWT_PUBLIC_KEY=public_pem,
        ):
            jwt_provider.reset()
            with patch.object(
                jwt_provider, "get_jwks", side_effect=Exception("boom")
            ):
                response = self.client.get(reverse("jwks"))

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data["keys"], [])
        self.assertEqual(response.data["error"], "boom")


# =============================================================================
# Token introspection (openid/views.py :: TokenIntrospectView.post)
# =============================================================================

@override_settings(URL_PREFIX="")
class TokenIntrospectViewCoverageTests(APITestCase):
    """RFC 7662 introspection: auth gate + active/inactive branches."""

    def setUp(self):
        from django.contrib.auth import get_user_model

        self.client = APIClient()
        self.User = get_user_model()
        self.url = reverse("oauth2_introspect")

    def _service_key(self):
        from stapel_auth.models import ServiceAPIKey

        key = ServiceAPIKey.objects.create(
            name="introspect-svc",
            key=f"svc-{uuid.uuid4().hex}",
            is_active=True,
        )
        return key.key

    def _make_user(self):
        return self.User.objects.create_user(
            email=f"{uuid.uuid4().hex[:8]}@example.com",
            username=uuid.uuid4().hex[:12],
            password="testpass123",
        )

    def test_missing_service_key_returns_401(self):
        """No X-API-Key -> 401 (never leaks token validity)."""
        response = self.client.post(self.url, {"token": "whatever"})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_empty_token_returns_inactive(self):
        """Valid service key, blank token -> {'active': False}."""
        response = self.client.post(
            self.url, {"token": "   "}, HTTP_X_API_KEY=self._service_key()
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["active"])

    def test_invalid_token_returns_inactive(self):
        """Valid service key, garbage token -> {'active': False}."""
        response = self.client.post(
            self.url,
            {"token": "not-a-real-jwt"},
            HTTP_X_API_KEY=self._service_key(),
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["active"])

    def test_valid_token_returns_active_with_claims(self):
        """Valid service key + valid JWT -> active True with subject claims."""
        user = self._make_user()
        access, _ = jwt_provider.create_tokens(user)
        response = self.client.post(
            self.url, {"token": access}, HTTP_X_API_KEY=self._service_key()
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["active"])
        self.assertEqual(response.data["sub"], str(user.pk))
        self.assertEqual(response.data["username"], user.username)
        self.assertEqual(response.data["token_type"], "access")


# =============================================================================
# GitHub provider email resolution (oauth_providers.py :: GitHubProvider)
# =============================================================================

class GitHubProviderCoverageTests(APITestCase):
    """Cover the primary/verified/fallback e-mail branches."""

    def _github(self):
        from stapel_auth.oauth_providers import GitHubProvider

        return GitHubProvider()

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_user_endpoint_failure_returns_none(self, mock_get):
        """Non-200 from /user short-circuits to None."""
        mock_get.return_value = _make_response(status_code=403)
        self.assertIsNone(self._github().get_user_data("tok"))

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_public_email_verified_via_emails_list(self, mock_get):
        """Public profile e-mail is only trusted if /user/emails lists it verified."""
        mock_get.side_effect = [
            _make_response(json_data={"id": 1, "login": "gh", "email": "pub@example.com"}),
            _make_response(
                json_data=[
                    {"email": "pub@example.com", "verified": True, "primary": True},
                    "not-a-dict",  # filtered out by the isinstance guard
                ]
            ),
        ]
        result = self._github().get_user_data("tok")
        self.assertEqual(result.email, "pub@example.com")
        self.assertTrue(result.email_verified)
        self.assertEqual(result.username, "gh")

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_emails_endpoint_non_200_leaves_unverified(self, mock_get):
        """When /user/emails is not 200, emails stays empty (branch 70->77)."""
        mock_get.side_effect = [
            _make_response(json_data={"id": 2, "login": "gh2", "email": "p@example.com"}),
            _make_response(status_code=500),
        ]
        result = self._github().get_user_data("tok")
        self.assertEqual(result.email, "p@example.com")
        self.assertFalse(result.email_verified)

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_emails_endpoint_raises_is_fail_safe(self, mock_get):
        """Exception fetching /user/emails is swallowed -> unverified (lines 74-76)."""
        mock_get.side_effect = [
            _make_response(json_data={"id": 3, "login": "gh3", "email": "e@example.com"}),
            Exception("network down"),
        ]
        result = self._github().get_user_data("tok")
        self.assertEqual(result.email, "e@example.com")
        self.assertFalse(result.email_verified)

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_emails_endpoint_non_list_body_ignored(self, mock_get):
        """A non-list /user/emails body (e.g. error dict) leaves emails empty."""
        mock_get.side_effect = [
            _make_response(json_data={"id": 6, "login": "gh6", "email": "d@example.com"}),
            _make_response(json_data={"message": "Not Found"}),
        ]
        result = self._github().get_user_data("tok")
        self.assertEqual(result.email, "d@example.com")
        self.assertFalse(result.email_verified)

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_no_public_email_and_no_emails_stays_none(self, mock_get):
        """No profile e-mail and an empty emails list -> email stays None."""
        mock_get.side_effect = [
            _make_response(json_data={"id": 7, "login": "gh7", "email": None}),
            _make_response(json_data=[]),
        ]
        result = self._github().get_user_data("tok")
        self.assertIsNone(result.email)
        self.assertFalse(result.email_verified)

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_no_public_email_uses_primary_verified(self, mock_get):
        """No profile e-mail -> take the primary verified address (lines 83-87)."""
        mock_get.side_effect = [
            _make_response(json_data={"id": 4, "login": "gh4", "email": None}),
            _make_response(
                json_data=[
                    {"email": "secondary@example.com", "verified": False, "primary": False},
                    {"email": "primary@example.com", "verified": True, "primary": True},
                ]
            ),
        ]
        result = self._github().get_user_data("tok")
        self.assertEqual(result.email, "primary@example.com")
        self.assertTrue(result.email_verified)

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_no_public_email_falls_back_to_first(self, mock_get):
        """No profile e-mail and no primary+verified -> first listed (lines 88-89)."""
        mock_get.side_effect = [
            _make_response(json_data={"id": 5, "login": "gh5", "email": None}),
            _make_response(
                json_data=[
                    {"email": "first@example.com", "verified": False, "primary": False},
                ]
            ),
        ]
        result = self._github().get_user_data("tok")
        self.assertEqual(result.email, "first@example.com")
        self.assertFalse(result.email_verified)


# =============================================================================
# Zoom provider username construction (oauth_providers.py :: ZoomProvider)
# =============================================================================

class ZoomProviderCoverageTests(APITestCase):
    def _zoom(self):
        from stapel_auth.oauth_providers import ZoomProvider

        return ZoomProvider()

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_non_200_returns_none(self, mock_get):
        mock_get.return_value = _make_response(status_code=401)
        self.assertIsNone(self._zoom().get_user_data("tok"))

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_username_from_first_and_last(self, mock_get):
        mock_get.return_value = _make_response(
            json_data={
                "id": "z1",
                "first_name": "Jane",
                "last_name": "Doe",
                "email": "jane@example.com",
                "pic_url": "https://pic",
            }
        )
        result = self._zoom().get_user_data("tok")
        self.assertEqual(result.id, "z1")
        self.assertEqual(result.username, "jane_doe")
        self.assertEqual(result.email, "jane@example.com")

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_username_falls_back_to_id_when_no_names(self, mock_get):
        mock_get.return_value = _make_response(
            json_data={"id": "z2", "first_name": "", "last_name": "", "email": "x@example.com"}
        )
        result = self._zoom().get_user_data("tok")
        self.assertEqual(result.username, "z2")


# =============================================================================
# Not-yet-implemented providers (oauth_providers.py)
# =============================================================================

class UnimplementedProviderTests(APITestCase):
    def test_providers_raise_not_implemented(self):
        from stapel_auth.oauth_providers import (
            AppleProvider,
            SberProvider,
            TwitterProvider,
            VKProvider,
            YandexProvider,
        )

        for provider_cls in (
            AppleProvider,
            TwitterProvider,
            YandexProvider,
            VKProvider,
            SberProvider,
        ):
            with self.assertRaises(NotImplementedError):
                provider_cls().get_user_data("tok")


# =============================================================================
# TestProvider + get_enabled_providers (oauth_providers.py)
# =============================================================================

class TestProviderAndRegistryTests(APITestCase):
    def test_test_provider_bad_token_returns_none(self):
        from stapel_auth.oauth_providers import TestProvider

        self.assertIsNone(TestProvider().get_user_data("wrong-token"))

    def test_test_provider_ok_token_returns_fixed_user(self):
        from stapel_auth.oauth_providers import TestProvider

        result = TestProvider().get_user_data(TestProvider.TOKEN_OK)
        self.assertEqual(result.id, "test-oauth-user-1")

    def test_get_enabled_providers_empty_without_credentials(self):
        from stapel_auth.oauth_providers import get_enabled_providers

        self.assertEqual(get_enabled_providers(), [])

    @override_settings(
        STAPEL_AUTH={
            "OAUTH_PROVIDERS": {
                "github": {"client_id": "gid", "client_secret": "gsecret"},
            }
        }
    )
    def test_get_enabled_providers_returns_configured(self):
        from stapel_auth.conf import auth_settings
        from stapel_auth.oauth_providers import get_enabled_providers

        auth_settings.reload()
        try:
            providers = get_enabled_providers()
            self.assertEqual([p.id for p in providers], ["github"])
        finally:
            auth_settings.reload()
