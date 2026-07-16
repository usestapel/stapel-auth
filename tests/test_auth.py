"""
Tests for authentication service.
Covers JWT token claims (is_staff, is_superuser) across all auth methods.
Also covers JWKS and OpenID Configuration endpoints.
Also covers authenticator change flows (instant + delayed).
"""

import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from stapel_auth.models import (
    AuthenticatorChangeRequest,
    AuthenticatorChangeStatus,
    EmailVerification,
    PhoneVerification,
)
from stapel_auth.oauth_providers import OAuthUserData
from stapel_auth.services import TokenService

User = get_user_model()


def decode_token_for_test(token: str) -> dict:
    """
    Decode JWT token for testing (without verification).
    Uses jwt_provider to ensure consistent decoding.
    """
    from stapel_core.django.jwt.provider import jwt_provider

    return jwt_provider.handler.decode_token(token, verify=False)


def create_token_for_user(user) -> tuple:
    """
    Create access and refresh tokens for user using jwt_provider.
    Returns (access_token, refresh_token).
    """
    from stapel_core.django.jwt.provider import jwt_provider

    return jwt_provider.create_tokens(user)


class JWTTokenClaimsTests(TestCase):
    """Test JWT token contains all required claims including is_staff and is_superuser"""

    def setUp(self):
        self.regular_user = User.objects.create_user(
            email="regular@example.com",
            username="regular",
            password="testpass123",
            is_staff=False,
            is_superuser=False,
        )
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            username="staff",
            password="testpass123",
            is_staff=True,
            is_superuser=False,
        )
        self.superuser = User.objects.create_user(
            email="super@example.com",
            username="super",
            password="testpass123",
            is_staff=True,
            is_superuser=True,
        )

    def test_token_contains_is_staff_false_for_regular_user(self):
        """Regular user token should have is_staff=False"""
        access, _ = create_token_for_user(self.regular_user)
        payload = decode_token_for_test(access)
        self.assertIn("is_staff", payload)
        self.assertFalse(payload["is_staff"])

    def test_token_contains_is_superuser_false_for_regular_user(self):
        """Regular user token should have is_superuser=False"""
        access, _ = create_token_for_user(self.regular_user)
        payload = decode_token_for_test(access)
        self.assertIn("is_superuser", payload)
        self.assertFalse(payload["is_superuser"])

    def test_token_contains_is_staff_true_for_staff_user(self):
        """Staff user token should have is_staff=True"""
        access, _ = create_token_for_user(self.staff_user)
        payload = decode_token_for_test(access)
        self.assertIn("is_staff", payload)
        self.assertTrue(payload["is_staff"])

    def test_token_contains_is_superuser_false_for_staff_user(self):
        """Staff user token should have is_superuser=False"""
        access, _ = create_token_for_user(self.staff_user)
        payload = decode_token_for_test(access)
        self.assertIn("is_superuser", payload)
        self.assertFalse(payload["is_superuser"])

    def test_token_contains_is_staff_true_for_superuser(self):
        """Superuser token should have is_staff=True"""
        access, _ = create_token_for_user(self.superuser)
        payload = decode_token_for_test(access)
        self.assertIn("is_staff", payload)
        self.assertTrue(payload["is_staff"])

    def test_token_contains_is_superuser_true_for_superuser(self):
        """Superuser token should have is_superuser=True"""
        access, _ = create_token_for_user(self.superuser)
        payload = decode_token_for_test(access)
        self.assertIn("is_superuser", payload)
        self.assertTrue(payload["is_superuser"])

    def test_token_contains_all_required_claims(self):
        """Token should contain all required claims"""
        access, _ = create_token_for_user(self.regular_user)
        payload = decode_token_for_test(access)
        required_claims = ["user_id", "username", "email", "is_staff", "is_superuser"]
        for claim in required_claims:
            self.assertIn(claim, payload, f"Missing claim: {claim}")

    def test_token_service_creates_tokens_with_claims(self):
        """TokenService.create_tokens_for_user should create tokens with all claims"""
        tokens = TokenService.create_tokens_for_user(self.staff_user)

        self.assertIn("access", tokens)
        self.assertIn("refresh", tokens)

        # Decode access token using jwt_provider
        decoded = decode_token_for_test(tokens["access"])

        self.assertTrue(decoded["is_staff"])
        self.assertFalse(decoded["is_superuser"])

    def test_token_service_get_refresh_token_contains_claims(self):
        """TokenService.get_refresh_token_for_user should create token with all claims"""
        from stapel_core.django.jwt.provider import jwt_provider

        token_pair = TokenService.get_refresh_token_for_user(self.superuser)
        refresh_token = str(token_pair)

        # Decode token to check claims (without verification for testing)
        payload = jwt_provider.handler.decode_token(refresh_token, verify=False)

        self.assertIn("is_staff", payload)
        self.assertIn("is_superuser", payload)
        self.assertTrue(payload["is_staff"])
        self.assertTrue(payload["is_superuser"])


@override_settings(URL_PREFIX="")
class EmailAuthenticationTests(APITestCase):
    """Test email OTP authentication flow"""

    def setUp(self):
        self.client = APIClient()
        self.existing_user = User.objects.create_user(
            email="existing@example.com",
            username="existing",
            password="testpass123",
            is_email_verified=True,
            auth_type="email",
        )

    @patch("stapel_auth.services.EmailVerificationService.send_verification_code")
    def test_email_request_otp_success(self, mock_send):
        """Request OTP for email should succeed"""
        mock_send.return_value = True

        response = self.client.post(
            reverse("email_request"), {"email": "new@example.com"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_email_verify_new_user_returns_registered(self, mock_verify):
        """Verifying OTP for new email should return REGISTERED status"""
        mock_verify.return_value = {"success": True}

        response = self.client.post(
            reverse("email_verify"), {"email": "newuser@example.com", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "REGISTERED")
        self.assertIn("tokens", response.data)
        self.assertIn("access", response.data["tokens"])
        self.assertIn("refresh", response.data["tokens"])

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_email_verify_existing_user_returns_logged_in(self, mock_verify):
        """Verifying OTP for existing user should return LOGGED_IN status"""
        mock_verify.return_value = {"success": True}

        response = self.client.post(
            reverse("email_verify"), {"email": "existing@example.com", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "LOGGED_IN")

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_email_verify_returns_token_with_admin_claims(self, mock_verify):
        """Email verify should return token with is_staff and is_superuser claims"""
        mock_verify.return_value = {"success": True}

        # Make existing user a staff member
        self.existing_user.is_staff = True
        self.existing_user.save()

        response = self.client.post(
            reverse("email_verify"), {"email": "existing@example.com", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Decode token and check claims
        decoded = decode_token_for_test(response.data["tokens"]["access"])

        self.assertIn("is_staff", decoded)
        self.assertIn("is_superuser", decoded)
        self.assertTrue(decoded["is_staff"])


@override_settings(URL_PREFIX="")
class PhoneAuthenticationTests(APITestCase):
    """Test phone OTP authentication flow"""

    def setUp(self):
        self.client = APIClient()
        self.existing_user = User.objects.create_user(
            phone="+12025551234",
            username="phoneuser",
            password="testpass123",
            is_phone_verified=True,
            auth_type="phone",
        )

    @patch("stapel_auth.services.PhoneVerificationService.verify_code")
    def test_phone_verify_new_user_returns_registered(self, mock_verify):
        """Verifying OTP for new phone should return REGISTERED status"""
        mock_verify.return_value = {"success": True}

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12025559876", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "REGISTERED")
        self.assertIn("tokens", response.data)

    @patch("stapel_auth.services.PhoneVerificationService.verify_code")
    def test_phone_verify_existing_user_returns_logged_in(self, mock_verify):
        """Verifying OTP for existing phone user should return LOGGED_IN status"""
        mock_verify.return_value = {"success": True}

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12025551234", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "LOGGED_IN")

    @patch("stapel_auth.services.PhoneVerificationService.verify_code")
    def test_phone_verify_returns_token_with_admin_claims(self, mock_verify):
        """Phone verify should return token with is_staff and is_superuser claims"""
        mock_verify.return_value = {"success": True}

        # Make existing user a superuser
        self.existing_user.is_staff = True
        self.existing_user.is_superuser = True
        self.existing_user.save()

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12025551234", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Decode token and check claims
        decoded = decode_token_for_test(response.data["tokens"]["access"])

        self.assertTrue(decoded["is_staff"])
        self.assertTrue(decoded["is_superuser"])


@override_settings(
    URL_PREFIX="", AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend"]
)
class TokenObtainPairAPITests(APITestCase):
    """Test standard username/password token obtain via API"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="user@example.com",
            username="testuser",
            password="testpass123",
            is_staff=True,
            is_superuser=False,
        )

    def test_token_obtain_returns_tokens_with_claims(self):
        """Token obtain should return tokens with all claims"""
        response = self.client.post(
            reverse("token_obtain_pair"),
            {"email": "user@example.com", "password": "testpass123"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

        # Decode token and check claims
        decoded = decode_token_for_test(response.data["access"])

        self.assertTrue(decoded["is_staff"])
        self.assertFalse(decoded["is_superuser"])


@override_settings(URL_PREFIX="")
class OAuthAuthenticationTests(APITestCase):
    """Test OAuth authentication flow"""

    def setUp(self):
        self.client = APIClient()

    @patch("stapel_auth.services.OAuthService.get_user_data")
    def test_oauth_google_returns_token_with_claims(self, mock_get_user_data):
        """OAuth Google auth should return token with admin claims"""
        mock_get_user_data.return_value = OAuthUserData(
            id="google-oauth-id-123",
            email="oauth@example.com",
            username="OAuth User",
            avatar="https://example.com/avatar.jpg",
        )

        response = self.client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "fake-google-token"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("tokens", response.data)

        # New OAuth user should have is_staff=False, is_superuser=False
        decoded = decode_token_for_test(response.data["tokens"]["access"])

        self.assertIn("is_staff", decoded)
        self.assertIn("is_superuser", decoded)
        self.assertFalse(decoded["is_staff"])
        self.assertFalse(decoded["is_superuser"])

    @patch("stapel_auth.services.OAuthService.get_user_data")
    def test_oauth_long_avatar_url_does_not_crash(self, mock_get_user_data):
        """Regression: a provider avatar URL longer than the old varchar(200)
        must not 500 the OAuth signup (StringDataRightTruncation in prod)."""
        long_avatar = "https://lh3.googleusercontent.com/a/" + "x" * 250 + "=s96-c"
        self.assertGreater(len(long_avatar), 200)
        mock_get_user_data.return_value = OAuthUserData(
            id="google-oauth-longavatar",
            email="longavatar@example.com",
            username="Long Avatar",
            avatar=long_avatar,
        )
        response = self.client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "fake-google-token"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(email="longavatar@example.com")
        # Fits in the widened field (<=500) → stored as-is.
        self.assertEqual(user.avatar, long_avatar)

    @patch("stapel_auth.services.OAuthService.get_user_data")
    def test_oauth_pathological_avatar_url_dropped(self, mock_get_user_data):
        """An avatar URL exceeding even the widened field degrades to no-avatar,
        never a crash."""
        huge = "https://x.example/" + "y" * 600
        self.assertGreater(len(huge), 500)
        mock_get_user_data.return_value = OAuthUserData(
            id="google-oauth-hugeavatar",
            email="hugeavatar@example.com",
            username="Huge Avatar",
            avatar=huge,
        )
        response = self.client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "fake-google-token"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(email="hugeavatar@example.com")
        self.assertIsNone(user.avatar)

    @patch("stapel_auth.services.OAuthService.get_user_data")
    def test_oauth_existing_staff_user_preserves_permissions(self, mock_get_user_data):
        """OAuth for existing staff user should preserve is_staff=True"""
        # Create existing staff user
        User.objects.create_user(
            email="staffoauth@example.com",
            username="staffoauth",
            password="testpass123",
            is_staff=True,
            is_superuser=False,
            oauth_provider="google",
            oauth_id="google-staff-id",
        )

        mock_get_user_data.return_value = OAuthUserData(
            id="google-staff-id",
            email="staffoauth@example.com",
            username="Staff OAuth User",
            avatar=None,
        )

        response = self.client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "fake-google-token"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        decoded = decode_token_for_test(response.data["tokens"]["access"])

        self.assertTrue(decoded["is_staff"])


class TokenObtainPairTests(TestCase):
    """Test standard token obtain returns correct claims"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="user@example.com",
            username="testuser",
            password="testpass123",
            is_staff=True,
            is_superuser=False,
        )

    def test_token_obtain_returns_tokens_with_claims(self):
        """Token obtain should return tokens with all claims"""
        # Use TokenService directly since API endpoint may vary
        tokens = TokenService.create_tokens_for_user(self.user)

        self.assertIn("access", tokens)
        self.assertIn("refresh", tokens)

        # Decode token and check claims
        decoded = decode_token_for_test(tokens["access"])

        self.assertTrue(decoded["is_staff"])
        self.assertFalse(decoded["is_superuser"])
        self.assertEqual(decoded["email"], "user@example.com")


@override_settings(URL_PREFIX="")
class AnonymousAuthenticationTests(APITestCase):
    """Test anonymous user authentication flow"""

    def setUp(self):
        self.client = APIClient()

    def test_anonymous_auth_creates_user(self):
        """Anonymous auth should create a new anonymous user"""
        response = self.client.post(reverse("anonymous"), {})

        # Anonymous endpoint returns 201 CREATED for new user
        self.assertIn(
            response.status_code, [status.HTTP_200_OK, status.HTTP_201_CREATED]
        )
        self.assertIn("user", response.data)
        self.assertIn("tokens", response.data)

    def test_anonymous_auth_returns_token_with_claims(self):
        """Anonymous auth should return token with is_staff=False and is_superuser=False"""
        response = self.client.post(reverse("anonymous"), {})

        self.assertIn(
            response.status_code, [status.HTTP_200_OK, status.HTTP_201_CREATED]
        )

        # Decode token and check claims
        decoded = decode_token_for_test(response.data["tokens"]["access"])

        self.assertIn("is_staff", decoded)
        self.assertIn("is_superuser", decoded)
        self.assertIn("is_anonymous", decoded)
        self.assertFalse(decoded["is_staff"])
        self.assertFalse(decoded["is_superuser"])
        self.assertTrue(decoded["is_anonymous"])


@override_settings(URL_PREFIX="")
class TokenRefreshTests(APITestCase):
    """Test token refresh preserves claims"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="refresh@example.com",
            username="refreshuser",
            password="testpass123",
            is_staff=True,
            is_superuser=True,
        )

    def test_token_refresh_returns_new_token(self):
        """Refreshed token should be returned successfully"""
        # Get initial tokens
        tokens = TokenService.create_tokens_for_user(self.user)

        response = self.client.post(
            reverse("token_refresh"), {"refresh": tokens["refresh"]}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)


class PermissionIntegrationTests(TestCase):
    """Integration tests for permission-based JWT claims"""

    def setUp(self):
        self.regular_user = User.objects.create_user(
            email="regular@example.com",
            username="regular",
            password="testpass123",
        )
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            username="staff",
            password="testpass123",
            is_staff=True,
        )
        self.superuser = User.objects.create_user(
            email="super@example.com",
            username="super",
            password="testpass123",
            is_staff=True,
            is_superuser=True,
        )

    def test_regular_user_token_has_correct_claims(self):
        """Regular user should have is_staff=False in token"""
        tokens = TokenService.create_tokens_for_user(self.regular_user)

        decoded = decode_token_for_test(tokens["access"])

        self.assertFalse(decoded["is_staff"])
        self.assertFalse(decoded["is_superuser"])

    def test_staff_user_token_has_correct_claims(self):
        """Staff user should have is_staff=True in token"""
        tokens = TokenService.create_tokens_for_user(self.staff_user)

        decoded = decode_token_for_test(tokens["access"])

        self.assertTrue(decoded["is_staff"])
        self.assertFalse(decoded["is_superuser"])

    def test_superuser_token_has_correct_claims(self):
        """Superuser should have is_staff=True and is_superuser=True in token"""
        tokens = TokenService.create_tokens_for_user(self.superuser)

        decoded = decode_token_for_test(tokens["access"])

        self.assertTrue(decoded["is_staff"])
        self.assertTrue(decoded["is_superuser"])

    def test_user_permission_change_reflects_in_new_token(self):
        """When user permission changes, new token should reflect the change"""
        # Initially regular user
        tokens1 = TokenService.create_tokens_for_user(self.regular_user)

        decoded1 = decode_token_for_test(tokens1["access"])
        self.assertFalse(decoded1["is_staff"])

        # Promote to staff
        self.regular_user.is_staff = True
        self.regular_user.save()

        # New token should have is_staff=True
        tokens2 = TokenService.create_tokens_for_user(self.regular_user)
        decoded2 = decode_token_for_test(tokens2["access"])
        self.assertTrue(decoded2["is_staff"])

    def test_anonymous_user_token_claims(self):
        """Anonymous user should have correct claims"""
        anon_user = User.create_anonymous_user()
        tokens = TokenService.create_tokens_for_user(anon_user)

        decoded = decode_token_for_test(tokens["access"])

        self.assertFalse(decoded["is_staff"])
        self.assertFalse(decoded["is_superuser"])
        self.assertTrue(decoded["is_anonymous"])


@override_settings(URL_PREFIX="")
class JWKSEndpointTests(APITestCase):
    """Test JWKS endpoint for JWT verification"""

    def setUp(self):
        self.client = APIClient()

    def test_jwks_endpoint_returns_200(self):
        """JWKS endpoint should return 200 OK"""
        response = self.client.get(reverse("jwks"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_jwks_endpoint_returns_keys_array(self):
        """JWKS endpoint should return keys array"""
        response = self.client.get(reverse("jwks"))
        self.assertIn("keys", response.data)
        self.assertIsInstance(response.data["keys"], list)

    def test_jwks_endpoint_hs256_returns_info(self):
        """For HS256, JWKS should return algorithm info (not the key)"""
        response = self.client.get(reverse("jwks"))
        # HS256 mode should return empty keys with info
        self.assertEqual(len(response.data["keys"]), 0)
        # Should have info about HS256 mode
        if "_info" in response.data:
            self.assertEqual(response.data["_info"]["algorithm"], "HS256")


@override_settings(URL_PREFIX="")
class OpenIDConfigurationTests(APITestCase):
    """Test OpenID Configuration endpoint"""

    def setUp(self):
        self.client = APIClient()

    def test_openid_config_returns_200(self):
        """OpenID configuration should return 200 OK"""
        response = self.client.get(reverse("openid-configuration"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_openid_config_contains_issuer(self):
        """OpenID configuration should contain issuer"""
        from django.conf import settings

        response = self.client.get(reverse("openid-configuration"))
        self.assertIn("issuer", response.data)
        # Issuer is derived from JWT_ISSUER setting (which comes from IRON_HOST)
        self.assertEqual(response.data["issuer"], settings.JWT_ISSUER)

    def test_openid_config_contains_jwks_uri(self):
        """OpenID configuration should contain jwks_uri"""
        response = self.client.get(reverse("openid-configuration"))
        self.assertIn("jwks_uri", response.data)
        self.assertIn(".well-known/jwks.json", response.data["jwks_uri"])

    def test_openid_config_contains_token_endpoint(self):
        """OpenID configuration should contain token_endpoint"""
        response = self.client.get(reverse("openid-configuration"))
        self.assertIn("token_endpoint", response.data)
        self.assertIn("api/v1/auth/token/", response.data["token_endpoint"])

    def test_openid_config_contains_claims_supported(self):
        """OpenID configuration should list supported claims"""
        response = self.client.get(reverse("openid-configuration"))
        self.assertIn("claims_supported", response.data)
        claims = response.data["claims_supported"]
        # Verify key claims are listed
        self.assertIn("user_id", claims)
        self.assertIn("is_staff", claims)
        self.assertIn("is_superuser", claims)
        self.assertIn("iss", claims)

    def test_openid_config_contains_algorithm(self):
        """OpenID configuration should list supported algorithms"""
        response = self.client.get(reverse("openid-configuration"))
        self.assertIn("id_token_signing_alg_values_supported", response.data)
        self.assertIn("HS256", response.data["id_token_signing_alg_values_supported"])


class IssuerVerificationTests(TestCase):
    """Test that JWT issuer claim is properly verified"""

    def test_token_with_correct_issuer_is_valid(self):
        """Token with correct issuer should be accepted"""
        from stapel_core.core.config import JWTConfig
        from stapel_core.core.jwt_handler import JWTHandler

        config = JWTConfig(
            secret_key="test-secret", algorithm="HS256", issuer="stapel-auth"
        )
        handler = JWTHandler(config)

        # Generate token (will have iss='stapel-auth')
        access_token, _ = handler.generate_token_pair({"user_id": "test-user"})

        # Should decode successfully
        payload = handler.decode_token(access_token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["iss"], "stapel-auth")

    def test_token_with_wrong_issuer_is_rejected(self):
        """Token with wrong issuer should be rejected"""
        from stapel_core.core.config import JWTConfig
        from stapel_core.core.jwt_handler import JWTHandler

        # Generate token with one issuer
        config1 = JWTConfig(
            secret_key="test-secret", algorithm="HS256", issuer="wrong-issuer"
        )
        handler1 = JWTHandler(config1)
        access_token, _ = handler1.generate_token_pair({"user_id": "test-user"})

        # Try to verify with different issuer
        config2 = JWTConfig(
            secret_key="test-secret", algorithm="HS256", issuer="stapel-auth"
        )
        handler2 = JWTHandler(config2)

        # Should reject due to issuer mismatch
        payload = handler2.decode_token(access_token)
        self.assertIsNone(payload)

    def test_token_without_issuer_check_when_not_configured(self):
        """Token should be accepted when issuer verification is not configured"""
        from stapel_core.core.config import JWTConfig
        from stapel_core.core.jwt_handler import JWTHandler

        # Generate token with issuer
        config1 = JWTConfig(
            secret_key="test-secret", algorithm="HS256", issuer="any-issuer"
        )
        handler1 = JWTHandler(config1)
        access_token, _ = handler1.generate_token_pair({"user_id": "test-user"})

        # Verify without issuer requirement (issuer='')
        config2 = JWTConfig(
            secret_key="test-secret",
            algorithm="HS256",
            issuer="",  # No issuer verification
        )
        handler2 = JWTHandler(config2)

        # Should accept token regardless of issuer
        payload = handler2.decode_token(access_token)
        self.assertIsNotNone(payload)


# =============================================================================
# Service Tests
# =============================================================================


@override_settings(USE_MOCK_SMS_OTP=True, MOCK_OTP_CODE="1234")
class PhoneVerificationServiceTests(TestCase):
    """Tests for PhoneVerificationService"""

    def setUp(self):
        from stapel_auth.services import PhoneVerificationService

        self.service = PhoneVerificationService()

    def test_generate_code_mock_mode(self):
        """In mock mode, should return mock code"""
        code = self.service.generate_code()
        self.assertEqual(code, "1234")

    def test_generate_code_force_real(self):
        """With force_real, should generate real code even in mock mode"""
        code = self.service.generate_code(force_real=True)
        self.assertNotEqual(code, "1234")
        self.assertEqual(len(code), 4)
        self.assertTrue(code.isdigit())

    def test_send_verification_code_creates_record(self):
        """send_verification_code should create PhoneVerification record"""
        result = self.service.send_verification_code("+15551234567")
        self.assertIsNotNone(result)
        self.assertEqual(result.phone, "+15551234567")
        self.assertEqual(result.code, "1234")

    def test_send_verification_code_rate_limit(self):
        """Should return rate_limit error if called too quickly"""
        # First request
        self.service.send_verification_code("+15551234567")
        # Second request immediately
        result = self.service.send_verification_code("+15551234567")
        self.assertEqual(result.get("error"), "rate_limit")

    def test_verify_code_success(self):
        """verify_code should return success for valid code"""
        self.service.send_verification_code("+15551234567")
        result = self.service.verify_code("+15551234567", "1234")
        self.assertTrue(result.get("success"))

    def test_verify_code_invalid(self):
        """verify_code should return error for invalid code"""
        self.service.send_verification_code("+15551234567")
        result = self.service.verify_code("+15551234567", "0000")
        self.assertEqual(result.get("error"), "invalid_code")

    def test_verify_code_no_verification(self):
        """verify_code should return error if no verification exists"""
        result = self.service.verify_code("+15559999999", "1234")
        self.assertEqual(result.get("error"), "invalid_code")

    def test_verify_code_max_attempts_blocks(self):
        """After 5 failed attempts, should block verification"""
        self.service.send_verification_code("+15551234567")

        # Make 5 failed attempts
        for i in range(5):
            result = self.service.verify_code("+15551234567", "0000")

        self.assertEqual(result.get("error"), "blocked")
        self.assertIn("retry_after", result)

    @override_settings(STAPEL_AUTH={"OTP_RESEND_COOLDOWN": 5})
    def test_resend_cooldown_setting_drives_actual_rate_limit(self):
        """AUTH_OTP_RESEND_COOLDOWN isn't just contract metadata — it is the
        exact window send_verification_code() enforces (single source)."""
        from stapel_auth.conf import auth_settings
        from stapel_auth.services import PhoneVerificationService
        auth_settings.reload()
        service = PhoneVerificationService()
        service.send_verification_code("+15557654321")
        result = service.send_verification_code("+15557654321")
        self.assertEqual(result.get("error"), "rate_limit")
        self.assertEqual(result.get("retry_after"), 5)

    @override_settings(STAPEL_AUTH={"OTP_TTL": 120})
    def test_otp_ttl_setting_drives_actual_expiry(self):
        """AUTH_OTP_TTL isn't just contract metadata — it is the exact
        lifetime the created PhoneVerification record gets (single source)."""
        from stapel_auth.conf import auth_settings
        from stapel_auth.services import PhoneVerificationService
        auth_settings.reload()
        service = PhoneVerificationService()
        verification = service.send_verification_code("+15559998888")
        delta = verification.expires_at - verification.created_at
        self.assertAlmostEqual(delta.total_seconds(), 120, delta=5)


@override_settings(USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="5678")
class EmailVerificationServiceTests(TestCase):
    """Tests for EmailVerificationService"""

    def setUp(self):
        from stapel_auth.services import EmailVerificationService

        self.service = EmailVerificationService()

    def test_generate_code_mock_mode(self):
        """In mock mode, should return mock code"""
        code = self.service.generate_code()
        self.assertEqual(code, "5678")

    def test_generate_code_force_real(self):
        """With force_real, should generate real code"""
        code = self.service.generate_code(force_real=True)
        self.assertNotEqual(code, "5678")
        self.assertEqual(len(code), 4)

    def test_send_verification_code_creates_record(self):
        """send_verification_code should create EmailVerification record"""
        result = self.service.send_verification_code("test@example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result.email, "test@example.com")

    def test_send_verification_code_rate_limit(self):
        """Should return rate_limit error if called too quickly"""
        self.service.send_verification_code("test@example.com")
        result = self.service.send_verification_code("test@example.com")
        self.assertEqual(result.get("error"), "rate_limit")

    def test_verify_code_success(self):
        """verify_code should return success for valid code"""
        self.service.send_verification_code("test@example.com")
        result = self.service.verify_code("test@example.com", "5678")
        self.assertTrue(result.get("success"))

    def test_verify_code_invalid(self):
        """verify_code should return error for invalid code"""
        self.service.send_verification_code("test@example.com")
        result = self.service.verify_code("test@example.com", "0000")
        self.assertEqual(result.get("error"), "invalid_code")


class OAuthServiceTests(TestCase):
    """Tests for OAuthService"""

    def setUp(self):
        from stapel_auth.services import OAuthService

        self.service = OAuthService()

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_get_google_user_data_success(self, mock_get):
        """Should parse Google user data correctly"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "id": "google123",
            "email": "user@gmail.com",
            "picture": "https://example.com/photo.jpg",
        }

        result = self.service.get_user_data("google", "fake-token")

        self.assertEqual(result.id, "google123")
        self.assertEqual(result.email, "user@gmail.com")
        self.assertEqual(result.username, "user")

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_get_google_user_data_failure(self, mock_get):
        """Should return None on Google API failure"""
        mock_get.return_value.status_code = 401

        result = self.service.get_user_data("google", "invalid-token")
        self.assertIsNone(result)

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_get_facebook_user_data_success(self, mock_get):
        """Should parse Facebook user data correctly"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "id": "fb123",
            "email": "user@facebook.com",
            "name": "John Doe",
            "picture": {"data": {"url": "https://example.com/photo.jpg"}},
        }

        result = self.service.get_user_data("facebook", "fake-token")

        self.assertEqual(result.id, "fb123")
        self.assertEqual(result.username, "john_doe")

    @patch("stapel_auth.oauth_providers.requests.get")
    def test_get_github_user_data_success(self, mock_get):
        """Should parse GitHub user data correctly"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "id": 12345,
            "email": "user@github.com",
            "login": "githubuser",
            "avatar_url": "https://example.com/photo.jpg",
        }

        result = self.service.get_user_data("github", "fake-token")

        self.assertEqual(result.id, "12345")
        self.assertEqual(result.username, "githubuser")

    def test_unsupported_provider(self):
        """Should return None for unsupported provider"""
        result = self.service.get_user_data("twitter", "fake-token")
        self.assertIsNone(result)


class TokenServiceTests(TestCase):
    """Tests for TokenService"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="tokentest@example.com",
            username="tokentest",
            password="testpass123",
            is_staff=True,
        )

    def test_create_tokens_for_user(self):
        """Should create valid access and refresh tokens"""
        tokens = TokenService.create_tokens_for_user(self.user)

        self.assertIn("access", tokens)
        self.assertIn("refresh", tokens)
        self.assertTrue(len(tokens["access"]) > 0)
        self.assertTrue(len(tokens["refresh"]) > 0)

    def test_verify_token_valid(self):
        """Should verify valid token"""
        tokens = TokenService.create_tokens_for_user(self.user)
        payload = TokenService.verify_token(tokens["access"])

        self.assertIsNotNone(payload)
        self.assertEqual(payload["email"], "tokentest@example.com")

    def test_verify_token_invalid(self):
        """Should return None for invalid token"""
        payload = TokenService.verify_token("invalid-token")
        self.assertIsNone(payload)

    def test_blacklist_token(self):
        """Should attempt to blacklist refresh token (may fail if blacklist app not installed)"""
        tokens = TokenService.create_tokens_for_user(self.user)
        # blacklist_token returns True if successful, False if blacklist not available
        result = TokenService.blacklist_token(tokens["refresh"])
        # Just verify it doesn't raise an exception
        self.assertIn(result, [True, False])

    def test_blacklist_invalid_token(self):
        """Should return False for invalid token"""
        result = TokenService.blacklist_token("invalid-token")
        self.assertFalse(result)


# =============================================================================
# Permission Tests
# =============================================================================


class IsServiceAPIKeyPermissionTests(TestCase):
    """Tests for IsServiceAPIKey permission"""

    def setUp(self):
        from stapel_auth.models import ServiceAPIKey
        from stapel_auth.permissions import IsServiceAPIKey

        self.permission = IsServiceAPIKey()
        self.api_key = ServiceAPIKey.objects.create(
            name="Test Service", key="test-service-key-12345", is_active=True
        )

    def test_valid_api_key_allowed(self):
        """Request with valid API key should be allowed"""
        request = MagicMock()
        request.headers = {"x-api-key": "test-service-key-12345"}

        result = self.permission.has_permission(request, None)

        self.assertTrue(result)
        self.assertEqual(request.service, self.api_key)

    def test_invalid_api_key_denied(self):
        """Request with invalid API key should be denied"""
        request = MagicMock()
        request.META = {"HTTP_X_API_KEY": "invalid-key"}

        result = self.permission.has_permission(request, None)

        self.assertFalse(result)

    def test_missing_api_key_denied(self):
        """Request without API key should be denied"""
        request = MagicMock()
        request.META = {}

        result = self.permission.has_permission(request, None)

        self.assertFalse(result)

    def test_inactive_api_key_denied(self):
        """Request with inactive API key should be denied"""
        self.api_key.is_active = False
        self.api_key.save()

        request = MagicMock()
        request.META = {"HTTP_X_API_KEY": "test-service-key-12345"}

        result = self.permission.has_permission(request, None)

        self.assertFalse(result)


@override_settings(INTERNAL_SERVICE_KEY="internal-secret-key")
class IsInternalServicePermissionTests(TestCase):
    """Tests for IsInternalService permission"""

    def setUp(self):
        from stapel_auth.permissions import IsInternalService

        self.permission = IsInternalService()

    def test_valid_internal_key_allowed(self):
        """Request with valid internal key should be allowed"""
        request = MagicMock()
        request.headers = {"x-internal-service-key": "internal-secret-key"}

        result = self.permission.has_permission(request, None)

        self.assertTrue(result)

    def test_invalid_internal_key_denied(self):
        """Request with invalid internal key should be denied"""
        request = MagicMock()
        request.META = {"HTTP_X_INTERNAL_SERVICE_KEY": "wrong-key"}

        result = self.permission.has_permission(request, None)

        self.assertFalse(result)

    def test_missing_internal_key_denied(self):
        """Request without internal key should be denied"""
        request = MagicMock()
        request.META = {}

        result = self.permission.has_permission(request, None)

        self.assertFalse(result)


class IsOwnerOrReadOnlyPermissionTests(TestCase):
    """Tests for IsOwnerOrReadOnly permission"""

    def setUp(self):
        from stapel_auth.permissions import IsOwnerOrReadOnly

        self.permission = IsOwnerOrReadOnly()
        self.user = User.objects.create_user(
            email="owner@example.com", username="owner", password="testpass123"
        )
        self.other_user = User.objects.create_user(
            email="other@example.com", username="other", password="testpass123"
        )

    def test_safe_method_allowed_for_anyone(self):
        """GET, HEAD, OPTIONS should be allowed for any user"""
        request = MagicMock()
        request.method = "GET"
        request.user = self.other_user

        obj = MagicMock()
        obj.user = self.user

        result = self.permission.has_object_permission(request, None, obj)

        self.assertTrue(result)

    def test_write_allowed_for_owner(self):
        """POST, PUT, DELETE should be allowed for owner"""
        request = MagicMock()
        request.method = "PUT"
        request.user = self.user

        obj = MagicMock()
        obj.user = self.user

        result = self.permission.has_object_permission(request, None, obj)

        self.assertTrue(result)

    def test_write_denied_for_non_owner(self):
        """POST, PUT, DELETE should be denied for non-owner"""
        request = MagicMock()
        request.method = "DELETE"
        request.user = self.other_user

        obj = MagicMock()
        obj.user = self.user

        result = self.permission.has_object_permission(request, None, obj)

        self.assertFalse(result)


# =============================================================================
# View Tests - Token Refresh
# =============================================================================


@override_settings(URL_PREFIX="")
class TokenRefreshViewTests(APITestCase):
    """Tests for CustomTokenRefreshView"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="refresh@example.com",
            username="refreshuser",
            password="testpass123",
        )

    def test_refresh_get_without_token_returns_401(self):
        """GET refresh without token should return 401"""
        response = self.client.get(reverse("token_refresh"))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_post_without_token_returns_401(self):
        """POST refresh without token should return 401"""
        response = self.client.post(reverse("token_refresh"), {})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_with_invalid_token_returns_401(self):
        """Refresh with invalid token should return 401"""
        response = self.client.post(
            reverse("token_refresh"), {"refresh": "invalid-token"}
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# =============================================================================
# View Tests - Email Verification Edge Cases
# =============================================================================


@override_settings(URL_PREFIX="", USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="1234")
class EmailVerificationEdgeCaseTests(APITestCase):
    """Tests for email verification edge cases"""

    def setUp(self):
        self.client = APIClient()

    def test_email_verify_blocked_returns_422(self):
        """Email verify when blocked should return 422"""
        from datetime import timedelta

        from stapel_auth.models import EmailVerification
        from stapel_auth.services import EmailVerificationService

        service = EmailVerificationService()
        service.send_verification_code("blocked@example.com")

        # Simulate blocked state directly (max_attempts varies by config)
        verification = EmailVerification.objects.get(email="blocked@example.com")
        verification.attempts = 10
        verification.blocked_until = timezone.now() + timedelta(minutes=5)
        verification.save()

        # Now try to verify via API
        response = self.client.post(
            reverse("email_verify"), {"email": "blocked@example.com", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("localizable_error", response.data)

    def test_email_verify_expired_returns_400(self):
        """Email verify with expired code should return 400"""
        from datetime import timedelta

        from django.utils import timezone

        from stapel_auth.models import EmailVerification

        # Create expired verification
        EmailVerification.objects.create(
            email="expired@example.com",
            code="1234",
            expires_at=timezone.now() - timedelta(minutes=1),
        )

        response = self.client.post(
            reverse("email_verify"), {"email": "expired@example.com", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("expired", response.data["error"].lower())

    def test_email_verify_invalid_code_shows_attempts(self):
        """Email verify with invalid code should show attempts remaining"""
        from stapel_auth.services import EmailVerificationService

        service = EmailVerificationService()
        service.send_verification_code("attempts@example.com")

        response = self.client.post(
            reverse("email_verify"),
            {
                "email": "attempts@example.com",
                "code": "0000",  # wrong code
            },
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("attempts_remaining", response.data.get("params", {}))

    def test_email_verify_authenticated_user_modifies_email(self):
        """Authenticated user verifying email should get MODIFIED status"""
        from stapel_auth.services import EmailVerificationService

        # Create and authenticate user
        user = User.objects.create_user(
            email="old@example.com",
            username="modifier",
            password="testpass123",
        )
        self.client.force_authenticate(user=user)

        # Send verification to new email
        service = EmailVerificationService()
        service.send_verification_code("new@example.com")

        # Verify new email
        response = self.client.post(
            reverse("email_verify"), {"email": "new@example.com", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "MODIFIED")

    def test_email_verify_anonymous_user_registers(self):
        """Anonymous user verifying new email should get REGISTERED status"""
        from stapel_auth.services import EmailVerificationService

        # Create anonymous user and authenticate
        anon_user = User.create_anonymous_user()
        original_username = anon_user.username
        self.assertTrue(original_username.startswith("anon_"))
        self.client.force_authenticate(user=anon_user)

        # Send verification code
        service = EmailVerificationService()
        service.send_verification_code("anon-register@example.com")

        # Verify email
        response = self.client.post(
            reverse("email_verify"),
            {"email": "anon-register@example.com", "code": "1234"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "REGISTERED")

        # Check username was upgraded from anon_xxx to user_xxx
        anon_user.refresh_from_db()
        self.assertTrue(anon_user.username.startswith("user_"))
        self.assertEqual(anon_user.username, f"user_{original_username[5:]}")

    def test_email_verify_anonymous_user_merges_with_existing(self):
        """Anonymous user verifying existing email should get MERGED status"""
        from stapel_auth.services import EmailVerificationService

        # Create existing user
        User.objects.create_user(
            email="existing@example.com",
            username="existing",
            password="testpass123",
        )

        # Create anonymous user and authenticate
        anon_user = User.create_anonymous_user()
        self.client.force_authenticate(user=anon_user)

        # Send verification to existing email
        service = EmailVerificationService()
        service.send_verification_code("existing@example.com")

        # Verify email
        response = self.client.post(
            reverse("email_verify"), {"email": "existing@example.com", "code": "1234"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "MERGED")


# =============================================================================
# View Tests - OAuth Edge Cases
# =============================================================================


@override_settings(URL_PREFIX="")
class OAuthViewEdgeCaseTests(APITestCase):
    """Tests for OAuth view edge cases"""

    def setUp(self):
        self.client = APIClient()

    def test_oauth_missing_provider_returns_400(self):
        """OAuth without provider should return 400"""
        response = self.client.post(
            reverse("oauth_login"), {"access_token": "some-token"}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("required", response.data["error"].lower())

    def test_oauth_missing_access_token_returns_400(self):
        """OAuth without access_token should return 400"""
        response = self.client.post(reverse("oauth_login"), {"provider": "google"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("stapel_auth.services.OAuthService.get_user_data")
    def test_oauth_failed_auth_returns_400(self, mock_get_user_data):
        """OAuth with failed provider auth should return 400"""
        mock_get_user_data.return_value = None

        response = self.client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "invalid-token"},
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Failed", response.data["error"])


# =============================================================================
# View Tests - Me Endpoint
# =============================================================================


@override_settings(URL_PREFIX="")
class MeEndpointTests(APITestCase):
    """Tests for /me endpoint"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="me@example.com",
            username="meuser",
            password="testpass123",
            is_staff=True,
        )

    def test_me_unauthenticated_returns_401(self):
        """Me endpoint without auth should return 401"""
        response = self.client.get(reverse("me"))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_me_authenticated_returns_user_data(self):
        """Me endpoint with auth should return user data"""
        self.client.force_authenticate(user=self.user)

        response = self.client.get(reverse("me"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "me@example.com")

    def test_me_includes_is_staff_and_is_superuser(self):
        """Frontends gate admin UI off these — surface them from /me/."""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(reverse("me"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("is_staff", response.data)
        self.assertIn("is_superuser", response.data)
        self.assertTrue(response.data["is_staff"])
        self.assertFalse(response.data["is_superuser"])

    def test_me_patch_cannot_escalate_privileges(self):
        """is_staff / is_superuser are read-only — PATCH must ignore them."""
        regular = User.objects.create_user(
            email="reg@example.com",
            username="reg",
            password="x",
            is_staff=False,
            is_superuser=False,
        )
        self.client.force_authenticate(user=regular)
        # Attempt to PATCH ourselves to superuser via /me/
        self.client.patch(
            reverse("me"),
            {"is_staff": True, "is_superuser": True},
            format="json",
        )
        regular.refresh_from_db()
        self.assertFalse(regular.is_staff)
        self.assertFalse(regular.is_superuser)


# =============================================================================
# View Tests - Logout Endpoint
# =============================================================================


@override_settings(URL_PREFIX="")
class LogoutEndpointTests(APITestCase):
    """Tests for logout endpoint"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="logout@example.com",
            username="logoutuser",
            password="testpass123",
        )

    def test_logout_unauthenticated_returns_success(self):
        """Logout without auth should still work (clears cookies)"""
        response = self.client.post(reverse("logout"))
        # Logout can succeed even without auth - it just clears cookies
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_authenticated_returns_success(self):
        """Logout with auth should return success"""
        tokens = TokenService.create_tokens_for_user(self.user)
        self.client.force_authenticate(user=self.user)

        response = self.client.post(
            reverse("logout"), {"refresh_token": tokens["refresh"]}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("message", response.data)

    def test_logout_get_authenticated_returns_success(self):
        """Logout GET with auth should return success"""
        self.client.force_authenticate(user=self.user)

        response = self.client.get(reverse("logout"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)


# =============================================================================
# View Tests - Verify Token Endpoint
# =============================================================================


@override_settings(URL_PREFIX="")
class VerifyTokenEndpointTests(APITestCase):
    """Tests for verify token endpoint"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="verify@example.com",
            username="verifyuser",
            password="testpass123",
        )

    def test_verify_valid_token_returns_valid(self):
        """Verify with valid token should return valid=True"""
        tokens = TokenService.create_tokens_for_user(self.user)

        response = self.client.post(
            reverse("verify_token"), {"token": tokens["access"]}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["valid"])

    def test_verify_invalid_token_returns_401(self):
        """Verify with invalid token should return 401"""
        response = self.client.post(reverse("verify_token"), {"token": "invalid-token"})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# =============================================================================
# View Tests - Email Request Edge Cases
# =============================================================================


@override_settings(URL_PREFIX="", USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="1234")
class EmailRequestEdgeCaseTests(APITestCase):
    """Tests for email request edge cases"""

    def setUp(self):
        self.client = APIClient()

    def test_email_request_rate_limit(self):
        """Email request should return 429 when rate limited"""
        # First request
        self.client.post(reverse("email_request"), {"email": "rate@example.com"})

        # Second request immediately
        response = self.client.post(
            reverse("email_request"), {"email": "rate@example.com"}
        )

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn("retry_after", response.data["params"])

    def test_email_request_authenticated_conflict(self):
        """Authenticated user requesting OTP for another user's email should get 409"""
        # Create existing user with email
        User.objects.create_user(
            email="taken@example.com",
            username="taken",
            password="testpass123",
        )

        # Create and authenticate different user
        other_user = User.objects.create_user(
            email="other@example.com",
            username="other",
            password="testpass123",
        )
        self.client.force_authenticate(user=other_user)

        # Try to request OTP for taken email
        response = self.client.post(
            reverse("email_request"), {"email": "taken@example.com"}
        )

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)


class PhoneVerificationEdgeCaseTests(APITestCase):
    """Edge case tests for phone verification flows"""

    def setUp(self):
        self.client = APIClient()

    @patch.object(PhoneVerification, "is_blocked", return_value=True)
    def test_phone_verify_blocked_returns_422(self, mock_blocked):
        """Blocked phone should return 422 with retry_after"""
        from datetime import timedelta

        # Create verification with blocked state
        PhoneVerification.objects.create(
            phone="+12345678901",
            code="1234",
            expires_at=timezone.now() + timedelta(minutes=10),
            blocked_until=timezone.now() + timedelta(minutes=5),
        )

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12345678901", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("localizable_error", response.data)

    def test_phone_verify_expired_returns_400(self):
        """Expired phone verification should return 400"""
        from datetime import timedelta

        # Create expired verification
        PhoneVerification.objects.create(
            phone="+12345678902",
            code="1234",
            expires_at=timezone.now() - timedelta(minutes=1),
        )

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12345678902", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("localizable_error", response.data)

    def test_phone_verify_invalid_code_shows_attempts(self):
        """Invalid phone code should show attempts remaining"""
        from stapel_auth.services import PhoneVerificationService

        service = PhoneVerificationService()
        service.send_verification_code("+12345678903")

        # Send wrong code
        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12345678903", "code": "9999"}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("attempts_remaining", response.data.get("params", {}))

    def test_phone_verify_authenticated_user_modifies_phone(self):
        """Authenticated user verifying phone should get MODIFIED status"""
        from stapel_auth.services import PhoneVerificationService

        # Create and authenticate user
        user = User.objects.create_user(
            email="user@example.com", username="testuser", password="testpass123"
        )
        self.client.force_authenticate(user=user)

        # Send verification code
        service = PhoneVerificationService()
        service.send_verification_code("+12345678904")

        # Verify phone
        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12345678904", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "MODIFIED")

    def test_phone_verify_anonymous_user_registers(self):
        """Anonymous user verifying new phone should get REGISTERED status"""
        from stapel_auth.services import PhoneVerificationService

        # Create anonymous user and authenticate
        anon_user = User.create_anonymous_user()
        original_username = anon_user.username
        self.assertTrue(original_username.startswith("anon_"))
        self.client.force_authenticate(user=anon_user)

        # Send verification code
        service = PhoneVerificationService()
        service.send_verification_code("+12345678905")

        # Verify phone
        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12345678905", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "REGISTERED")

        # Check username was upgraded from anon_xxx to user_xxx
        anon_user.refresh_from_db()
        self.assertTrue(anon_user.username.startswith("user_"))

    def test_phone_verify_anonymous_user_merges_with_existing(self):
        """Anonymous user verifying existing phone should get MERGED status"""
        from stapel_auth.services import PhoneVerificationService

        # Create existing user with phone
        User.objects.create_user(
            username="existing_phone_user", phone="+12345678906", auth_type="phone"
        )

        # Create anonymous user and authenticate
        anon_user = User.create_anonymous_user()
        self.client.force_authenticate(user=anon_user)

        # Send verification code for existing phone
        service = PhoneVerificationService()
        service.send_verification_code("+12345678906")

        # Verify phone
        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12345678906", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "MERGED")


class PhoneRequestEdgeCaseTests(APITestCase):
    """Edge case tests for phone OTP request"""

    def setUp(self):
        self.client = APIClient()

    def test_phone_request_rate_limit(self):
        """Rapid phone requests should be rate limited"""
        from stapel_auth.services import PhoneVerificationService

        service = PhoneVerificationService()
        # First request
        service.send_verification_code("+12345678910")

        # Second request should be rate limited
        result = service.send_verification_code("+12345678910")

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("error"), "rate_limit")

    def test_phone_request_authenticated_conflict(self):
        """Authenticated user requesting OTP for taken phone should get 409"""
        # Create user with phone
        User.objects.create_user(username="phone_owner", phone="+12345678911")

        # Create another user and authenticate
        other_user = User.objects.create_user(
            email="other@example.com", username="other_user", password="testpass123"
        )
        self.client.force_authenticate(user=other_user)

        # Try to request OTP for taken phone
        response = self.client.post(reverse("phone_request"), {"phone": "+12345678911"})

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)


@override_settings(USE_MOCK_EMAIL_OTP=True, USE_MOCK_SMS_OTP=True)
class CookieAuthenticationTests(APITestCase):
    """Tests for cookie-based JWT authentication"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="cookie@example.com", username="cookieuser", password="testpass123"
        )

    def test_email_verify_sets_cookies(self):
        """Email verification should set JWT cookies"""
        from stapel_auth.services import EmailVerificationService

        service = EmailVerificationService()
        service.send_verification_code("newcookie@example.com")

        response = self.client.post(
            reverse("email_verify"), {"email": "newcookie@example.com", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check cookies are set
        self.assertIn("stapel_jwt", response.cookies)
        self.assertIn("stapel_refresh_jwt", response.cookies)
        # Check cookies are httponly
        self.assertTrue(response.cookies["stapel_jwt"]["httponly"])
        self.assertTrue(response.cookies["stapel_refresh_jwt"]["httponly"])

    def test_phone_verify_sets_cookies(self):
        """Phone verification should set JWT cookies"""
        from stapel_auth.services import PhoneVerificationService

        service = PhoneVerificationService()
        service.send_verification_code("+12345678920")

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12345678920", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("stapel_jwt", response.cookies)
        self.assertIn("stapel_refresh_jwt", response.cookies)

    def test_anonymous_auth_sets_cookies(self):
        """Anonymous auth should set JWT cookies"""
        response = self.client.post(
            reverse("anonymous"), {"device_id": "test-device-123"}
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("stapel_jwt", response.cookies)
        self.assertIn("stapel_refresh_jwt", response.cookies)

    def test_logout_clears_cookies(self):
        """Logout should clear JWT cookies"""
        from stapel_auth.services import TokenService

        # Get tokens and authenticate
        refresh = TokenService.get_refresh_token_for_user(self.user)
        self.client.force_authenticate(user=self.user)
        self.client.cookies["stapel_jwt"] = str(refresh.access_token)
        self.client.cookies["stapel_refresh_jwt"] = str(refresh)

        response = self.client.post(reverse("logout"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Cookies should be deleted (max-age=0 or empty)
        if "stapel_jwt" in response.cookies:
            cookie = response.cookies["stapel_jwt"]
            self.assertTrue(cookie["max-age"] == 0 or cookie.value == "")

    def test_token_refresh_via_cookie(self):
        """Token refresh should work via cookie"""
        from stapel_auth.services import TokenService

        refresh = TokenService.get_refresh_token_for_user(self.user)
        self.client.cookies["stapel_refresh_jwt"] = str(refresh)

        response = self.client.get(reverse("token_refresh"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_token_refresh_via_body(self):
        """Token refresh should work via request body"""
        from stapel_auth.services import TokenService

        refresh = TokenService.get_refresh_token_for_user(self.user)

        response = self.client.post(reverse("token_refresh"), {"refresh": str(refresh)})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)


class UserTypeTests(APITestCase):
    """Tests for different user types and their behavior"""

    def setUp(self):
        self.client = APIClient()

    def test_me_anonymous_user(self):
        """Me endpoint should work for anonymous user"""
        anon_user = User.create_anonymous_user()
        self.client.force_authenticate(user=anon_user)

        response = self.client.get(reverse("me"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["is_anonymous"])
        self.assertTrue(response.data["username"].startswith("anon_"))

    def test_me_email_only_user(self):
        """Me endpoint should work for email-only user"""
        user = User.objects.create_user(
            email="emailonly@example.com",
            username="emailonly",
            auth_type="email",
            is_email_verified=True,
        )
        self.client.force_authenticate(user=user)

        response = self.client.get(reverse("me"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "emailonly@example.com")
        self.assertFalse(response.data["phone"])  # Empty string or None
        self.assertTrue(response.data["is_email_verified"])
        self.assertFalse(response.data["is_phone_verified"])

    def test_me_phone_only_user(self):
        """Me endpoint should work for phone-only user"""
        user = User.objects.create_user(
            username="phoneonly",
            phone="+12345678930",
            auth_type="phone",
            is_phone_verified=True,
        )
        self.client.force_authenticate(user=user)

        response = self.client.get(reverse("me"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["email"])  # Empty string or None
        self.assertEqual(response.data["phone"], "+12345678930")
        self.assertFalse(response.data["is_email_verified"])
        self.assertTrue(response.data["is_phone_verified"])

    def test_me_email_and_phone_user(self):
        """Me endpoint should work for user with both email and phone"""
        user = User.objects.create_user(
            email="both@example.com",
            username="bothuser",
            phone="+12345678931",
            auth_type="email",
            is_email_verified=True,
            is_phone_verified=True,
        )
        self.client.force_authenticate(user=user)

        response = self.client.get(reverse("me"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "both@example.com")
        self.assertEqual(response.data["phone"], "+12345678931")
        self.assertTrue(response.data["is_email_verified"])
        self.assertTrue(response.data["is_phone_verified"])

    def test_anonymous_user_has_correct_claims(self):
        """Anonymous user token should have correct claims"""
        anon_user = User.create_anonymous_user()

        access, _ = create_token_for_user(anon_user)
        payload = decode_token_for_test(access)

        self.assertTrue(payload["is_anonymous"])
        self.assertEqual(payload["auth_type"], "anonymous")
        self.assertFalse(payload["is_staff"])
        self.assertFalse(payload["is_superuser"])

    def test_email_user_has_correct_claims(self):
        """Email user token should have correct claims"""
        user = User.objects.create_user(
            email="claims@example.com",
            username="claimsuser",
            auth_type="email",
            is_email_verified=True,
        )

        access, _ = create_token_for_user(user)
        payload = decode_token_for_test(access)

        self.assertFalse(payload["is_anonymous"])
        self.assertEqual(payload["auth_type"], "email")
        self.assertEqual(payload["email"], "claims@example.com")

    def test_phone_user_has_correct_claims(self):
        """Phone user token should have correct claims"""
        user = User.objects.create_user(
            username="phoneclaimsuser",
            phone="+12345678932",
            auth_type="phone",
            is_phone_verified=True,
        )

        access, _ = create_token_for_user(user)
        payload = decode_token_for_test(access)

        self.assertFalse(payload["is_anonymous"])
        self.assertEqual(payload["auth_type"], "phone")


@override_settings(USE_MOCK_EMAIL_OTP=True, USE_MOCK_SMS_OTP=True)
class UserUpgradeTests(APITestCase):
    """Tests for anonymous user upgrade flows"""

    def setUp(self):
        self.client = APIClient()

    def test_anonymous_upgrade_to_email_changes_auth_type(self):
        """Anonymous user upgrading via email should change auth_type"""
        from stapel_auth.services import EmailVerificationService

        anon_user = User.create_anonymous_user()
        self.assertEqual(anon_user.auth_type, "anonymous")
        self.client.force_authenticate(user=anon_user)

        service = EmailVerificationService()
        service.send_verification_code("upgrade@example.com")

        response = self.client.post(
            reverse("email_verify"), {"email": "upgrade@example.com", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        anon_user.refresh_from_db()
        self.assertEqual(anon_user.auth_type, "email")
        self.assertFalse(anon_user.is_anonymous)

    def test_anonymous_upgrade_to_phone_changes_auth_type(self):
        """Anonymous user upgrading via phone should change auth_type"""
        from stapel_auth.services import PhoneVerificationService

        anon_user = User.create_anonymous_user()
        self.assertEqual(anon_user.auth_type, "anonymous")
        self.client.force_authenticate(user=anon_user)

        service = PhoneVerificationService()
        service.send_verification_code("+12345678940")

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12345678940", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        anon_user.refresh_from_db()
        self.assertEqual(anon_user.auth_type, "phone")
        self.assertFalse(anon_user.is_anonymous)

    def test_email_user_adding_phone(self):
        """Email user adding phone should get MODIFIED and keep auth_type"""
        from stapel_auth.services import PhoneVerificationService

        user = User.objects.create_user(
            email="addphone@example.com",
            username="addphoneuser",
            auth_type="email",
            is_email_verified=True,
        )
        self.client.force_authenticate(user=user)

        service = PhoneVerificationService()
        service.send_verification_code("+12345678941")

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12345678941", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "MODIFIED")
        user.refresh_from_db()
        self.assertEqual(user.auth_type, "email")  # auth_type unchanged
        self.assertTrue(user.is_phone_verified)
        self.assertEqual(user.phone, "+12345678941")

    def test_phone_user_adding_email(self):
        """Phone user adding email should get MODIFIED and keep auth_type"""
        from stapel_auth.services import EmailVerificationService

        user = User.objects.create_user(
            username="addemailuser",
            phone="+12345678942",
            auth_type="phone",
            is_phone_verified=True,
        )
        self.client.force_authenticate(user=user)

        service = EmailVerificationService()
        service.send_verification_code("addemail@example.com")

        response = self.client.post(
            reverse("email_verify"), {"email": "addemail@example.com", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "MODIFIED")
        user.refresh_from_db()
        self.assertEqual(user.auth_type, "phone")  # auth_type unchanged
        self.assertTrue(user.is_email_verified)
        self.assertEqual(user.email, "addemail@example.com")


class AdminOTPSecurityTests(APITestCase):
    """Tests for admin account OTP security"""

    def setUp(self):
        self.client = APIClient()

    @patch("stapel_auth.services.EmailVerificationService.generate_code")
    def test_admin_email_gets_real_otp(self, mock_generate):
        """Admin accounts should get real OTP even in mock mode"""
        mock_generate.return_value = "5678"

        # Create admin user
        User.objects.create_user(
            email="adminotp_test@example.com", username="adminotp_test", is_staff=True
        )

        response = self.client.post(
            reverse("email_request"), {"email": "adminotp_test@example.com"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify generate_code was called with force_real=True
        mock_generate.assert_called_with(force_real=True)

    @patch("stapel_auth.services.PhoneVerificationService.generate_code")
    def test_admin_phone_gets_real_otp(self, mock_generate):
        """Admin accounts should get real OTP for phone even in mock mode"""
        mock_generate.return_value = "5678"

        # Create admin user
        User.objects.create_user(
            username="phoneadmin", phone="+12345678950", is_staff=True
        )

        response = self.client.post(reverse("phone_request"), {"phone": "+12345678950"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_generate.assert_called_with(force_real=True)

    @patch("stapel_auth.services.EmailVerificationService.generate_code")
    def test_superuser_email_gets_real_otp(self, mock_generate):
        """Superuser accounts should get real OTP"""
        mock_generate.return_value = "5678"

        # Create superuser
        User.objects.create_superuser(
            email="superuser@example.com", username="superuser", password="testpass123"
        )

        response = self.client.post(
            reverse("email_request"), {"email": "superuser@example.com"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_generate.assert_called_with(force_real=True)


class VerificationModelTests(TestCase):
    """Tests for verification model behavior"""

    def test_phone_verification_is_expired(self):
        """Phone verification should correctly report expiry"""
        from datetime import timedelta

        from django.utils import timezone

        expired = PhoneVerification.objects.create(
            phone="+12345678960",
            code="1234",
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        valid = PhoneVerification.objects.create(
            phone="+12345678961",
            code="1234",
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        self.assertTrue(expired.is_expired())
        self.assertFalse(valid.is_expired())

    def test_phone_verification_is_blocked(self):
        """Phone verification should correctly report blocked state"""
        from datetime import timedelta

        from django.utils import timezone

        blocked = PhoneVerification.objects.create(
            phone="+12345678962",
            code="1234",
            expires_at=timezone.now() + timedelta(minutes=10),
            blocked_until=timezone.now() + timedelta(minutes=5),
        )
        not_blocked = PhoneVerification.objects.create(
            phone="+12345678963",
            code="1234",
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        self.assertTrue(blocked.is_blocked())
        self.assertFalse(not_blocked.is_blocked())

    def test_email_verification_is_expired(self):
        """Email verification should correctly report expiry"""
        from datetime import timedelta

        from django.utils import timezone

        expired = EmailVerification.objects.create(
            email="expired@example.com",
            code="1234",
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        valid = EmailVerification.objects.create(
            email="valid@example.com",
            code="1234",
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        self.assertTrue(expired.is_expired())
        self.assertFalse(valid.is_expired())

    def test_email_verification_is_blocked(self):
        """Email verification should correctly report blocked state"""
        from datetime import timedelta

        from django.utils import timezone

        blocked = EmailVerification.objects.create(
            email="blocked@example.com",
            code="1234",
            expires_at=timezone.now() + timedelta(minutes=10),
            blocked_until=timezone.now() + timedelta(minutes=5),
        )
        not_blocked = EmailVerification.objects.create(
            email="notblocked@example.com",
            code="1234",
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        self.assertTrue(blocked.is_blocked())
        self.assertFalse(not_blocked.is_blocked())


@override_settings(USE_MOCK_EMAIL_OTP=True, USE_MOCK_SMS_OTP=True)
class LoginAttemptTests(TestCase):
    """Tests for login attempt logging"""

    def test_login_attempt_created_on_failed_email_verify(self):
        """Failed email verification should create login attempt"""
        from stapel_auth.models import LoginAttempt
        from stapel_auth.services import EmailVerificationService

        client = APIClient()
        service = EmailVerificationService()
        service.send_verification_code("attempt@example.com")

        # Wrong code
        client.post(
            reverse("email_verify"), {"email": "attempt@example.com", "code": "9999"}
        )

        attempts = LoginAttempt.objects.filter(
            identifier="attempt@example.com", attempt_type="failed"
        )
        self.assertEqual(attempts.count(), 1)

    def test_login_attempt_created_on_successful_email_verify(self):
        """Successful email verification should create success login attempt"""
        from stapel_auth.models import LoginAttempt
        from stapel_auth.services import EmailVerificationService

        client = APIClient()
        service = EmailVerificationService()
        service.send_verification_code("success@example.com")

        client.post(
            reverse("email_verify"), {"email": "success@example.com", "code": "0000"}
        )

        attempts = LoginAttempt.objects.filter(
            identifier="success@example.com", attempt_type="success"
        )
        self.assertEqual(attempts.count(), 1)


class UsernameUpgradeTests(TestCase):
    """Tests for username upgrade from anon_ to user_"""

    def test_upgrade_username_basic(self):
        """Username should upgrade from anon_xxx to user_xxx"""
        user = User.create_anonymous_user()
        original = user.username
        self.assertTrue(original.startswith("anon_"))

        user.upgrade_username_from_anonymous()

        self.assertTrue(user.username.startswith("user_"))
        self.assertEqual(user.username[5:], original[5:])  # Same suffix

    def test_upgrade_username_conflict_resolution(self):
        """Username upgrade should handle conflicts"""
        # Create first anonymous user and upgrade
        user1 = User.create_anonymous_user()
        suffix = user1.username[5:]
        user1.upgrade_username_from_anonymous()
        user1.save()

        # Create another user with same suffix pattern
        user2 = User.objects.create(
            username=f"anon_{suffix}", auth_type="anonymous", is_anonymous=True
        )
        user2.upgrade_username_from_anonymous()

        # Should get different username due to conflict
        self.assertTrue(user2.username.startswith("user_"))
        self.assertNotEqual(user2.username, user1.username)

    def test_upgrade_non_anonymous_username_unchanged(self):
        """Non-anonymous username should not change"""
        user = User.objects.create_user(
            email="normal@example.com", username="normaluser"
        )
        original = user.username

        user.upgrade_username_from_anonymous()

        self.assertEqual(user.username, original)


class PhoneSerializerValidationTests(TestCase):
    """Tests for phone serializer validation"""

    def test_invalid_phone_number_format(self):
        """Invalid phone number format should raise validation error"""
        from stapel_auth.serializers import PhoneAuthRequestSerializer

        serializer = PhoneAuthRequestSerializer(data={"phone": "not-a-phone"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("phone", serializer.errors)

    def test_invalid_phone_number(self):
        """Invalid phone number should raise validation error"""
        from stapel_auth.serializers import PhoneAuthRequestSerializer

        serializer = PhoneAuthRequestSerializer(data={"phone": "+1234"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("phone", serializer.errors)

    def test_valid_phone_number(self):
        """Valid phone number should pass validation"""
        from stapel_auth.serializers import PhoneAuthRequestSerializer

        serializer = PhoneAuthRequestSerializer(data={"phone": "+12025551234"})
        self.assertTrue(serializer.is_valid())


class ConvertAnonymousUserSerializerTests(TestCase):
    """Tests for ConvertAnonymousUserSerializer validation"""

    def test_convert_anonymous_requires_email_or_phone(self):
        """ConvertAnonymousUserSerializer requires email or phone"""
        from stapel_auth.serializers import ConvertAnonymousUserSerializer

        serializer = ConvertAnonymousUserSerializer(data={})
        self.assertFalse(serializer.is_valid())

    def test_convert_anonymous_email_valid(self):
        """ConvertAnonymousUserSerializer with email should be valid"""
        from stapel_auth.serializers import ConvertAnonymousUserSerializer

        serializer = ConvertAnonymousUserSerializer(
            data={"email": "test@example.com", "code": "1234"}
        )
        self.assertTrue(serializer.is_valid())

    def test_convert_anonymous_phone_valid(self):
        """ConvertAnonymousUserSerializer with phone should be valid"""
        from stapel_auth.serializers import ConvertAnonymousUserSerializer

        serializer = ConvertAnonymousUserSerializer(
            data={"phone": "+12025551234", "code": "1234"}
        )
        self.assertTrue(serializer.is_valid())


class EmailRequestErrorTests(APITestCase):
    """Tests for email request error handling"""

    def setUp(self):
        self.client = APIClient()

    @patch("stapel_auth.services.EmailVerificationService.send_verification_code")
    def test_email_request_service_failure(self, mock_send):
        """Service failure should return 500"""
        mock_send.return_value = None

        response = self.client.post(
            reverse("email_request"), {"email": "fail@example.com"}
        )

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn("error", response.data)

    def test_email_request_invalid_email(self):
        """Invalid email should return 400"""
        response = self.client.post(reverse("email_request"), {"email": "not-an-email"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class PhoneRequestErrorTests(APITestCase):
    """Tests for phone request error handling"""

    def setUp(self):
        self.client = APIClient()

    @patch("stapel_auth.services.PhoneVerificationService.send_verification_code")
    def test_phone_request_service_failure(self, mock_send):
        """Service failure should return 500"""
        mock_send.return_value = None

        response = self.client.post(reverse("phone_request"), {"phone": "+12025551234"})

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn("error", response.data)

    @patch("stapel_auth.services.PhoneVerificationService.send_verification_code")
    def test_phone_request_blocked(self, mock_send):
        """Blocked account should return 422"""
        mock_send.return_value = {"error": "blocked", "retry_after": 600}

        response = self.client.post(reverse("phone_request"), {"phone": "+12025551234"})

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("error", response.data)
        self.assertEqual(response.data["params"]["retry_after"], 600)

    def test_phone_request_invalid_format(self):
        """Invalid phone format should return 400"""
        response = self.client.post(reverse("phone_request"), {"phone": "invalid"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TokenRefreshErrorTests(APITestCase):
    """Tests for token refresh error handling"""

    def setUp(self):
        self.client = APIClient()

    @patch("stapel_core.core.token_manager.TokenManager.refresh_access_token")
    def test_token_refresh_user_not_found(self, mock_refresh):
        """Token refresh with deleted user should fail"""
        from stapel_auth.services import TokenService

        # Create user and get refresh token
        user = User.objects.create_user(
            email="deleted@example.com", username="deleteduser", password="testpass123"
        )
        refresh = TokenService.get_refresh_token_for_user(user)

        # Delete the user
        user.delete()

        # Mock to return None (simulating user not found)
        mock_refresh.return_value = None

        response = self.client.post(reverse("token_refresh"), {"refresh": str(refresh)})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class OAuthEdgeCaseTests(APITestCase):
    """Tests for OAuth edge cases"""

    def setUp(self):
        self.client = APIClient()

    def test_oauth_invalid_provider(self):
        """Invalid OAuth provider should return 400"""
        response = self.client.post(
            reverse("oauth_login"),
            {"provider": "invalid_provider", "access_token": "some_token"},
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("stapel_auth.services.OAuthService.get_user_data")
    def test_oauth_user_data_fetch_failure(self, mock_get_user_data):
        """OAuth user data fetch failure should return 400"""
        mock_get_user_data.return_value = None

        response = self.client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "invalid_token"},
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class VerifyTokenEndpointEdgeCaseTests(APITestCase):
    """Additional tests for verify token endpoint"""

    def setUp(self):
        self.client = APIClient()

    def test_verify_expired_token(self):
        """Expired token should return 401"""
        # Create an expired token
        expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjE1MDAwMDAwMDB9.invalid"

        response = self.client.post(reverse("verify_token"), {"token": expired_token})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_verify_missing_token(self):
        """Missing token should return 400"""
        response = self.client.post(reverse("verify_token"), {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class LogoutEdgeCaseTests(APITestCase):
    """Additional tests for logout endpoint"""

    def setUp(self):
        self.client = APIClient()

    def test_logout_with_invalid_refresh_token(self):
        """Logout with invalid refresh token should still succeed"""
        self.client.cookies["stapel_refresh_jwt"] = "invalid_token"

        response = self.client.post(reverse("logout"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_get_request(self):
        """Logout should work with GET request"""
        response = self.client.get(reverse("logout"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)


class EmailVerifyMaxAttemptsTests(APITestCase):
    """Tests for email verification max attempts"""

    def setUp(self):
        self.client = APIClient()

    def test_email_verify_max_attempts_blocks(self):
        """Max failed attempts should block verification"""
        from datetime import timedelta

        from stapel_auth.models import EmailVerification
        from stapel_auth.services import EmailVerificationService

        service = EmailVerificationService()
        service.send_verification_code("maxattempts@example.com")

        # Simulate max attempts with blocked state
        verification = EmailVerification.objects.get(email="maxattempts@example.com")
        verification.attempts = 10
        verification.blocked_until = timezone.now() + timedelta(minutes=5)
        verification.save()

        response = self.client.post(
            reverse("email_verify"),
            {"email": "maxattempts@example.com", "code": "0000"},
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("localizable_error", response.data)


class PhoneVerifyMaxAttemptsTests(APITestCase):
    """Tests for phone verification max attempts"""

    def setUp(self):
        self.client = APIClient()

    def test_phone_verify_max_attempts_blocks(self):
        """Max failed attempts should block verification"""
        from datetime import timedelta

        from stapel_auth.services import PhoneVerificationService

        service = PhoneVerificationService()
        service.send_verification_code("+12025559999")

        # Simulate max attempts with blocked state
        verification = PhoneVerification.objects.get(phone="+12025559999")
        verification.attempts = 10
        verification.blocked_until = timezone.now() + timedelta(minutes=5)
        verification.save()

        response = self.client.post(
            reverse("phone_verify"), {"phone": "+12025559999", "code": "0000"}
        )

        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("localizable_error", response.data)


class ModelStringRepresentationTests(TestCase):
    """Tests for model __str__ methods"""

    def test_email_verification_str(self):
        """EmailVerification __str__ should return email"""
        from datetime import timedelta

        from django.utils import timezone

        from stapel_auth.models import EmailVerification

        verification = EmailVerification.objects.create(
            email="str@example.com",
            code="1234",
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        self.assertIn("str@example.com", str(verification))

    def test_phone_verification_str(self):
        """PhoneVerification __str__ should return phone"""
        from datetime import timedelta

        from django.utils import timezone

        from stapel_auth.models import PhoneVerification

        verification = PhoneVerification.objects.create(
            phone="+12025558888",
            code="1234",
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        self.assertIn("+12025558888", str(verification))

    def test_login_attempt_str(self):
        """LoginAttempt __str__ should return identifier"""
        from stapel_auth.models import LoginAttempt

        attempt = LoginAttempt.objects.create(
            identifier="test@example.com",
            attempt_type="success",
            ip_address="127.0.0.1",
        )

        self.assertIn("test@example.com", str(attempt))

    def test_service_api_key_str(self):
        """ServiceAPIKey __str__ should return name"""
        from stapel_auth.models import ServiceAPIKey

        api_key = ServiceAPIKey.objects.create(
            name="Test API Key", key="test-key-12345"
        )

        self.assertIn("Test API Key", str(api_key))


class DeviceIdTrackingTests(APITestCase):
    """Tests for device_id tracking in verifications"""

    def setUp(self):
        self.client = APIClient()

    def test_email_request_stores_device_id(self):
        """Email request should store device_id"""
        from stapel_auth.models import EmailVerification

        response = self.client.post(
            reverse("email_request"),
            {"email": "device@example.com", "device_id": "test-device-001"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        verification = EmailVerification.objects.get(email="device@example.com")
        self.assertEqual(verification.device_id, "test-device-001")

    def test_phone_request_stores_device_id(self):
        """Phone request should store device_id"""
        from stapel_auth.models import PhoneVerification

        response = self.client.post(
            reverse("phone_request"),
            {"phone": "+12025557777", "device_id": "test-device-002"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        verification = PhoneVerification.objects.get(phone="+12025557777")
        self.assertEqual(verification.device_id, "test-device-002")


# =============================================================================
# Masking Utility Tests
# =============================================================================


class MaskingUtilTests(TestCase):
    """Tests for phone/email masking utilities"""

    def test_mask_phone_standard(self):
        from stapel_auth.utils import mask_phone

        self.assertEqual(mask_phone("+79994561234"), "+7 *** *** 12 34")

    def test_mask_phone_us(self):
        from stapel_auth.utils import mask_phone

        result = mask_phone("+12025551234")
        self.assertIn("12 34", result)
        self.assertIn("***", result)

    def test_mask_phone_short(self):
        from stapel_auth.utils import mask_phone

        self.assertEqual(mask_phone("+1"), "+1")

    def test_mask_email_standard(self):
        from stapel_auth.utils import mask_email

        self.assertEqual(mask_email("user@example.com"), "u***@example.com")

    def test_mask_email_single_char_local(self):
        from stapel_auth.utils import mask_email

        self.assertEqual(mask_email("u@example.com"), "u@example.com")

    def test_mask_email_no_at(self):
        from stapel_auth.utils import mask_email

        self.assertEqual(mask_email("noemail"), "noemail")

    def test_mask_value_dispatch_phone(self):
        from stapel_auth.utils import mask_value

        result = mask_value("+79994561234", "phone")
        self.assertIn("***", result)

    def test_mask_value_dispatch_email(self):
        from stapel_auth.utils import mask_value

        result = mask_value("user@example.com", "email")
        self.assertEqual(result, "u***@example.com")


# =============================================================================
# AuthenticatorChangeService Tests
# =============================================================================


@override_settings(USE_MOCK_SMS_OTP=True, USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="0000")
class AuthenticatorChangeServiceTests(TestCase):
    """Tests for AuthenticatorChangeService"""

    def setUp(self):
        from stapel_auth.services import AuthenticatorChangeService

        self.service = AuthenticatorChangeService()
        self.user = User.objects.create_user(
            email="change@example.com",
            username="changeuser",
            phone="+12025551000",
            is_email_verified=True,
            is_phone_verified=True,
        )

    def test_is_value_available_free_phone(self):
        """Available phone should return True"""
        self.assertTrue(self.service.is_value_available("+13125551111", "phone"))

    def test_is_value_available_taken_phone(self):
        """Taken phone should return False"""
        self.assertFalse(self.service.is_value_available("+12025551000", "phone"))

    def test_is_value_available_excludes_self(self):
        """Own phone should be available when excluding self"""
        self.assertTrue(
            self.service.is_value_available(
                "+12025551000", "phone", exclude_user=self.user
            )
        )

    def test_is_value_available_reserved_phone(self):
        """Reserved phone (pending change) should return False"""
        AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551000",
            new_value="+13125552222",
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        self.assertFalse(self.service.is_value_available("+13125552222", "phone"))

    def test_request_old_otp_no_phone(self):
        """Request old OTP for user without phone should fail"""
        user_no_phone = User.objects.create_user(
            email="nophone@example.com",
            username="nophone",
        )
        result = self.service.request_old_otp(user_no_phone, "phone")
        self.assertEqual(result["error"], "no_current_value")

    def test_request_old_otp_phone_success(self):
        """Request old OTP for phone should succeed"""
        result = self.service.request_old_otp(self.user, "phone")
        self.assertTrue(result.get("success"))
        self.assertIn("masked_target", result)
        self.assertIn("***", result["masked_target"])

    def test_request_old_otp_email_success(self):
        """Request old OTP for email should succeed"""
        result = self.service.request_old_otp(self.user, "email")
        self.assertTrue(result.get("success"))
        self.assertIn("masked_target", result)

    def test_verify_old_otp_creates_change_request(self):
        """Verifying old OTP should create change request with token"""
        self.service.request_old_otp(self.user, "phone")
        result = self.service.verify_old_otp(self.user, "phone", "0000")
        self.assertTrue(result.get("success"))
        self.assertIn("change_token", result)
        self.assertIn("expires_at", result)

        # Verify DB record
        req = AuthenticatorChangeRequest.objects.get(
            user=self.user,
            change_type="phone",
            status=AuthenticatorChangeStatus.PENDING,
        )
        self.assertEqual(str(req.change_token), result["change_token"])

    def test_verify_old_otp_wrong_code(self):
        """Verifying old OTP with wrong code should fail"""
        self.service.request_old_otp(self.user, "phone")
        result = self.service.verify_old_otp(self.user, "phone", "9999")
        self.assertIn("error", result)

    def test_request_new_otp_success(self):
        """Request new OTP after verifying old should succeed"""
        self.service.request_old_otp(self.user, "phone")
        old_result = self.service.verify_old_otp(self.user, "phone", "0000")
        token = old_result["change_token"]

        result = self.service.request_new_otp(self.user, "phone", "+13125553333", token)
        self.assertTrue(result.get("success"))

    def test_request_new_otp_invalid_token(self):
        """Request new OTP with invalid token should fail"""
        result = self.service.request_new_otp(
            self.user, "phone", "+13125553333", str(uuid.uuid4())
        )
        self.assertEqual(result["error"], "invalid_change_token")

    def test_request_new_otp_unavailable_value(self):
        """Request new OTP for taken value should fail"""
        User.objects.create_user(username="other", phone="+13125554444")

        self.service.request_old_otp(self.user, "phone")
        old_result = self.service.verify_old_otp(self.user, "phone", "0000")
        token = old_result["change_token"]

        result = self.service.request_new_otp(self.user, "phone", "+13125554444", token)
        self.assertEqual(result["error"], "not_available")

    def test_verify_new_and_apply_success(self):
        """Full instant flow should change user's phone"""
        self.service.request_old_otp(self.user, "phone")
        old_result = self.service.verify_old_otp(self.user, "phone", "0000")
        token = old_result["change_token"]

        self.service.request_new_otp(self.user, "phone", "+13125555555", token)
        result = self.service.verify_new_and_apply(
            self.user, "phone", "+13125555555", "0000", token
        )
        self.assertTrue(result.get("success"))

        self.user.refresh_from_db()
        self.assertEqual(self.user.phone, "+13125555555")
        self.assertTrue(self.user.is_phone_verified)

        # Change request should be completed
        req = AuthenticatorChangeRequest.objects.get(change_token=uuid.UUID(token))
        self.assertEqual(req.status, AuthenticatorChangeStatus.COMPLETED)

    def test_verify_new_value_mismatch(self):
        """Verify-new with different phone than request-new should fail"""
        self.service.request_old_otp(self.user, "phone")
        old_result = self.service.verify_old_otp(self.user, "phone", "0000")
        token = old_result["change_token"]

        self.service.request_new_otp(self.user, "phone", "+13125555555", token)
        result = self.service.verify_new_and_apply(
            self.user, "phone", "+13125556666", "0000", token
        )
        self.assertEqual(result["error"], "value_mismatch")

    def test_initiate_delayed_success(self):
        """Delayed initiation should create pending request with scheduled_at"""
        result = self.service.initiate_delayed(
            self.user,
            "phone",
            "+13125557777",
            device_id="dev-1",
            ip="1.2.3.4",
            user_agent="test",
        )
        self.assertTrue(result.get("success"))
        self.assertIn("change_request_id", result)
        self.assertIn("scheduled_at", result)

        req = AuthenticatorChangeRequest.objects.get(id=result["change_request_id"])
        self.assertEqual(req.status, AuthenticatorChangeStatus.PENDING)
        self.assertIsNotNone(req.scheduled_at)
        self.assertEqual(req.device_id, "dev-1")
        self.assertEqual(str(req.ip_address), "1.2.3.4")

    def test_initiate_delayed_unavailable_value(self):
        """Delayed initiation with taken value should fail"""
        User.objects.create_user(username="taken2", phone="+13125558888")
        result = self.service.initiate_delayed(self.user, "phone", "+13125558888")
        self.assertEqual(result["error"], "not_available")

    def test_get_pending_status_exists(self):
        """get_pending_status should return info for pending request"""
        self.service.initiate_delayed(self.user, "phone", "+13125559999")
        info = self.service.get_pending_status(self.user, "phone")
        self.assertIsNotNone(info)
        self.assertIn("change_request_id", info)
        self.assertIn("days_remaining", info)
        self.assertEqual(info["type"], "phone")

    def test_get_pending_status_none(self):
        """get_pending_status should return None when no pending request"""
        info = self.service.get_pending_status(self.user, "phone")
        self.assertIsNone(info)

    def test_cancel_pending_success(self):
        """cancel_pending should mark request as cancelled"""
        result = self.service.initiate_delayed(self.user, "phone", "+13125550001")
        cancel_result = self.service.cancel_pending(
            self.user,
            "phone",
            result["change_request_id"],
        )
        self.assertTrue(cancel_result.get("success"))

        req = AuthenticatorChangeRequest.objects.get(id=result["change_request_id"])
        self.assertEqual(req.status, AuthenticatorChangeStatus.CANCELLED)
        self.assertIsNotNone(req.cancelled_at)

    def test_cancel_pending_not_found(self):
        """cancel_pending with wrong ID should fail"""
        result = self.service.cancel_pending(self.user, "phone", str(uuid.uuid4()))
        self.assertEqual(result["error"], "not_found")

    def test_initiate_delayed_cancels_previous(self):
        """New delayed request should cancel existing pending one"""
        result1 = self.service.initiate_delayed(self.user, "phone", "+13125550002")
        result2 = self.service.initiate_delayed(self.user, "phone", "+13125550003")
        self.assertTrue(result2.get("success"))

        req1 = AuthenticatorChangeRequest.objects.get(id=result1["change_request_id"])
        self.assertEqual(req1.status, AuthenticatorChangeStatus.CANCELLED)


# =============================================================================
# Authenticator Change View Tests - Phone Instant
# =============================================================================


@override_settings(
    URL_PREFIX="", USE_MOCK_SMS_OTP=True, USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="0000"
)
class PhoneInstantChangeViewTests(APITestCase):
    """Tests for phone instant change flow via API"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="instant@example.com",
            username="instantuser",
            phone="+12025551100",
            is_phone_verified=True,
            is_email_verified=True,
        )
        self.client.force_authenticate(user=self.user)

    def test_request_old_success(self):
        response = self.client.post(reverse("phone_instant_request_old"), {})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("masked_target", response.data)

    def test_request_old_unauthenticated(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(reverse("phone_instant_request_old"), {})
        self.assertIn(
            response.status_code,
            [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN],
        )

    def test_verify_old_success(self):
        self.client.post(reverse("phone_instant_request_old"), {})
        response = self.client.post(
            reverse("phone_instant_verify_old"), {"code": "0000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "OLD_VERIFIED")
        self.assertIn("change_token", response.data)

    def test_verify_old_wrong_code(self):
        self.client.post(reverse("phone_instant_request_old"), {})
        response = self.client.post(
            reverse("phone_instant_verify_old"), {"code": "9999"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_request_new_success(self):
        self.client.post(reverse("phone_instant_request_old"), {})
        resp = self.client.post(reverse("phone_instant_verify_old"), {"code": "0000"})
        token = resp.data["change_token"]

        response = self.client.post(
            reverse("phone_instant_request_new"),
            {
                "phone": "+13125551234",
                "change_token": token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_request_new_taken_phone(self):
        User.objects.create_user(username="takenphone", phone="+13125559876")

        self.client.post(reverse("phone_instant_request_old"), {})
        resp = self.client.post(reverse("phone_instant_verify_old"), {"code": "0000"})
        token = resp.data["change_token"]

        response = self.client.post(
            reverse("phone_instant_request_new"),
            {
                "phone": "+13125559876",
                "change_token": token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_full_instant_phone_change(self):
        """Full 4-step phone instant change"""
        # Step 1: request old
        self.client.post(reverse("phone_instant_request_old"), {})
        # Step 2: verify old
        resp2 = self.client.post(reverse("phone_instant_verify_old"), {"code": "0000"})
        token = resp2.data["change_token"]
        # Step 3: request new
        self.client.post(
            reverse("phone_instant_request_new"),
            {
                "phone": "+13125550099",
                "change_token": token,
            },
        )
        # Step 4: verify new
        resp4 = self.client.post(
            reverse("phone_instant_verify_new"),
            {
                "phone": "+13125550099",
                "code": "0000",
                "change_token": token,
            },
        )
        self.assertEqual(resp4.status_code, status.HTTP_200_OK)
        self.assertEqual(resp4.data["status"], "MODIFIED")
        self.assertIn("tokens", resp4.data)

        self.user.refresh_from_db()
        self.assertEqual(self.user.phone, "+13125550099")

    def test_verify_new_missing_phone(self):
        """verify-new without phone field should return 400"""
        self.client.post(reverse("phone_instant_request_old"), {})
        resp = self.client.post(reverse("phone_instant_verify_old"), {"code": "0000"})
        token = resp.data["change_token"]

        response = self.client.post(
            reverse("phone_instant_verify_new"),
            {
                "email": "x@x.com",
                "code": "0000",
                "change_token": token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# =============================================================================
# Authenticator Change View Tests - Email Instant
# =============================================================================


@override_settings(
    URL_PREFIX="", USE_MOCK_SMS_OTP=True, USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="0000"
)
class EmailInstantChangeViewTests(APITestCase):
    """Tests for email instant change flow via API"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="emailinst@example.com",
            username="emailinstuser",
            phone="+12025551200",
            is_email_verified=True,
        )
        self.client.force_authenticate(user=self.user)

    def test_request_old_success(self):
        response = self.client.post(reverse("email_instant_request_old"), {})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("masked_target", response.data)

    def test_full_instant_email_change(self):
        """Full 4-step email instant change"""
        self.client.post(reverse("email_instant_request_old"), {})
        resp2 = self.client.post(reverse("email_instant_verify_old"), {"code": "0000"})
        token = resp2.data["change_token"]

        self.client.post(
            reverse("email_instant_request_new"),
            {
                "email": "newemail@example.com",
                "change_token": token,
            },
        )
        resp4 = self.client.post(
            reverse("email_instant_verify_new"),
            {
                "email": "newemail@example.com",
                "code": "0000",
                "change_token": token,
            },
        )
        self.assertEqual(resp4.status_code, status.HTTP_200_OK)
        self.assertEqual(resp4.data["status"], "MODIFIED")

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "newemail@example.com")
        self.assertTrue(self.user.is_email_verified)


# =============================================================================
# Authenticator Change View Tests - Phone Delayed
# =============================================================================


@override_settings(
    URL_PREFIX="", USE_MOCK_SMS_OTP=True, USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="0000"
)
class PhoneDelayedChangeViewTests(APITestCase):
    """Tests for phone delayed change flow via API"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="delayed@example.com",
            username="delayeduser",
            phone="+12025551300",
            is_phone_verified=True,
        )
        self.client.force_authenticate(user=self.user)

    def test_initiate_success(self):
        response = self.client.post(
            reverse("phone_delayed_initiate"),
            {
                "phone": "+13125550100",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["status"], "PENDING")
        self.assertIn("change_request_id", response.data)
        self.assertIn("scheduled_at", response.data)
        self.assertIn("new_value_masked", response.data)

    def test_initiate_taken_phone(self):
        User.objects.create_user(username="taken3", phone="+13125550200")
        response = self.client.post(
            reverse("phone_delayed_initiate"),
            {
                "phone": "+13125550200",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_status_with_pending(self):
        self.client.post(reverse("phone_delayed_initiate"), {"phone": "+13125550300"})
        response = self.client.get(reverse("phone_delayed_status"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["has_pending_change"])
        self.assertIn("days_remaining", response.data)

    def test_status_no_pending(self):
        response = self.client.get(reverse("phone_delayed_status"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["has_pending_change"])

    def test_cancel_success(self):
        resp = self.client.post(
            reverse("phone_delayed_initiate"), {"phone": "+13125550400"}
        )
        req_id = resp.data["change_request_id"]

        response = self.client.post(
            reverse("phone_delayed_cancel"),
            {
                "change_request_id": req_id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "CANCELLED")

    def test_cancel_not_found(self):
        response = self.client.post(
            reverse("phone_delayed_cancel"),
            {
                "change_request_id": str(uuid.uuid4()),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_initiate_unauthenticated(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(
            reverse("phone_delayed_initiate"),
            {
                "phone": "+13125550500",
            },
        )
        self.assertIn(
            response.status_code,
            [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN],
        )


# =============================================================================
# Authenticator Change View Tests - Email Delayed
# =============================================================================


@override_settings(
    URL_PREFIX="", USE_MOCK_SMS_OTP=True, USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="0000"
)
class EmailDelayedChangeViewTests(APITestCase):
    """Tests for email delayed change flow via API"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="emaildel@example.com",
            username="emaildeluser",
            is_email_verified=True,
        )
        self.client.force_authenticate(user=self.user)

    def test_initiate_success(self):
        response = self.client.post(
            reverse("email_delayed_initiate"),
            {
                "email": "newdelayed@example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["status"], "PENDING")

    def test_status_and_cancel(self):
        resp = self.client.post(
            reverse("email_delayed_initiate"),
            {
                "email": "cancelme@example.com",
            },
        )
        req_id = resp.data["change_request_id"]

        # Status
        status_resp = self.client.get(reverse("email_delayed_status"))
        self.assertTrue(status_resp.data["has_pending_change"])

        # Cancel
        cancel_resp = self.client.post(
            reverse("email_delayed_cancel"),
            {
                "change_request_id": req_id,
            },
        )
        self.assertEqual(cancel_resp.status_code, status.HTTP_200_OK)

        # Status after cancel
        status_resp2 = self.client.get(reverse("email_delayed_status"))
        self.assertFalse(status_resp2.data["has_pending_change"])


# =============================================================================
# Reservation Check Tests
# =============================================================================


@override_settings(
    URL_PREFIX="", USE_MOCK_SMS_OTP=True, USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="0000"
)
class ReservationCheckTests(APITestCase):
    """Tests that reserved phone/email are blocked during registration OTP request"""

    def setUp(self):
        self.client = APIClient()
        self.user_a = User.objects.create_user(
            email="usera@example.com",
            username="usera",
            phone="+12025551400",
            is_phone_verified=True,
            is_email_verified=True,
        )
        self.user_b = User.objects.create_user(
            email="userb@example.com",
            username="userb",
            phone="+12025551401",
            is_phone_verified=True,
            is_email_verified=True,
        )

    def test_email_request_blocked_by_reservation(self):
        """Email request should return 409 if email is reserved by pending change"""
        # user_a creates pending delayed change to newemail
        AuthenticatorChangeRequest.objects.create(
            user=self.user_a,
            change_type="email",
            old_value="usera@example.com",
            new_value="reserved@example.com",
            scheduled_at=timezone.now() + timedelta(days=14),
        )

        # user_b tries to request OTP for the reserved email
        self.client.force_authenticate(user=self.user_b)
        response = self.client.post(
            reverse("email_request"),
            {
                "email": "reserved@example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertIn("reserved", response.data["error"].lower())

    def test_phone_request_blocked_by_reservation(self):
        """Phone request should return 409 if phone is reserved by pending change"""
        AuthenticatorChangeRequest.objects.create(
            user=self.user_a,
            change_type="phone",
            old_value="+12025551400",
            new_value="+13125550600",
            scheduled_at=timezone.now() + timedelta(days=14),
        )

        self.client.force_authenticate(user=self.user_b)
        response = self.client.post(
            reverse("phone_request"),
            {
                "phone": "+13125550600",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertIn("reserved", response.data["error"].lower())

    def test_email_request_allowed_after_cancel(self):
        """Email request should succeed after reservation is cancelled"""
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user_a,
            change_type="email",
            old_value="usera@example.com",
            new_value="freed@example.com",
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        req.status = AuthenticatorChangeStatus.CANCELLED
        req.save()

        self.client.force_authenticate(user=self.user_b)
        response = self.client.post(
            reverse("email_request"),
            {
                "email": "freed@example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)


# =============================================================================
# Celery Task Tests
# =============================================================================


@override_settings(USE_MOCK_SMS_OTP=True, USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="0000")
class CeleryTaskTests(TestCase):
    """Tests for Celery tasks"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="taskuser@example.com",
            username="taskuser",
            phone="+12025551500",
            is_phone_verified=True,
            is_email_verified=True,
        )

    def test_send_change_notifications_day1(self):
        """Notification task should mark day 1 sent"""
        from stapel_auth.tasks import send_change_notifications

        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551500",
            new_value="+13125550700",
            scheduled_at=timezone.now() + timedelta(days=13),
        )
        # Backdate created_at to 2 days ago
        AuthenticatorChangeRequest.objects.filter(id=req.id).update(
            created_at=timezone.now() - timedelta(days=2),
        )

        count = send_change_notifications()
        self.assertEqual(count, 1)

        req.refresh_from_db()
        self.assertTrue(req.notification_day_1_sent)
        self.assertFalse(req.notification_day_7_sent)

    def test_send_change_notifications_day7(self):
        """Notification task should mark day 7 sent"""
        from stapel_auth.tasks import send_change_notifications

        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="email",
            old_value="taskuser@example.com",
            new_value="newtask@example.com",
            scheduled_at=timezone.now() + timedelta(days=7),
            notification_day_1_sent=True,
        )
        AuthenticatorChangeRequest.objects.filter(id=req.id).update(
            created_at=timezone.now() - timedelta(days=8),
        )

        count = send_change_notifications()
        self.assertEqual(count, 1)

        req.refresh_from_db()
        self.assertTrue(req.notification_day_7_sent)

    def test_execute_pending_changes(self):
        """Execute task should apply due changes"""
        from stapel_auth.tasks import execute_pending_changes

        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551500",
            new_value="+13125550800",
            scheduled_at=timezone.now() - timedelta(hours=1),
        )

        count = execute_pending_changes()
        self.assertEqual(count, 1)

        self.user.refresh_from_db()
        self.assertEqual(self.user.phone, "+13125550800")
        self.assertTrue(self.user.is_phone_verified)

        req.refresh_from_db()
        self.assertEqual(req.status, AuthenticatorChangeStatus.COMPLETED)
        self.assertIsNotNone(req.completed_at)

    def test_execute_pending_changes_not_due(self):
        """Execute task should skip future changes"""
        from stapel_auth.tasks import execute_pending_changes

        AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551500",
            new_value="+13125550900",
            scheduled_at=timezone.now() + timedelta(days=10),
        )

        count = execute_pending_changes()
        self.assertEqual(count, 0)

        self.user.refresh_from_db()
        self.assertEqual(self.user.phone, "+12025551500")

    def test_cleanup_expired_requests(self):
        """Cleanup task should expire old pending requests"""
        from stapel_auth.tasks import cleanup_expired_requests

        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551500",
            new_value="+13125551000",
            scheduled_at=timezone.now() - timedelta(days=20),
        )
        AuthenticatorChangeRequest.objects.filter(id=req.id).update(
            created_at=timezone.now() - timedelta(days=35),
        )

        count = cleanup_expired_requests()
        self.assertEqual(count, 1)

        req.refresh_from_db()
        self.assertEqual(req.status, AuthenticatorChangeStatus.EXPIRED)

    def test_cleanup_does_not_touch_recent(self):
        """Cleanup task should not touch recent pending requests"""
        from stapel_auth.tasks import cleanup_expired_requests

        AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551500",
            new_value="+13125551100",
            scheduled_at=timezone.now() + timedelta(days=10),
        )

        count = cleanup_expired_requests()
        self.assertEqual(count, 0)


# =============================================================================
# AuthenticatorChangeRequest Model Tests
# =============================================================================


class AuthenticatorChangeRequestModelTests(TestCase):
    """Tests for AuthenticatorChangeRequest model"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="model@example.com",
            username="modeluser",
            phone="+12025551600",
        )

    def test_str_representation(self):
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551600",
            new_value="+13125551200",
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        s = str(req)
        self.assertIn("phone", s)
        self.assertIn("pending", s)

    def test_unique_pending_per_user_type(self):
        """Only one pending request per user+type"""
        from django.db import IntegrityError

        AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551600",
            new_value="+13125551300",
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        with self.assertRaises(IntegrityError):
            AuthenticatorChangeRequest.objects.create(
                user=self.user,
                change_type="phone",
                old_value="+12025551600",
                new_value="+13125551400",
                scheduled_at=timezone.now() + timedelta(days=14),
            )

    def test_unique_pending_reservation(self):
        """Only one pending reservation per new_value+type"""
        from django.db import IntegrityError

        other_user = User.objects.create_user(
            email="other2@example.com",
            username="other2",
            phone="+12025551601",
        )
        AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551600",
            new_value="+13125551500",
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        with self.assertRaises(IntegrityError):
            AuthenticatorChangeRequest.objects.create(
                user=other_user,
                change_type="phone",
                old_value="+12025551601",
                new_value="+13125551500",
                scheduled_at=timezone.now() + timedelta(days=14),
            )

    def test_cancelled_does_not_block_constraint(self):
        """Cancelled request should not block new pending"""
        AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551600",
            new_value="+13125551600",
            scheduled_at=timezone.now() + timedelta(days=14),
            status=AuthenticatorChangeStatus.CANCELLED,
        )
        # Should succeed since previous is cancelled
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type="phone",
            old_value="+12025551600",
            new_value="+13125551700",
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        self.assertEqual(req.status, AuthenticatorChangeStatus.PENDING)


# =============================================================================
# Serializer Validation Tests
# =============================================================================


class ChangeSerializerTests(TestCase):
    """Tests for authenticator change serializers"""

    def test_instant_request_new_requires_phone_or_email(self):
        from stapel_auth.serializers import InstantChangeRequestNewSerializer

        serializer = InstantChangeRequestNewSerializer(
            data={
                "change_token": str(uuid.uuid4()),
            }
        )
        self.assertFalse(serializer.is_valid())

    def test_instant_request_new_valid_phone(self):
        from stapel_auth.serializers import InstantChangeRequestNewSerializer

        serializer = InstantChangeRequestNewSerializer(
            data={
                "phone": "+12025551234",
                "change_token": str(uuid.uuid4()),
            }
        )
        self.assertTrue(serializer.is_valid())

    def test_instant_request_new_invalid_phone(self):
        from stapel_auth.serializers import InstantChangeRequestNewSerializer

        serializer = InstantChangeRequestNewSerializer(
            data={
                "phone": "invalid",
                "change_token": str(uuid.uuid4()),
            }
        )
        self.assertFalse(serializer.is_valid())

    def test_delayed_initiate_requires_value(self):
        from stapel_auth.serializers import DelayedChangeInitiateSerializer

        serializer = DelayedChangeInitiateSerializer(data={})
        self.assertFalse(serializer.is_valid())

    def test_delayed_initiate_valid_email(self):
        from stapel_auth.serializers import DelayedChangeInitiateSerializer

        serializer = DelayedChangeInitiateSerializer(
            data={
                "email": "test@example.com",
            }
        )
        self.assertTrue(serializer.is_valid())

    def test_delayed_cancel_requires_uuid(self):
        from stapel_auth.serializers import DelayedChangeCancelSerializer

        serializer = DelayedChangeCancelSerializer(
            data={"change_request_id": "not-a-uuid"}
        )
        self.assertFalse(serializer.is_valid())

    def test_delayed_cancel_valid_uuid(self):
        from stapel_auth.serializers import DelayedChangeCancelSerializer

        serializer = DelayedChangeCancelSerializer(
            data={
                "change_request_id": str(uuid.uuid4()),
            }
        )
        self.assertTrue(serializer.is_valid())


# =============================================================================
# Password Login Tests
# =============================================================================


@override_settings(URL_PREFIX="", STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True})
class PasswordLoginTests(APITestCase):
    """Tests for POST /password/login/"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="loginuser",
            email="login@example.com",
            password="correct_password",
            is_email_verified=True,
        )

    def test_login_with_email(self):
        response = self.client.post(
            reverse("password_login"),
            {
                "login": "login@example.com",
                "password": "correct_password",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "LOGGED_IN")
        self.assertIn("access", response.data["tokens"])
        self.assertIn("refresh", response.data["tokens"])

    def test_login_with_username(self):
        response = self.client.post(
            reverse("password_login"),
            {
                "login": "loginuser",
                "password": "correct_password",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "LOGGED_IN")

    def test_login_wrong_password(self):
        response = self.client.post(
            reverse("password_login"),
            {
                "login": "login@example.com",
                "password": "wrong",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            response.data["localizable_error"], "error.401.invalid_credentials"
        )

    def test_login_nonexistent_user(self):
        response = self.client.post(
            reverse("password_login"),
            {
                "login": "nobody@example.com",
                "password": "whatever",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            response.data["localizable_error"], "error.401.invalid_credentials"
        )

    def test_login_inactive_user(self):
        self.user.is_active = False
        self.user.save()
        response = self.client.post(
            reverse("password_login"),
            {
                "login": "login@example.com",
                "password": "correct_password",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            response.data["localizable_error"], "error.401.account_disabled"
        )

    def test_login_missing_fields(self):
        response = self.client.post(
            reverse("password_login"), {"login": "login@example.com"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_sets_cookies(self):
        response = self.client.post(
            reverse("password_login"),
            {
                "login": "login@example.com",
                "password": "correct_password",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("stapel_jwt", response.cookies)


# =============================================================================
# Password Methods Tests
# =============================================================================


@override_settings(URL_PREFIX="")
class PasswordMethodsTests(APITestCase):
    """Tests for GET /password/methods/"""

    def setUp(self):
        self.client = APIClient()

    def _auth(self, user):
        access, _ = create_token_for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def test_methods_requires_auth(self):
        response = self.client.get(reverse("password_methods"))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_methods_no_password_no_contacts(self):
        user = User.objects.create_user(username="bare", password=None)
        user.set_unusable_password()
        user.save()
        self._auth(user)
        response = self.client.get(reverse("password_methods"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["has_password"])
        self.assertEqual(response.data["methods"], [])

    def test_methods_with_password(self):
        user = User.objects.create_user(username="withpw", password="secret")
        self._auth(user)
        response = self.client.get(reverse("password_methods"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["has_password"])
        methods = [m["method"] for m in response.data["methods"]]
        self.assertIn("password", methods)

    def test_methods_with_verified_email(self):
        user = User.objects.create_user(
            username="emailuser",
            email="e@x.com",
            is_email_verified=True,
        )
        self._auth(user)
        response = self.client.get(reverse("password_methods"))
        methods = [m["method"] for m in response.data["methods"]]
        self.assertIn("email", methods)
        email_method = next(
            m for m in response.data["methods"] if m["method"] == "email"
        )
        self.assertIn("target", email_method)
        self.assertIn("***", email_method["target"])

    def test_methods_with_verified_phone(self):
        user = User.objects.create_user(
            username="phoneuser2",
            phone="+79991234567",
            is_phone_verified=True,
        )
        self._auth(user)
        response = self.client.get(reverse("password_methods"))
        methods = [m["method"] for m in response.data["methods"]]
        self.assertIn("phone", methods)

    def test_methods_unverified_email_excluded(self):
        user = User.objects.create_user(
            username="unverified",
            email="u@x.com",
            is_email_verified=False,
        )
        self._auth(user)
        response = self.client.get(reverse("password_methods"))
        methods = [m["method"] for m in response.data["methods"]]
        self.assertNotIn("email", methods)


# =============================================================================
# Password Change (direct) Tests
# =============================================================================


@override_settings(URL_PREFIX="")
class PasswordChangeDirectTests(APITestCase):
    """Tests for POST /password/change/"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="changeuser",
            password="oldpass123",
        )
        access, _ = create_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def test_change_success(self):
        response = self.client.post(
            reverse("password_change"),
            {
                "old_password": "oldpass123",
                "new_password": "newpass456!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "password_changed")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("newpass456!"))

    def test_change_wrong_old_password(self):
        response = self.client.post(
            reverse("password_change"),
            {
                "old_password": "wrongpass",
                "new_password": "newpass456!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["localizable_error"], "error.400.wrong_password")

    def test_change_no_password_set(self):
        user = User.objects.create_user(username="nopw2")
        user.set_unusable_password()
        user.save()
        access, _ = create_token_for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        response = self.client.post(
            reverse("password_change"),
            {
                "old_password": "whatever",
                "new_password": "newpass456!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["localizable_error"], "error.400.no_password")

    def test_change_requires_auth(self):
        self.client.credentials()
        response = self.client.post(
            reverse("password_change"),
            {
                "old_password": "oldpass123",
                "new_password": "newpass456!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# =============================================================================
# Password Change via OTP Tests
# =============================================================================


@override_settings(URL_PREFIX="")
class PasswordChangeOtpTests(APITestCase):
    """Tests for POST /password/change/otp/request/ and /verify/"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="otpchangeuser",
            email="otp@example.com",
            phone="+79991112233",
            is_email_verified=True,
            is_phone_verified=True,
        )
        access, _ = create_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    @patch("stapel_auth.services.EmailVerificationService.send_verification_code")
    def test_request_otp_email(self, mock_send):
        mock_send.return_value = MagicMock()
        response = self.client.post(
            reverse("password_change_otp_request"), {"method": "email"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("target", response.data)
        self.assertIn("***", response.data["target"])

    @patch("stapel_auth.services.PhoneVerificationService.send_verification_code")
    def test_request_otp_phone(self, mock_send):
        mock_send.return_value = MagicMock()
        response = self.client.post(
            reverse("password_change_otp_request"), {"method": "phone"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_request_otp_no_verified_email(self):
        user = User.objects.create_user(
            username="noemail",
            email="no@x.com",
            is_email_verified=False,
        )
        access, _ = create_token_for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        response = self.client.post(
            reverse("password_change_otp_request"), {"method": "email"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["localizable_error"], "error.400.no_verified_contact"
        )

    def test_request_otp_invalid_method(self):
        response = self.client.post(
            reverse("password_change_otp_request"), {"method": "fax"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_verify_otp_email_success(self, mock_verify):
        mock_verify.return_value = {"success": True}
        response = self.client.post(
            reverse("password_change_otp_verify"),
            {
                "method": "email",
                "code": "1234",
                "new_password": "brandnew456!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "password_changed")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("brandnew456!"))

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_verify_otp_wrong_code(self, mock_verify):
        mock_verify.return_value = {"error": "invalid_code", "attempts_remaining": 2}
        response = self.client.post(
            reverse("password_change_otp_verify"),
            {
                "method": "email",
                "code": "0000",
                "new_password": "brandnew456!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["localizable_error"], "error.400.invalid_code_attempts"
        )
        self.assertEqual(response.data["params"]["attempts_remaining"], 2)

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_verify_otp_expired_code(self, mock_verify):
        mock_verify.return_value = {"error": "expired"}
        response = self.client.post(
            reverse("password_change_otp_verify"),
            {
                "method": "email",
                "code": "1234",
                "new_password": "brandnew456!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["localizable_error"], "error.400.code_expired")

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_verify_otp_rate_limited(self, mock_verify):
        mock_verify.return_value = {"error": "rate_limit", "retry_after": 30}
        response = self.client.post(
            reverse("password_change_otp_verify"),
            {
                "method": "email",
                "code": "1234",
                "new_password": "brandnew456!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_change_otp_requires_auth(self):
        self.client.credentials()
        response = self.client.post(
            reverse("password_change_otp_request"), {"method": "email"}
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# =============================================================================
# Password Reset via Email Tests
# =============================================================================


@override_settings(URL_PREFIX="")
class PasswordResetEmailTests(APITestCase):
    """Tests for /password/reset/email/request/ and /verify/"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="resetuser",
            email="reset@example.com",
            password="oldpass",
            is_email_verified=True,
        )

    @patch("stapel_auth.services.EmailVerificationService.send_verification_code")
    def test_request_success(self, mock_send):
        mock_send.return_value = MagicMock()
        response = self.client.post(
            reverse("password_reset_email_request"),
            {
                "email": "reset@example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("target", response.data)
        self.assertIn("***", response.data["target"])

    def test_request_nonexistent_email(self):
        response = self.client.post(
            reverse("password_reset_email_request"),
            {
                "email": "nobody@example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data["localizable_error"], "error.404.user_for_reset")

    def test_request_unverified_email(self):
        User.objects.create_user(
            username="unverified2",
            email="unverified@example.com",
            is_email_verified=False,
        )
        response = self.client.post(
            reverse("password_reset_email_request"),
            {
                "email": "unverified@example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_request_invalid_email_format(self):
        response = self.client.post(
            reverse("password_reset_email_request"),
            {
                "email": "not-an-email",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_verify_success_logs_in_user(self, mock_verify):
        mock_verify.return_value = {"success": True}
        response = self.client.post(
            reverse("password_reset_email_verify"),
            {
                "email": "reset@example.com",
                "code": "1234",
                "new_password": "freshpass789!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "LOGGED_IN")
        self.assertIn("access", response.data["tokens"])
        self.assertIn("refresh", response.data["tokens"])
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("freshpass789!"))

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_verify_sets_cookies(self, mock_verify):
        mock_verify.return_value = {"success": True}
        response = self.client.post(
            reverse("password_reset_email_verify"),
            {
                "email": "reset@example.com",
                "code": "1234",
                "new_password": "freshpass789!",
            },
        )
        self.assertIn("stapel_jwt", response.cookies)

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_verify_wrong_code(self, mock_verify):
        mock_verify.return_value = {"error": "invalid_code"}
        response = self.client.post(
            reverse("password_reset_email_verify"),
            {
                "email": "reset@example.com",
                "code": "9999",
                "new_password": "freshpass789!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["localizable_error"], "error.400.invalid_code")

    @patch("stapel_auth.services.EmailVerificationService.verify_code")
    def test_verify_blocked(self, mock_verify):
        mock_verify.return_value = {"error": "blocked", "retry_after": 300}
        response = self.client.post(
            reverse("password_reset_email_verify"),
            {
                "email": "reset@example.com",
                "code": "1234",
                "new_password": "freshpass789!",
            },
        )
        self.assertEqual(response.status_code, 422)


# =============================================================================
# Password Reset via Phone Tests
# =============================================================================


@override_settings(URL_PREFIX="")
class PasswordResetPhoneTests(APITestCase):
    """Tests for /password/reset/phone/request/ and /verify/"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="phonereset",
            phone="+79991234560",
            password="oldpass",
            is_phone_verified=True,
        )

    @patch("stapel_auth.services.PhoneVerificationService.send_verification_code")
    def test_request_success(self, mock_send):
        mock_send.return_value = MagicMock()
        response = self.client.post(
            reverse("password_reset_phone_request"),
            {
                "phone": "+79991234560",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("target", response.data)
        self.assertIn("***", response.data["target"])

    def test_request_nonexistent_phone(self):
        response = self.client.post(
            reverse("password_reset_phone_request"),
            {
                "phone": "+79990000000",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data["localizable_error"], "error.404.user_for_reset")

    def test_request_invalid_phone_format(self):
        response = self.client.post(
            reverse("password_reset_phone_request"),
            {
                "phone": "12345",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("stapel_auth.services.PhoneVerificationService.verify_code")
    def test_verify_success_logs_in_user(self, mock_verify):
        mock_verify.return_value = {"success": True}
        response = self.client.post(
            reverse("password_reset_phone_verify"),
            {
                "phone": "+79991234560",
                "code": "1234",
                "new_password": "freshpass789!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "LOGGED_IN")
        self.assertIn("access", response.data["tokens"])
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("freshpass789!"))

    @patch("stapel_auth.services.PhoneVerificationService.verify_code")
    def test_verify_wrong_code(self, mock_verify):
        mock_verify.return_value = {"error": "invalid_code", "attempts_remaining": 1}
        response = self.client.post(
            reverse("password_reset_phone_verify"),
            {
                "phone": "+79991234560",
                "code": "9999",
                "new_password": "freshpass789!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["params"]["attempts_remaining"], 1)


# =============================================================================
# Mock Admin OTP Block Tests
# =============================================================================


@override_settings(URL_PREFIX="", USE_MOCK_EMAIL_OTP=True, USE_MOCK_SMS_OTP=True)
class MockAdminOtpBlockTests(APITestCase):
    """Admin accounts must be blocked from OTP password flows in mock mode."""

    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_user(
            username="mockadmin",
            email="mockadmin@example.com",
            phone="+79990001111",
            password="adminpass",
            is_staff=True,
            is_email_verified=True,
            is_phone_verified=True,
        )
        self.superuser = User.objects.create_superuser(
            username="superadmin",
            email="superadmin@example.com",
            phone="+79990002222",
            password="superpass",
        )
        self.regular = User.objects.create_user(
            username="regular2",
            email="regular2@example.com",
            phone="+79990003333",
            password="regularpass",
            is_email_verified=True,
            is_phone_verified=True,
        )

    def _auth(self, user):
        access, _ = create_token_for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def test_staff_blocked_change_otp_request(self):
        self._auth(self.admin)
        response = self.client.post(
            reverse("password_change_otp_request"), {"method": "email"}
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["localizable_error"], "error.403.mock_otp_admin")

    def test_superuser_blocked_change_otp_request_phone(self):
        self._auth(self.superuser)
        response = self.client.post(
            reverse("password_change_otp_request"), {"method": "phone"}
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_regular_user_not_blocked(self):
        self._auth(self.regular)
        with patch(
            "stapel_auth.services.EmailVerificationService.send_verification_code"
        ) as m:
            m.return_value = MagicMock()
            response = self.client.post(
                reverse("password_change_otp_request"), {"method": "email"}
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_admin_reset_request_blocked(self):
        response = self.client.post(
            reverse("password_reset_email_request"),
            {
                "email": "mockadmin@example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["localizable_error"], "error.403.mock_otp_admin")

    def test_superuser_phone_reset_blocked(self):
        self.superuser.phone = "+79990002222"
        self.superuser.is_phone_verified = True
        self.superuser.save()
        response = self.client.post(
            reverse("password_reset_phone_request"),
            {
                "phone": "+79990002222",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_regular_reset_not_blocked(self):
        with patch(
            "stapel_auth.services.EmailVerificationService.send_verification_code"
        ) as m:
            m.return_value = MagicMock()
            response = self.client.post(
                reverse("password_reset_email_request"),
                {
                    "email": "regular2@example.com",
                },
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)


# =============================================================================
# QR Auth Tests
# =============================================================================


@override_settings(URL_PREFIX="")
class QRAuthGenerateTests(APITestCase):
    """Tests for POST /qr/generate/"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="qruser", password="pass")
        access, _ = create_token_for_user(self.user)
        self.token = access

    def _auth(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def test_generate_login_request_no_auth(self):
        response = self.client.post(reverse("qr_generate"), {"type": "login_request"})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("key", response.data)
        self.assertIn("scan_url", response.data)
        self.assertIn("scan", response.data["scan_url"])
        self.assertEqual(response.data["type"], "login_request")
        self.assertEqual(response.data["expires_in"], 300)

    def test_generate_session_share_requires_auth(self):
        response = self.client.post(reverse("qr_generate"), {"type": "session_share"})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            response.data["localizable_error"], "error.401.qr_auth_required"
        )

    def test_generate_session_share_with_auth(self):
        self._auth()
        response = self.client.post(reverse("qr_generate"), {"type": "session_share"})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["type"], "session_share")

    def test_generate_with_redirect_url(self):
        self._auth()
        response = self.client.post(
            reverse("qr_generate"),
            {
                "type": "session_share",
                "redirect_url": "/home",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_generate_absolute_redirect_url_rejected(self):
        self._auth()
        response = self.client.post(
            reverse("qr_generate"),
            {
                "type": "session_share",
                "redirect_url": "https://app.example.com/home",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_generate_invalid_type(self):
        response = self.client.post(reverse("qr_generate"), {"type": "invalid"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_generate_missing_type(self):
        response = self.client.post(reverse("qr_generate"), {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


@override_settings(URL_PREFIX="")
class QRAuthStatusTests(APITestCase):
    """Tests for GET /qr/<key>/status/"""

    def setUp(self):
        self.client = APIClient()

    def _generate_key(self, qr_type="login_request"):
        response = self.client.post(reverse("qr_generate"), {"type": qr_type})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        return response.data["key"]

    def test_status_pending(self):
        key = self._generate_key()
        response = self.client.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "pending")
        self.assertIsNone(response.data["access_token"])

    def test_status_expired_for_unknown_key(self):
        response = self.client.get(
            reverse("qr_status", kwargs={"key": "nonexistent_key_xyz"})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "expired")

    def test_status_fulfilled_after_confirm(self):
        user = User.objects.create_user(username="confirmuser", password="pass")
        access, _ = create_token_for_user(user)

        # Generate login_request key
        key = self._generate_key("login_request")

        # Confirm as logged-in user
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        confirm_resp = self.client.post(reverse("qr_confirm", kwargs={"key": key}))
        self.assertEqual(confirm_resp.status_code, status.HTTP_200_OK)

        # Poll status — should be fulfilled with tokens
        self.client.credentials()
        status_resp = self.client.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(status_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(status_resp.data["status"], "fulfilled")
        self.assertIsNotNone(status_resp.data["access_token"])
        self.assertIsNotNone(status_resp.data["refresh_token"])


@override_settings(URL_PREFIX="")
class QRAuthConfirmTests(APITestCase):
    """Tests for POST /qr/<key>/confirm/"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="confirmuser2", password="pass")
        access, _ = create_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def _generate_key(self, qr_type="login_request"):
        anon_client = APIClient()
        response = anon_client.post(reverse("qr_generate"), {"type": qr_type})
        return response.data["key"]

    def test_confirm_login_request_success(self):
        key = self._generate_key("login_request")
        response = self.client.post(reverse("qr_confirm", kwargs={"key": key}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "confirmed")

    def test_confirm_nonexistent_key(self):
        response = self.client.post(reverse("qr_confirm", kwargs={"key": "badkey"}))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data["localizable_error"], "error.404.qr_not_found")

    def test_confirm_wrong_type_session_share(self):
        user2 = User.objects.create_user(username="owner2", password="pass")
        access2, _ = create_token_for_user(user2)
        owner_client = APIClient()
        owner_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access2}")
        resp = owner_client.post(reverse("qr_generate"), {"type": "session_share"})
        key = resp.data["key"]

        response = self.client.post(reverse("qr_confirm", kwargs={"key": key}))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["localizable_error"], "error.400.qr_type_required"
        )

    def test_confirm_already_fulfilled(self):
        key = self._generate_key("login_request")
        self.client.post(reverse("qr_confirm", kwargs={"key": key}))
        response = self.client.post(reverse("qr_confirm", kwargs={"key": key}))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["localizable_error"], "error.400.qr_fulfilled")

    def test_confirm_requires_auth(self):
        key = self._generate_key("login_request")
        anon = APIClient()
        response = anon.post(reverse("qr_confirm", kwargs={"key": key}))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


@override_settings(URL_PREFIX="")
class QRAuthScanTests(APITestCase):
    """Tests for GET /qr/<key>/scan/ (browser redirect endpoint)"""

    def setUp(self):
        self.client = APIClient()
        self.owner = User.objects.create_user(
            username="scanowner",
            password="pass",
            email="owner@x.com",
        )
        access, _ = create_token_for_user(self.owner)
        self.owner_token = access

    def _generate_session_share_key(self, allow_unauthenticated_scanner=False):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {self.owner_token}")
        payload = {
            "type": "session_share",
            "redirect_url": "/",
        }
        if allow_unauthenticated_scanner:
            payload["allow_unauthenticated_scanner"] = True
        resp = c.post(reverse("qr_generate"), payload)
        return resp.data["key"]

    def _generate_login_request_key(self):
        c = APIClient()
        resp = c.post(reverse("qr_generate"), {"type": "login_request"})
        return resp.data["key"]

    def test_scan_nonexistent_key_returns_404(self):
        response = self.client.get(reverse("qr_scan", kwargs={"key": "badkey"}))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_scan_session_share_unauthenticated_redirects(self):
        # Opt-in required: only a QR generated with
        # allow_unauthenticated_scanner hands the session to an anonymous scanner.
        key = self._generate_session_share_key(allow_unauthenticated_scanner=True)
        response = self.client.get(
            reverse("qr_scan", kwargs={"key": key}), follow=False
        )
        self.assertIn(response.status_code, [301, 302])
        self.assertIn("stapel_jwt", response.cookies)

    def test_scan_session_share_unauthenticated_default_forbidden(self):
        key = self._generate_session_share_key()
        response = self.client.get(
            reverse("qr_scan", kwargs={"key": key}), follow=False
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data["localizable_error"], "error.403.qr_unauth_scan"
        )

    def test_scan_session_share_same_user_redirects(self):
        key = self._generate_session_share_key()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.owner_token}")
        response = self.client.get(
            reverse("qr_scan", kwargs={"key": key}), follow=False
        )
        self.assertIn(response.status_code, [301, 302])
        self.assertNotIn("qr_status=account_conflict", response.get("Location", ""))

    def test_scan_session_share_different_user_conflict(self):
        key = self._generate_session_share_key()
        other = User.objects.create_user(username="otherscan", password="pass")
        access, _ = create_token_for_user(other)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        response = self.client.get(
            reverse("qr_scan", kwargs={"key": key}), follow=False
        )
        self.assertIn(response.status_code, [301, 302])
        self.assertIn("error=account_conflict", response.get("Location", ""))

    def test_scan_login_request_authenticated_redirects_to_confirm(self):
        key = self._generate_login_request_key()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.owner_token}")
        response = self.client.get(
            reverse("qr_scan", kwargs={"key": key}), follow=False
        )
        self.assertIn(response.status_code, [301, 302])
        self.assertIn("qr-confirm", response.get("Location", ""))
        self.assertIn(key, response.get("Location", ""))

    def test_scan_login_request_unauthenticated_redirects_to_signin(self):
        key = self._generate_login_request_key()
        response = self.client.get(
            reverse("qr_scan", kwargs={"key": key}), follow=False
        )
        self.assertIn(response.status_code, [301, 302])
        self.assertIn("sign-in", response.get("Location", ""))

    def test_scan_fulfilled_key_returns_400(self):
        key = self._generate_login_request_key()
        # confirm it first
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.owner_token}")
        self.client.post(reverse("qr_confirm", kwargs={"key": key}))
        response = self.client.get(reverse("qr_scan", kwargs={"key": key}))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["localizable_error"], "error.400.qr_fulfilled")
