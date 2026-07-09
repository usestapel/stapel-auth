"""Final coverage gaps: model __str__/save defaults, URL factory gates,
token-obtain/refresh legacy branches, logout revoke fault-injection,
password lockout/register branches and verification factor resolution.
"""
import uuid
from datetime import timedelta, datetime, timezone as dt_timezone
from unittest.mock import patch

import jwt as pyjwt
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from stapel_core.django.jwt.provider import jwt_provider

User = get_user_model()


def _make_user(**kwargs):
    defaults = dict(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


# =============================================================================
# models.py — __str__, save() defaults, is_expired
# =============================================================================


class ModelDunderTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def test_phone_verification_save_defaults_expiry(self):
        from stapel_auth.models import PhoneVerification

        v = PhoneVerification.objects.create(phone="+15550001111", code="1234")
        self.assertIsNotNone(v.expires_at)
        self.assertGreater(v.expires_at, timezone.now())

    def test_email_verification_save_defaults_expiry(self):
        from stapel_auth.models import EmailVerification

        v = EmailVerification.objects.create(email="x@example.com", code="1234")
        self.assertIsNotNone(v.expires_at)
        self.assertGreater(v.expires_at, timezone.now())

    def test_refresh_token_tracker_str(self):
        from stapel_auth.models import RefreshTokenTracker

        t = RefreshTokenTracker.objects.create(
            user=self.user,
            token=uuid.uuid4().hex,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.assertIn(str(self.user), str(t))

    def test_user_session_str_and_is_expired(self):
        from stapel_auth.models import UserSession

        live = UserSession.objects.create(
            user=self.user,
            jti=uuid.uuid4().hex,
            device_name="Chrome on Mac",
            expires_at=timezone.now() + timedelta(days=1),
        )
        stale = UserSession.objects.create(
            user=self.user,
            jti=uuid.uuid4().hex,
            expires_at=timezone.now() - timedelta(days=1),
        )
        self.assertIn("Chrome on Mac", str(live))
        self.assertIn("unknown device", str(stale))
        self.assertFalse(live.is_expired)
        self.assertTrue(stale.is_expired)

    def test_totp_device_str(self):
        from stapel_auth.models import TOTPDevice

        device = TOTPDevice.objects.create(user=self.user, secret="S" * 32)
        self.assertIn("pending", str(device))
        device.is_active = True
        self.assertIn("active", str(device))

    def test_sso_model_strs(self):
        from stapel_auth.models import Organization, OrgMembership, SSOConfig

        org = Organization.objects.create(
            name="Acme Corp", slug="acmecorp", domain="acmecorp.com"
        )
        config = SSOConfig.objects.create(
            org=org, protocol=SSOConfig.PROTOCOL_SAML, is_active=True
        )
        membership = OrgMembership.objects.create(user=self.user, org=org)
        self.assertEqual(str(org), "Acme Corp (acmecorp)")
        self.assertIn("acmecorp", str(config))
        self.assertIn("acmecorp", str(membership))

    def test_verification_preference_str(self):
        from stapel_auth.models import VerificationPreference

        pref = VerificationPreference.objects.create(
            user=self.user, scope="sensitive", enabled=True
        )
        self.assertIn("on", str(pref))
        pref.enabled = False
        self.assertIn("off", str(pref))


# =============================================================================
# urls.py — factory gates (enabled=False -> [])
# =============================================================================


class UrlFactoryGateTests(TestCase):
    def test_every_factory_returns_empty_when_disabled(self):
        from stapel_auth import urls as auth_urls

        factories = [
            auth_urls.get_otp_urls,
            auth_urls.get_anonymous_urls,
            auth_urls.get_password_urls,
            auth_urls.get_oauth_urls,
            auth_urls.get_sso_urls,
            auth_urls.get_mfa_urls,
            auth_urls.get_qr_urls,
            auth_urls.get_magic_link_urls,
            auth_urls.get_sessions_urls,
            auth_urls.get_admin_api_urls,
            auth_urls.get_security_urls,
            auth_urls.get_openid_urls,
            auth_urls.get_verification_urls,
        ]
        for factory in factories:
            with self.subTest(factory=factory.__name__):
                self.assertEqual(factory(enabled=False), [])

    def test_every_factory_returns_patterns_when_enabled(self):
        from stapel_auth import urls as auth_urls

        for name in auth_urls.__all__:
            if not name.startswith("get_"):
                continue
            with self.subTest(factory=name):
                self.assertTrue(getattr(auth_urls, name)(enabled=True))


# =============================================================================
# sessions/views.py — inactive user on token obtain, legacy no-jti refresh
# =============================================================================


class TokenObtainInactiveUserTests(APITestCase):
    def test_inactive_user_from_custom_backend_gets_401_disabled(self):
        # ModelBackend never returns inactive users, but a host may install a
        # backend that does (e.g. AllowAllUsersModelBackend) — the view-level
        # guard is the contract for that configuration.
        user = _make_user(is_active=False)
        with patch(
            "stapel_auth.sessions.views.authenticate", return_value=user
        ):
            resp = self.client.post(
                reverse("token_obtain_pair"),
                {"username": user.username, "password": "testpass123"},
                format="json",
            )
        self.assertEqual(resp.status_code, 401)


class LegacyNoJtiRefreshTests(APITestCase):
    """Refresh tokens minted before session tracking carry no jti claim —
    the refresh endpoint keeps the old refresh token and only re-issues the
    access token (no session rotation)."""

    def _legacy_refresh_token(self, user):
        from django.conf import settings

        now = datetime.now(dt_timezone.utc)
        payload = {
            "user_id": str(user.id),
            "token_type": "refresh",
            "iat": now,
            "exp": now + timedelta(days=7),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
        }
        return pyjwt.encode(
            payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )

    def test_refresh_with_legacy_token_reuses_refresh(self):
        user = _make_user()
        legacy = self._legacy_refresh_token(user)
        resp = self.client.post(
            reverse("token_refresh"), {"refresh": legacy}, format="json"
        )
        self.assertEqual(resp.status_code, 200, resp.data)
        self.assertEqual(resp.data["refresh"], legacy)
        self.assertTrue(resp.data["access"])


# =============================================================================
# otp/views.py — logout swallows session-revoke failures
# =============================================================================


class LogoutRevokeFaultTests(APITestCase):
    def test_logout_swallows_revoke_by_jti_failure(self):
        user = _make_user()
        access, refresh = jwt_provider.create_tokens(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        with patch(
            "stapel_auth.sessions.services.SessionService.revoke_by_jti",
            side_effect=Exception("db down"),
        ):
            resp = self.client.post(
                reverse("logout"), {"refresh_token": refresh}, format="json"
            )
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# password/views.py — lockout branches + register validation branches
# =============================================================================


@override_settings(STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True})
class PasswordLoginLockoutTests(APITestCase):
    def test_locked_identifier_gets_423(self):
        with patch(
            "stapel_auth.services.LockoutService.check", return_value=(True, 60)
        ):
            resp = self.client.post(
                reverse("password_login"),
                {"login": "someone@example.com", "password": "x" * 8},
                format="json",
            )
        self.assertEqual(resp.status_code, 423)

    def test_failure_crossing_threshold_gets_423(self):
        with patch(
            "stapel_auth.services.LockoutService.check", return_value=(False, 0)
        ), patch(
            "stapel_auth.services.PasswordService.login", return_value=None
        ), patch(
            "stapel_auth.services.LockoutService.record_failure", return_value=20
        ), patch(
            "stapel_auth.services.LockoutService.apply_lockout", return_value=3600
        ):
            resp = self.client.post(
                reverse("password_login"),
                {"login": "someone@example.com", "password": "x" * 8},
                format="json",
            )
        self.assertEqual(resp.status_code, 423)


@override_settings(STAPEL_AUTH={"AUTH_PASSWORD_REGISTRATION": True})
class PasswordRegisterBranchTests(APITestCase):
    def test_weak_password_rejected_by_validators(self):
        # conftest configures no AUTH_PASSWORD_VALIDATORS, so inject the
        # rejection at the validate_password seam (imported inside the view).
        with patch(
            "django.contrib.auth.password_validation.validate_password",
            side_effect=ValidationError(["too weak"]),
        ):
            resp = self.client.post(
                reverse("password_register"),
                {"email": "new@example.com", "password": "weakweak"},
                format="json",
            )
        self.assertEqual(resp.status_code, 400)

    def test_phone_already_taken_gets_409(self):
        _make_user(phone="+14155552671")
        resp = self.client.post(
            reverse("password_register"),
            {"phone": "+14155552671", "password": "strongpass123"},
            format="json",
        )
        self.assertEqual(resp.status_code, 409)


# =============================================================================
# verification/views.py — factor resolution + verify crash branches
# =============================================================================


class _StubFactor:
    id = "stub_factor"

    def __init__(self, available=True, verify_exc=None):
        self._available = available
        self._verify_exc = verify_exc

    def available_for(self, user):
        return self._available

    def initiate(self, user, challenge):
        return {}

    def verify(self, user, challenge, payload):
        if self._verify_exc:
            raise self._verify_exc
        return True


class VerificationFactorBranchTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        access, _ = jwt_provider.create_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def _challenge(self, factors):
        from stapel_core.verification import create_challenge

        challenge = create_challenge(self.user, "sensitive", factors, 300)
        return challenge["challenge_id"]

    def _complete(self, challenge_id, factor):
        return self.client.post(
            reverse("verification_complete", kwargs={"challenge_id": challenge_id}),
            {"factor": factor, "code": "0000"},
            format="json",
        )

    def test_unregistered_factor_returns_400(self):
        challenge_id = self._challenge(["ghost_factor"])
        resp = self._complete(challenge_id, "ghost_factor")
        self.assertEqual(resp.status_code, 400)

    def test_unavailable_factor_returns_400(self):
        from stapel_core.verification import factor_registry

        challenge_id = self._challenge(["stub_factor"])
        with patch.object(
            factor_registry, "get", return_value=_StubFactor(available=False)
        ):
            resp = self._complete(challenge_id, "stub_factor")
        self.assertEqual(resp.status_code, 400)

    def test_factor_verify_crash_counts_as_failure(self):
        from stapel_core.verification import factor_registry

        challenge_id = self._challenge(["stub_factor"])
        with patch.object(
            factor_registry,
            "get",
            return_value=_StubFactor(verify_exc=RuntimeError("boom")),
        ):
            resp = self._complete(challenge_id, "stub_factor")
        self.assertEqual(resp.status_code, 400)
