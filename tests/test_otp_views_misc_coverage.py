"""Coverage tests for otp/views.py, qr/*, tasks.py, utils.py, permissions.py, apps.py.

Adds only the missing branches on top of the existing suite (test_auth.py,
test_extra.py, test_upgrade.py). Mock OTP code is "0000" (conftest).
"""
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase

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
# _sanitize_redirect_after + _notify_user_registered + helpers
# =============================================================================


class SanitizeRedirectAfterTests(TestCase):
    def test_empty_returns_empty(self):
        from stapel_auth.otp.views import _sanitize_redirect_after

        self.assertEqual(_sanitize_redirect_after(""), "")

    def test_relative_path_allowed(self):
        from stapel_auth.otp.views import _sanitize_redirect_after

        self.assertEqual(_sanitize_redirect_after("/dashboard"), "/dashboard")

    def test_protocol_relative_rejected(self):
        from stapel_auth.otp.views import _sanitize_redirect_after

        self.assertEqual(_sanitize_redirect_after("//evil.com"), "")

    @override_settings(FRONTEND_URL="http://localhost:3000")
    def test_same_origin_absolute_allowed(self):
        from stapel_auth.conf import auth_settings
        from stapel_auth.otp.views import _sanitize_redirect_after

        auth_settings.reload()
        self.assertEqual(
            _sanitize_redirect_after("http://localhost:3000/ok"),
            "http://localhost:3000/ok",
        )

    @override_settings(FRONTEND_URL="http://localhost:3000")
    def test_foreign_origin_rejected(self):
        from stapel_auth.conf import auth_settings
        from stapel_auth.otp.views import _sanitize_redirect_after

        auth_settings.reload()
        self.assertEqual(_sanitize_redirect_after("https://evil.example/x"), "")

    @override_settings(FRONTEND_URL="")
    def test_absolute_url_rejected_when_no_frontend_configured(self):
        from stapel_auth.conf import auth_settings
        from stapel_auth.otp.views import _sanitize_redirect_after

        auth_settings.reload()
        try:
            self.assertEqual(_sanitize_redirect_after("https://x.example/y"), "")
        finally:
            auth_settings.reload()


class NotifyUserRegisteredTests(TestCase):
    def test_signal_exception_swallowed(self):
        from stapel_auth.otp.views import _notify_user_registered

        user = _make_user()
        with patch(
            "stapel_core.signals.user_registered.send",
            side_effect=Exception("boom"),
        ):
            # Must not raise
            _notify_user_registered(user)


class GetClientIpAndLogAttemptTests(TestCase):
    def _view(self):
        from stapel_auth.otp.views import AuthViewSet

        return AuthViewSet()

    def test_get_client_ip_from_forwarded_header(self):
        rf = RequestFactory()
        req = rf.get("/", HTTP_X_FORWARDED_FOR="1.2.3.4, 5.6.7.8")
        self.assertEqual(self._view().get_client_ip(req), "1.2.3.4")

    def test_get_client_ip_from_remote_addr(self):
        rf = RequestFactory()
        req = rf.get("/", REMOTE_ADDR="9.9.9.9")
        self.assertEqual(self._view().get_client_ip(req), "9.9.9.9")

    def test_log_login_attempt_swallows_exception(self):
        rf = RequestFactory()
        req = rf.get("/")
        with patch(
            "stapel_auth.models.LoginAttempt.objects.create",
            side_effect=Exception("db down"),
        ):
            # Must not raise
            self._view().log_login_attempt("x@y.com", "failed", req)


# =============================================================================
# Email / Phone request + verify error branches
# =============================================================================

_EVS = "stapel_auth.otp.services.EmailVerificationService"
_PVS = "stapel_auth.otp.services.PhoneVerificationService"
_LOCK = "stapel_auth.security.services.LockoutService"


class EmailRequestVerifyBranchTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_email_request_rate_limit_returns_429(self):
        with patch(
            f"{_EVS}.send_verification_code",
            return_value={"error": "rate_limit", "retry_after": 30},
        ):
            resp = self.client.post(
                reverse("email_request"), {"email": "rl@example.com"}
            )
        self.assertEqual(resp.status_code, 429)

    def test_email_request_blocked_returns_422(self):
        with patch(
            f"{_EVS}.send_verification_code",
            return_value={"error": "blocked", "retry_after": 60},
        ):
            resp = self.client.post(
                reverse("email_request"), {"email": "bl@example.com"}
            )
        self.assertEqual(resp.status_code, 422)

    def test_email_request_unknown_dict_returns_500(self):
        with patch(
            f"{_EVS}.send_verification_code",
            return_value={"error": "server_error"},
        ):
            resp = self.client.post(
                reverse("email_request"), {"email": "se@example.com"}
            )
        self.assertEqual(resp.status_code, 500)

    def test_email_verify_invalid_payload(self):
        # Missing code -> serializer raises 400 (exercises is_valid exit arc)
        resp = self.client.post(reverse("email_verify"), {"email": "a@b.com"})
        self.assertEqual(resp.status_code, 400)

    def test_email_verify_success_non_dict_result(self):
        with patch(f"{_EVS}.verify_code", return_value=True):
            resp = self.client.post(
                reverse("email_verify"),
                {"email": "nondict@example.com", "code": "0000"},
            )
        self.assertEqual(resp.status_code, 200)

    def test_email_verify_invalid_code_no_attempts_no_lock(self):
        with patch(f"{_EVS}.verify_code", return_value={"error": "invalid_code"}), \
             patch(f"{_LOCK}.apply_lockout", return_value=None):
            resp = self.client.post(
                reverse("email_verify"),
                {"email": "ic@example.com", "code": "9999"},
            )
        self.assertEqual(resp.status_code, 400)

    def test_email_verify_not_success_with_lockout(self):
        with patch(f"{_EVS}.verify_code", return_value={}), \
             patch(f"{_LOCK}.apply_lockout", return_value=600):
            resp = self.client.post(
                reverse("email_verify"),
                {"email": "ns1@example.com", "code": "9999"},
            )
        self.assertEqual(resp.status_code, 423)

    def test_email_verify_not_success_no_lockout(self):
        with patch(f"{_EVS}.verify_code", return_value={}), \
             patch(f"{_LOCK}.apply_lockout", return_value=None):
            resp = self.client.post(
                reverse("email_verify"),
                {"email": "ns2@example.com", "code": "9999"},
            )
        self.assertEqual(resp.status_code, 400)

    def test_email_verify_authenticated_email_belongs_to_other(self):
        me = _make_user()
        other = _make_user(email="taken@example.com")
        access, _ = _tokens(me)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        with patch(f"{_EVS}.verify_code", return_value={"success": True}):
            resp = self.client.post(
                reverse("email_verify"),
                {"email": other.email, "code": "0000"},
            )
        self.assertEqual(resp.status_code, 409)


class PhoneRequestVerifyBranchTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_phone_request_rate_limit_returns_429(self):
        with patch(
            f"{_PVS}.send_verification_code",
            return_value={"error": "rate_limit", "retry_after": 30},
        ):
            resp = self.client.post(
                reverse("phone_request"), {"phone": "+12025550111"}
            )
        self.assertEqual(resp.status_code, 429)

    def test_phone_request_unknown_dict_returns_500(self):
        with patch(
            f"{_PVS}.send_verification_code",
            return_value={"error": "server_error"},
        ):
            resp = self.client.post(
                reverse("phone_request"), {"phone": "+12025550112"}
            )
        self.assertEqual(resp.status_code, 500)

    def test_phone_verify_invalid_payload(self):
        resp = self.client.post(reverse("phone_verify"), {"phone": "+12025550113"})
        self.assertEqual(resp.status_code, 400)

    def test_phone_verify_success_non_dict_result(self):
        with patch(f"{_PVS}.verify_code", return_value=True):
            resp = self.client.post(
                reverse("phone_verify"),
                {"phone": "+12025550114", "code": "0000"},
            )
        self.assertEqual(resp.status_code, 200)

    def test_phone_verify_invalid_code_no_attempts_no_lock(self):
        with patch(f"{_PVS}.verify_code", return_value={"error": "invalid_code"}), \
             patch(f"{_LOCK}.apply_lockout", return_value=None):
            resp = self.client.post(
                reverse("phone_verify"),
                {"phone": "+12025550115", "code": "9999"},
            )
        self.assertEqual(resp.status_code, 400)

    def test_phone_verify_not_success_with_lockout(self):
        with patch(f"{_PVS}.verify_code", return_value={}), \
             patch(f"{_LOCK}.apply_lockout", return_value=600):
            resp = self.client.post(
                reverse("phone_verify"),
                {"phone": "+12025550116", "code": "9999"},
            )
        self.assertEqual(resp.status_code, 423)

    def test_phone_verify_not_success_no_lockout(self):
        with patch(f"{_PVS}.verify_code", return_value={}), \
             patch(f"{_LOCK}.apply_lockout", return_value=None):
            resp = self.client.post(
                reverse("phone_verify"),
                {"phone": "+12025550117", "code": "9999"},
            )
        self.assertEqual(resp.status_code, 400)

    def test_phone_verify_authenticated_phone_belongs_to_other(self):
        me = _make_user()
        _make_user(phone="+12025550199")
        access, _ = _tokens(me)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        with patch(f"{_PVS}.verify_code", return_value={"success": True}):
            resp = self.client.post(
                reverse("phone_verify"),
                {"phone": "+12025550199", "code": "0000"},
            )
        self.assertEqual(resp.status_code, 409)


def _tokens(user):
    from stapel_core.django.jwt.provider import jwt_provider

    return jwt_provider.create_tokens(user)


# =============================================================================
# Anonymous auth: reuse + device dedup
# =============================================================================


class AnonymousAuthBranchTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_reuses_existing_anonymous_session(self):
        anon = User.create_anonymous_user()
        access, _ = _tokens(anon)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        resp = self.client.post(reverse("anonymous"), {})
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(str(resp.data["user"]["id"]), str(anon.id))

    def test_device_id_reuses_cached_anonymous_user(self):
        anon = User.create_anonymous_user()
        cache.set("anon_device:dev-abc", str(anon.id), timeout=60)
        resp = self.client.post(
            reverse("anonymous"), {"device_id": "dev-abc"}
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(str(resp.data["user"]["id"]), str(anon.id))

    def test_device_id_cached_missing_user_creates_new(self):
        cache.set("anon_device:dev-gone", str(uuid.uuid4()), timeout=60)
        resp = self.client.post(
            reverse("anonymous"), {"device_id": "dev-gone"}
        )
        self.assertEqual(resp.status_code, 201)

    def test_anonymous_invalid_payload(self):
        # device_id over max_length -> serializer 400 (exercises is_valid exit arc)
        resp = self.client.post(
            reverse("anonymous"), {"device_id": "x" * 300}
        )
        self.assertEqual(resp.status_code, 400)


# =============================================================================
# OAuth login / authorize / callback edge branches
# =============================================================================

_OAUTH_DISABLED = {"AUTH_OAUTH_LOGIN": False, "AUTH_OAUTH_REGISTRATION": False}
_TEST_OAUTH = {
    "OAUTH_PROVIDERS": {"test": {"client_id": "cid", "client_secret": "sec"}},
}


class OAuthLoginBranchTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    @override_settings(STAPEL_AUTH=_OAUTH_DISABLED)
    def test_oauth_login_disabled_returns_403(self):
        from stapel_auth.conf import auth_settings

        auth_settings.reload()
        try:
            resp = self.client.post(
                reverse("oauth_login"),
                {"provider": "test", "access_token": "tok"},
            )
        finally:
            auth_settings.reload()
        self.assertEqual(resp.status_code, 403)

    def test_oauth_login_unverified_email_conflict_returns_400(self):
        from stapel_core.oauth import OAuthUserData

        _make_user(email="victim-oauth@example.com")
        data = OAuthUserData(
            id="oid-1",
            email="victim-oauth@example.com",
            username="x",
            avatar=None,
            email_verified=False,
        )
        with patch(
            "stapel_auth.oauth.services.OAuthService.get_user_data",
            return_value=data,
        ):
            resp = self.client.post(
                reverse("oauth_login"),
                {"provider": "test", "access_token": "tok"},
            )
        self.assertEqual(resp.status_code, 400)


@override_settings(URL_PREFIX="", DEBUG=True, STAPEL_AUTH=_TEST_OAUTH)
class OAuthAuthorizeCallbackBranchTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        from stapel_auth.conf import auth_settings
        from stapel_auth.oauth_providers import PROVIDER_REGISTRY, TestProvider

        PROVIDER_REGISTRY.setdefault("test", TestProvider())
        auth_settings.reload()

    def _store_state(self, provider="test", state="st-1", redirect_after=""):
        cache.set(
            f"oauth_state:{state}",
            {
                "provider": provider,
                "redirect_uri": "http://localhost:8000/api/v1/oauth/test/callback",
                "redirect_after": redirect_after,
            },
            timeout=600,
        )

    @override_settings(STAPEL_AUTH=_OAUTH_DISABLED)
    def test_authorize_disabled_returns_403(self):
        from stapel_auth.conf import auth_settings

        auth_settings.reload()
        try:
            resp = self.client.get(
                reverse("oauth_authorize", kwargs={"provider": "test"})
            )
        finally:
            auth_settings.reload()
        self.assertEqual(resp.status_code, 403)

    def test_callback_provider_not_in_registry_returns_400(self):
        # State provider matches URL provider, but provider isn't registered.
        self._store_state(provider="ghostprov", state="st-ghost")
        resp = self.client.get(
            reverse("oauth_callback", kwargs={"provider": "ghostprov"}),
            {"code": "valid-code", "state": "st-ghost"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_callback_provider_unconfigured_returns_400(self):
        from stapel_auth.oauth_providers import PROVIDER_REGISTRY, GoogleProvider

        PROVIDER_REGISTRY.setdefault("google", GoogleProvider())
        self._store_state(provider="google", state="st-goog")
        resp = self.client.get(
            reverse("oauth_callback", kwargs={"provider": "google"}),
            {"code": "valid-code", "state": "st-goog"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_callback_user_data_none_returns_400(self):
        self._store_state(state="st-nodata")
        with patch(
            "stapel_auth.oauth.services.OAuthService.get_user_data",
            return_value=None,
        ):
            resp = self.client.get(
                reverse("oauth_callback", kwargs={"provider": "test"}),
                {"code": "valid-code", "state": "st-nodata"},
            )
        self.assertEqual(resp.status_code, 400)

    @override_settings(OAUTH_STEP_UP=True)
    def test_callback_step_up_totp_disabled_issues_tokens(self):
        User.objects.create(
            email="test-oauth@example.com",
            oauth_provider="test",
            oauth_id="test-oauth-user-1",
            is_email_verified=True,
        )
        self._store_state(state="st-stepup1")
        with patch(
            "stapel_auth.mfa.services.TOTPService.is_enabled", return_value=False
        ):
            resp = self.client.get(
                reverse("oauth_callback", kwargs={"provider": "test"}),
                {"code": "valid-code", "state": "st-stepup1"},
            )
        self.assertEqual(resp.status_code, 200)

    @override_settings(OAUTH_STEP_UP=True)
    def test_callback_step_up_totp_challenge_with_redirect_after(self):
        User.objects.create(
            email="test-oauth@example.com",
            oauth_provider="test",
            oauth_id="test-oauth-user-1",
            is_email_verified=True,
        )
        self._store_state(state="st-stepup2", redirect_after="/dashboard")
        with patch("stapel_auth.mfa.services.TOTPService.is_enabled", return_value=True), \
             patch(
                 "stapel_auth.mfa.services.TOTPService.create_challenge",
                 return_value="chal-tok",
             ):
            resp = self.client.get(
                reverse("oauth_callback", kwargs={"provider": "test"}),
                {"code": "valid-code", "state": "st-stepup2"},
            )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("redirect_after", resp["Location"])


class ResolveOAuthUserAndCallbackUriTests(TestCase):
    def test_resolve_creates_user_when_no_email(self):
        from stapel_auth.otp.views import AuthViewSet

        class _Data:
            id = "no-email-oid"
            email = None
            avatar = None
            email_verified = False

        view = AuthViewSet()
        user = view._resolve_oauth_user("test", _Data())
        self.assertEqual(user.oauth_id, "no-email-oid")

    @override_settings(OAUTH_CALLBACK_BASE_URL="https://api.example.com", URL_PREFIX="")
    def test_build_callback_uri_uses_configured_base(self):
        from stapel_auth.otp.views import AuthViewSet

        rf = RequestFactory()
        req = rf.get("/")
        uri = AuthViewSet()._build_callback_uri(req, "test")
        self.assertEqual(uri, "https://api.example.com/api/v1/oauth/test/callback")


# =============================================================================
# Logout token-blacklist branches + me + verify_token
# =============================================================================

_DECODE = "stapel_core.core.jwt_handler.JWTHandler.decode_token"


class LogoutBranchTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def _future_exp(self):
        import time

        return int(time.time()) + 3600

    def _past_exp(self):
        import time

        return int(time.time()) - 3600

    def test_logout_access_payload_without_jti(self):
        self.client.cookies["stapel_jwt"] = "acc"
        with patch(_DECODE, return_value={"no": "jti"}):
            resp = self.client.post(reverse("logout"), {})
        self.assertEqual(resp.status_code, 200)

    def test_logout_access_no_exp(self):
        self.client.cookies["stapel_jwt"] = "acc"
        with patch(_DECODE, return_value={"jti": "abcd1234"}):
            resp = self.client.post(reverse("logout"), {})
        self.assertEqual(resp.status_code, 200)

    def test_logout_access_already_expired(self):
        self.client.cookies["stapel_jwt"] = "acc"
        with patch(_DECODE, return_value={"jti": "abcd1234", "exp": self._past_exp()}):
            resp = self.client.post(reverse("logout"), {})
        self.assertEqual(resp.status_code, 200)

    def test_logout_access_decode_raises(self):
        self.client.cookies["stapel_jwt"] = "acc"
        with patch(_DECODE, side_effect=Exception("bad token")):
            resp = self.client.post(reverse("logout"), {})
        self.assertEqual(resp.status_code, 200)

    def test_logout_refresh_no_exp(self):
        with patch(_DECODE, return_value={"jti": "refreshjti"}):
            resp = self.client.post(
                reverse("logout"), {"refresh_token": "reftok"}
            )
        self.assertEqual(resp.status_code, 200)

    def test_logout_refresh_already_expired(self):
        with patch(
            _DECODE, return_value={"jti": "refreshjti", "exp": self._past_exp()}
        ), patch("stapel_auth.sessions.services.SessionService.revoke_by_jti"):
            resp = self.client.post(
                reverse("logout"), {"refresh_token": "reftok"}
            )
        self.assertEqual(resp.status_code, 200)

    def test_logout_outer_exception_returns_500(self):
        with patch(
            "stapel_core.django.jwt.utils.extract_jwt_from_request",
            side_effect=Exception("kaboom"),
        ):
            resp = self.client.post(reverse("logout"), {})
        self.assertEqual(resp.status_code, 500)


class MeUnauthenticatedDirectTests(TestCase):
    """me() has permission_classes=[IsAuthenticated]; its internal 401 logging
    branch is only reachable by calling the handler directly."""

    def _call(self, **extra):
        from stapel_auth.otp.views import AuthViewSet

        rf = RequestFactory()
        req = rf.get("/me/", **extra)
        req.user = AnonymousUser()
        return AuthViewSet().me(req)

    def test_me_unauth_with_auth_header(self):
        resp = self._call(HTTP_AUTHORIZATION="Bearer abcdefghijklmnop")
        self.assertEqual(resp.status_code, 401)

    def test_me_unauth_with_jwt_cookie(self):
        from stapel_auth.otp.views import AuthViewSet

        rf = RequestFactory()
        req = rf.get("/me/")
        req.user = AnonymousUser()
        req.COOKIES["stapel_jwt"] = "cookievalue123456"
        resp = AuthViewSet().me(req)
        self.assertEqual(resp.status_code, 401)


class VerifyTokenBranchTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    _JP = "stapel_core.django.jwt.provider.jwt_provider"

    def test_verify_token_blacklisted_returns_401(self):
        with patch(f"{self._JP}.validate_token", return_value={"user_id": "x"}), \
             patch(f"{self._JP}.is_blacklisted", return_value=True):
            resp = self.client.post(reverse("verify_token"), {"token": "t"})
        self.assertEqual(resp.status_code, 401)

    def test_verify_token_user_not_found_returns_401(self):
        with patch(
            f"{self._JP}.validate_token",
            return_value={"user_id": str(uuid.uuid4())},
        ), patch(f"{self._JP}.is_blacklisted", return_value=False):
            resp = self.client.post(reverse("verify_token"), {"token": "t"})
        self.assertEqual(resp.status_code, 401)

    def test_verify_token_validate_raises_returns_401(self):
        with patch(
            f"{self._JP}.validate_token", side_effect=Exception("bad")
        ):
            resp = self.client.post(reverse("verify_token"), {"token": "t"})
        self.assertEqual(resp.status_code, 401)


# =============================================================================
# AuthenticatorChangeViewSet: _service_error_to_response + endpoint branches
# =============================================================================


class ServiceErrorToResponseTests(TestCase):
    def _map(self, result):
        from stapel_auth.otp.views import AuthenticatorChangeViewSet

        return AuthenticatorChangeViewSet()._service_error_to_response(result)

    def test_rate_limit(self):
        self.assertEqual(self._map({"error": "rate_limit", "retry_after": 30}).status_code, 429)

    def test_blocked(self):
        self.assertEqual(self._map({"error": "blocked", "retry_after": 60}).status_code, 422)

    def test_no_current_value(self):
        self.assertEqual(self._map({"error": "no_current_value"}).status_code, 400)

    def test_invalid_change_token(self):
        self.assertEqual(self._map({"error": "invalid_change_token"}).status_code, 400)

    def test_value_mismatch(self):
        self.assertEqual(self._map({"error": "value_mismatch"}).status_code, 400)

    def test_expired(self):
        self.assertEqual(self._map({"error": "expired"}).status_code, 400)

    def test_send_failed(self):
        self.assertEqual(self._map({"error": "send_failed"}).status_code, 500)

    def test_unknown_fallthrough(self):
        self.assertEqual(self._map({"error": "totally_unknown"}).status_code, 400)


_ACS = "stapel_auth.otp.services.AuthenticatorChangeService"


class AuthenticatorChangeEndpointBranchTests(APITestCase):
    def setUp(self):
        self.user = _make_user(phone="+12025550001")
        self.client = APIClient()
        access, _ = _tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def _tok(self):
        return str(uuid.uuid4())

    # ── failure paths → _service_error_to_response ──
    def test_phone_instant_request_old_failure(self):
        with patch(f"{_ACS}.request_old_otp", return_value={"error": "send_failed"}):
            resp = self.client.post(reverse("phone_instant_request_old"), {})
        self.assertEqual(resp.status_code, 500)

    def test_phone_instant_verify_new_failure(self):
        with patch(f"{_ACS}.verify_new_and_apply", return_value={"error": "value_mismatch"}):
            resp = self.client.post(
                reverse("phone_instant_verify_new"),
                {"phone": "+12025550002", "code": "0000", "change_token": self._tok()},
            )
        self.assertEqual(resp.status_code, 400)

    def test_email_instant_request_old_failure(self):
        with patch(f"{_ACS}.request_old_otp", return_value={"error": "send_failed"}):
            resp = self.client.post(reverse("email_instant_request_old"), {})
        self.assertEqual(resp.status_code, 500)

    def test_email_instant_verify_old_failure(self):
        with patch(f"{_ACS}.verify_old_otp", return_value={"error": "invalid_change_token"}):
            resp = self.client.post(
                reverse("email_instant_verify_old"), {"code": "0000"}
            )
        self.assertEqual(resp.status_code, 400)

    def test_email_instant_request_new_failure(self):
        with patch(f"{_ACS}.request_new_otp", return_value={"error": "not_available"}):
            resp = self.client.post(
                reverse("email_instant_request_new"),
                {"email": "new@example.com", "change_token": self._tok()},
            )
        self.assertEqual(resp.status_code, 409)

    def test_email_instant_verify_new_failure(self):
        with patch(f"{_ACS}.verify_new_and_apply", return_value={"error": "value_mismatch"}):
            resp = self.client.post(
                reverse("email_instant_verify_new"),
                {"email": "new@example.com", "code": "0000", "change_token": self._tok()},
            )
        self.assertEqual(resp.status_code, 400)

    def test_email_delayed_cancel_failure(self):
        with patch(f"{_ACS}.cancel_pending", return_value={"error": "not_found"}):
            resp = self.client.post(
                reverse("email_delayed_cancel"),
                {"change_request_id": str(uuid.uuid4())},
            )
        self.assertEqual(resp.status_code, 404)

    # ── missing-new-value guards (wrong-type field passes serializer) ──
    def test_phone_instant_request_new_missing_phone(self):
        resp = self.client.post(
            reverse("phone_instant_request_new"),
            {"email": "wrong@example.com", "change_token": self._tok()},
        )
        self.assertEqual(resp.status_code, 400)

    def test_email_instant_request_new_missing_email(self):
        resp = self.client.post(
            reverse("email_instant_request_new"),
            {"phone": "+12025550003", "change_token": self._tok()},
        )
        self.assertEqual(resp.status_code, 400)

    def test_email_instant_verify_new_missing_email(self):
        resp = self.client.post(
            reverse("email_instant_verify_new"),
            {"phone": "+12025550004", "code": "0000", "change_token": self._tok()},
        )
        self.assertEqual(resp.status_code, 400)

    def test_phone_delayed_initiate_missing_phone(self):
        resp = self.client.post(
            reverse("phone_delayed_initiate"), {"email": "wrong@example.com"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_email_delayed_initiate_missing_email(self):
        resp = self.client.post(
            reverse("email_delayed_initiate"), {"phone": "+12025550005"}
        )
        self.assertEqual(resp.status_code, 400)

    # ── delayed initiate x-forwarded-for splitting ──
    def test_phone_delayed_initiate_forwarded_for_split(self):
        with patch(f"{_ACS}.initiate_delayed", return_value={"error": "send_failed"}):
            resp = self.client.post(
                reverse("phone_delayed_initiate"),
                {"phone": "+12025550006"},
                HTTP_X_FORWARDED_FOR="1.1.1.1, 2.2.2.2",
            )
        self.assertEqual(resp.status_code, 500)

    def test_email_delayed_initiate_forwarded_for_split(self):
        with patch(f"{_ACS}.initiate_delayed", return_value={"error": "send_failed"}):
            resp = self.client.post(
                reverse("email_delayed_initiate"),
                {"email": "new6@example.com"},
                HTTP_X_FORWARDED_FOR="3.3.3.3, 4.4.4.4",
            )
        self.assertEqual(resp.status_code, 500)


# =============================================================================
# QR services + views
# =============================================================================


class QRServiceBranchTests(TestCase):
    def test_fulfill_session_share_missing_key(self):
        from stapel_auth.qr.services import QRAuthService

        self.assertFalse(
            QRAuthService.fulfill_session_share("nope", scanner_user_id=1)
        )

    def test_fulfill_login_request_missing_key(self):
        from stapel_auth.qr.services import QRAuthService

        self.assertFalse(
            QRAuthService.fulfill_login_request(
                "nope", approver_user_id=1, access_token="a", refresh_token="r"
            )
        )

    def test_reject_missing_key(self):
        from stapel_auth.qr.services import QRAuthService

        self.assertFalse(QRAuthService.reject("nope"))


class QRViewBranchTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_status_legacy_record_without_nonce(self):
        from stapel_auth.qr.dto import QRType
        from stapel_auth.qr.services import QRAuthService

        key = QRAuthService.generate(qr_type=QRType.LOGIN_REQUEST, nonce=None)
        resp = self.client.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(resp.status_code, 200)

    def test_status_rejected(self):
        from stapel_auth.qr.dto import QRType
        from stapel_auth.qr.services import QRAuthService

        owner = _make_user()
        key = QRAuthService.generate(
            qr_type=QRType.SESSION_SHARE, owner_user_id=owner.id
        )
        QRAuthService.reject(key)
        resp = self.client.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "rejected")

    def test_status_session_share_fulfilled_without_tokens(self):
        from stapel_auth.qr.dto import QRType
        from stapel_auth.qr.services import QRAuthService

        owner = _make_user()
        key = QRAuthService.generate(
            qr_type=QRType.SESSION_SHARE, owner_user_id=owner.id
        )
        QRAuthService.fulfill_session_share(key, scanner_user_id=owner.id)
        resp = self.client.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "fulfilled")

    def _fulfilled_login_key(self, user, nonce="thenonce"):
        from stapel_auth.qr.dto import QRType
        from stapel_auth.qr.services import QRAuthService

        access, refresh = _tokens(user)
        key = QRAuthService.generate(qr_type=QRType.LOGIN_REQUEST, nonce=nonce)
        data = QRAuthService.get(key)
        data["status"] = "fulfilled"
        data["fulfilled_user_id"] = str(user.id)
        data["access_token"] = access
        data["refresh_token"] = refresh
        QRAuthService._update(key, data)
        return key

    def test_status_login_request_fulfilled_creates_session(self):
        user = _make_user()
        key = self._fulfilled_login_key(user)
        self.client.cookies["stapel_qr_" + key] = "thenonce"
        with patch(
            "stapel_auth.sessions.services.LoginNotificationService.check_and_notify"
        ):
            resp = self.client.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "fulfilled")

    def test_status_login_request_fulfilled_session_none(self):
        user = _make_user()
        key = self._fulfilled_login_key(user)
        self.client.cookies["stapel_qr_" + key] = "thenonce"
        with patch(
            "stapel_auth.sessions.services.SessionService.create", return_value=None
        ):
            resp = self.client.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(resp.status_code, 200)

    def test_status_login_request_fulfilled_user_missing(self):
        user = _make_user()
        from stapel_auth.qr.dto import QRType
        from stapel_auth.qr.services import QRAuthService

        access, refresh = _tokens(user)
        key = QRAuthService.generate(qr_type=QRType.LOGIN_REQUEST, nonce="thenonce")
        data = QRAuthService.get(key)
        data["status"] = "fulfilled"
        data["fulfilled_user_id"] = str(uuid.uuid4())  # non-existent
        data["access_token"] = access
        data["refresh_token"] = refresh
        QRAuthService._update(key, data)
        self.client.cookies["stapel_qr_" + key] = "thenonce"
        resp = self.client.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(resp.status_code, 200)

    def test_status_login_request_fulfilled_session_create_raises(self):
        user = _make_user()
        key = self._fulfilled_login_key(user)
        self.client.cookies["stapel_qr_" + key] = "thenonce"
        with patch(
            "stapel_auth.sessions.services.SessionService.create",
            side_effect=Exception("boom"),
        ):
            resp = self.client.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(resp.status_code, 200)

    def test_scan_session_share_owner_missing_returns_404(self):
        from stapel_auth.qr.dto import QRType
        from stapel_auth.qr.services import QRAuthService

        key = QRAuthService.generate(
            qr_type=QRType.SESSION_SHARE, owner_user_id=str(uuid.uuid4())
        )
        resp = self.client.get(reverse("qr_scan", kwargs={"key": key}))
        self.assertEqual(resp.status_code, 404)

    def test_reject_endpoint_success(self):
        from stapel_auth.qr.dto import QRType
        from stapel_auth.qr.services import QRAuthService

        owner = _make_user()
        key = QRAuthService.generate(
            qr_type=QRType.SESSION_SHARE, owner_user_id=owner.id
        )
        resp = self.client.post(reverse("qr_reject", kwargs={"key": key}))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "rejected")

    def test_reject_endpoint_not_found(self):
        resp = self.client.post(reverse("qr_reject", kwargs={"key": "no-such-key"}))
        self.assertEqual(resp.status_code, 404)


# =============================================================================
# tasks.py branches
# =============================================================================


class TasksBranchTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def _req(self, **kw):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        defaults = dict(
            user=self.user,
            change_type="email",
            old_value="old@example.com",
            new_value="new@example.com",
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=14),
            change_token=uuid.uuid4(),
        )
        defaults.update(kw)
        return AuthenticatorChangeRequest.objects.create(**defaults)

    def test_day7_notification_exception_swallowed(self):
        from stapel_auth.tasks import send_change_notifications

        req = self._req(
            scheduled_at=timezone.now() + timedelta(days=7),
            notification_day_1_sent=True,
        )
        req.created_at = timezone.now() - timedelta(days=8)
        req.save(update_fields=["created_at"])
        with patch(
            "stapel_auth.tasks.request_notification", side_effect=Exception("x")
        ):
            self.assertEqual(send_change_notifications(), 0)

    def test_day13_notification_exception_swallowed(self):
        from stapel_auth.tasks import send_change_notifications

        req = self._req(
            change_type="phone",
            old_value="+10000000000",
            new_value="+10000000001",
            scheduled_at=timezone.now() + timedelta(days=1),
            notification_day_1_sent=True,
            notification_day_7_sent=True,
        )
        req.created_at = timezone.now() - timedelta(days=14)
        req.save(update_fields=["created_at"])
        with patch(
            "stapel_auth.tasks.request_notification", side_effect=Exception("x")
        ):
            self.assertEqual(send_change_notifications(), 0)

    def test_execute_pending_completion_notification_exception(self):
        from stapel_auth.models import AuthenticatorChangeStatus
        from stapel_auth.tasks import execute_pending_changes

        req = self._req(
            old_value=self.user.email,
            new_value="changed@example.com",
            scheduled_at=timezone.now() - timedelta(minutes=5),
        )
        with patch(f"{_ACS}._apply_change"), \
             patch(f"{_ACS}._invalidate_all_tokens"), \
             patch(
                 "stapel_auth.tasks.request_notification",
                 side_effect=Exception("notify fail"),
             ):
            self.assertEqual(execute_pending_changes(), 1)
        req.refresh_from_db()
        self.assertEqual(req.status, AuthenticatorChangeStatus.COMPLETED)

    def test_execute_pending_apply_change_exception(self):
        from stapel_auth.tasks import execute_pending_changes

        self._req(
            old_value=self.user.email,
            new_value="changed2@example.com",
            scheduled_at=timezone.now() - timedelta(minutes=5),
        )
        with patch(f"{_ACS}._apply_change", side_effect=Exception("apply fail")):
            # Exception is caught (149-150); nothing executed.
            self.assertEqual(execute_pending_changes(), 0)

    def test_execute_pending_row_vanished_is_skipped(self):
        from stapel_auth.models import AuthenticatorChangeRequest
        from stapel_auth.tasks import execute_pending_changes

        self._req(
            old_value=self.user.email,
            new_value="changed3@example.com",
            scheduled_at=timezone.now() - timedelta(minutes=5),
        )
        real_get = AuthenticatorChangeRequest.objects.get

        def _raise_missing(*a, **k):
            raise AuthenticatorChangeRequest.DoesNotExist()

        with patch.object(
            AuthenticatorChangeRequest.objects, "select_for_update"
        ) as m:
            m.return_value.get.side_effect = (
                AuthenticatorChangeRequest.DoesNotExist()
            )
            self.assertEqual(execute_pending_changes(), 0)
        # keep reference used to satisfy linters
        self.assertTrue(callable(real_get))

    def test_evaluate_login_notification_not_new_not_suspicious(self):
        from stapel_auth.models import UserSession
        from stapel_auth.tasks import evaluate_login_notification

        session = UserSession.objects.create(
            user=self.user,
            jti=uuid.uuid4().hex,
            device_name="Chrome",
            device_type="desktop",
            expires_at=timezone.now() + timedelta(days=30),
        )
        with patch(
            "stapel_auth.sessions.services.LoginNotificationService.is_new_device",
            return_value=False,
        ), patch(
            "stapel_auth.sessions.services.LoginNotificationService.is_suspicious_ip",
            return_value=False,
        ), patch("stapel_auth.tasks._send_login_alert_email") as mock_send:
            evaluate_login_notification(str(self.user.id), str(session.id))
        mock_send.assert_not_called()

    def test_send_login_alert_email_non_suspicious(self):
        from stapel_auth.models import UserSession
        from stapel_auth.tasks import _send_login_alert_email

        session = UserSession.objects.create(
            user=self.user,
            jti=uuid.uuid4().hex,
            device_name="Chrome",
            device_type="desktop",
            ip_address="1.2.3.4",
            expires_at=timezone.now() + timedelta(days=30),
        )
        with patch("stapel_core.notifications.request_notification") as mock_notify:
            _send_login_alert_email(self.user, session, is_suspicious=False)
        mock_notify.assert_called_once()

    def test_send_login_alert_email_notification_exception(self):
        from stapel_auth.models import UserSession
        from stapel_auth.tasks import _send_login_alert_email

        session = UserSession.objects.create(
            user=self.user,
            jti=uuid.uuid4().hex,
            device_name="Chrome",
            device_type="desktop",
            expires_at=timezone.now() + timedelta(days=30),
        )
        with patch(
            "stapel_core.notifications.request_notification",
            side_effect=Exception("smtp down"),
        ):
            # Must not raise
            _send_login_alert_email(self.user, session, is_suspicious=True)


# =============================================================================
# utils.py + permissions.py
# =============================================================================


class UtilsBranchTests(TestCase):
    def test_serializer_seam_missing_attr_raises(self):
        from stapel_auth.utils import SerializerSeamsMixin

        class Dummy(SerializerSeamsMixin):
            pass

        with self.assertRaises(AttributeError):
            Dummy().get_missing_serializer_class()

    def test_mask_phone_without_plus(self):
        from stapel_auth.utils import mask_phone

        masked = mask_phone("2025551234")
        self.assertIn("12", masked)
        self.assertNotIn("+", masked)

    def test_mask_value_unknown_type_returns_value(self):
        from stapel_auth.utils import mask_value

        self.assertEqual(mask_value("raw", "unknown"), "raw")


class PermissionsBranchTests(TestCase):
    def test_internal_service_missing_header_denied(self):
        from stapel_auth.permissions import IsInternalService

        rf = RequestFactory()
        req = rf.get("/")
        self.assertFalse(IsInternalService().has_permission(req, view=None))


# =============================================================================
# apps.py startup branches (DEBUG off, no FRONTEND_URL, GDPR collecting services)
# =============================================================================


class AppsReadyBranchTests(TestCase):
    @override_settings(
        DEBUG=False,
        FRONTEND_URL="",
        GDPR_COLLECTING_SERVICES=["billing"],
        STAPEL_AUTH={"FRONTEND_URL": ""},
    )
    def test_ready_non_debug_no_frontend_gdpr_collecting(self):
        import warnings

        from stapel_auth.apps import StapelAuthConfig
        from stapel_auth.conf import auth_settings

        auth_settings.reload()
        cfg = StapelAuthConfig.create("stapel_auth")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                cfg.ready()
        finally:
            auth_settings.reload()
