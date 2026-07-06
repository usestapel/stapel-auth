"""Coverage tests for stapel_auth.sessions.views and stapel_auth.sessions.services.

Targets SessionViewSet (list/revoke/revoke-all/confirm), the token obtain/refresh
views, _issue_session_tokens, and the SessionService/TokenService/AuditService/
LoginNotificationService service methods (including defensive except branches via
fault injection).
"""
import datetime
import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.test.client import RequestFactory
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase

from stapel_auth.models import UserSession
from stapel_auth.sessions import services as svc
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


def _make_session(user, **kwargs):
    defaults = dict(
        jti=uuid.uuid4().hex,
        device_name="Chrome on Mac",
        device_type="desktop",
        expires_at=timezone.now() + timedelta(days=30),
    )
    defaults.update(kwargs)
    return UserSession.objects.create(user=user, **defaults)


# =============================================================================
# SessionViewSet (sessions/views.py)
# =============================================================================


@override_settings(URL_PREFIX="")
class SessionViewSetTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.access, self.refresh = jwt_provider.create_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        # jti embedded in the current access token (refresh_jti or jti)
        payload = jwt_provider.handler.decode_token(self.access, verify=False) or {}
        self.current_jti = payload.get("refresh_jti") or payload.get("jti")

    def test_list_sessions_marks_current_and_other(self):
        # One session that matches the current token -> is_current True
        _make_session(self.user, jti=self.current_jti, device_name="Current device")
        # A second, unrelated session -> is_current False
        _make_session(self.user, device_name="Other device", is_suspicious=True)
        resp = self.client.get(reverse("sessions"))
        self.assertEqual(resp.status_code, 200)
        data = resp.data
        # StapelResponse may wrap; normalise to a list of dicts
        items = data.get("data", data) if isinstance(data, dict) else data
        self.assertEqual(len(items), 2)
        current_flags = {d["device_name"]: d["is_current"] for d in items}
        self.assertTrue(current_flags["Current device"])
        self.assertFalse(current_flags["Other device"])

    def test_list_sessions_without_bearer_header_no_current(self):
        # Authenticate via cookie-less path: force META without Bearer to hit
        # the `current_jti = None` branch (is_current always False).
        _make_session(self.user)
        self.client.credentials()  # drop Authorization header
        # Re-auth through force_authenticate so IsAuthenticated passes but no bearer
        self.client.force_authenticate(self.user)
        resp = self.client.get(reverse("sessions"))
        self.assertEqual(resp.status_code, 200)
        items = resp.data.get("data", resp.data) if isinstance(resp.data, dict) else resp.data
        self.assertFalse(items[0]["is_current"])

    # Regression guard: revoke_one / confirm_session / revoke_all used to do
    # `from .dto import SimpleStatusResponse` (wrong module -> ImportError -> 500
    # after the DB mutation had already been applied). Fixed to import from the
    # top-level stapel_auth.dto; these assert the 200 success contract.
    def test_revoke_one_marks_revoked(self):
        session = _make_session(self.user, access_jti=uuid.uuid4().hex)
        resp = self.client.delete(reverse("session_revoke", args=[str(session.id)]))
        self.assertEqual(resp.status_code, 200)
        session.refresh_from_db()
        self.assertTrue(session.is_revoked)

    def test_revoke_one_not_found(self):
        resp = self.client.delete(reverse("session_revoke", args=[str(uuid.uuid4())]))
        self.assertEqual(resp.status_code, 404)

    def test_confirm_session_clears_suspicious(self):
        session = _make_session(self.user, is_suspicious=True)
        resp = self.client.post(reverse("session_confirm", args=[str(session.id)]))
        self.assertEqual(resp.status_code, 200)
        session.refresh_from_db()
        self.assertFalse(session.is_suspicious)

    def test_confirm_session_non_suspicious_ok(self):
        session = _make_session(self.user, is_suspicious=False)
        resp = self.client.post(reverse("session_confirm", args=[str(session.id)]))
        self.assertEqual(resp.status_code, 200)

    def test_confirm_session_not_found(self):
        resp = self.client.post(reverse("session_confirm", args=[str(uuid.uuid4())]))
        self.assertEqual(resp.status_code, 404)

    def test_revoke_all_except_current(self):
        keep = _make_session(self.user, jti=self.current_jti, device_name="keep")
        drop = _make_session(self.user, device_name="drop")
        resp = self.client.delete(reverse("sessions"))
        self.assertEqual(resp.status_code, 200)
        keep.refresh_from_db()
        drop.refresh_from_db()
        self.assertFalse(keep.is_revoked)  # except_jti spared
        self.assertTrue(drop.is_revoked)

    def test_revoke_all_without_bearer(self):
        # force_authenticate leaves no Bearer header -> current_jti None branch
        drop = _make_session(self.user)
        self.client.credentials()
        self.client.force_authenticate(self.user)
        resp = self.client.delete(reverse("sessions"))
        self.assertEqual(resp.status_code, 200)
        drop.refresh_from_db()
        self.assertTrue(drop.is_revoked)


# =============================================================================
# CustomTokenObtainPairView (sessions/views.py)
# =============================================================================


@override_settings(URL_PREFIX="")
class TokenObtainTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_missing_credentials_returns_400(self):
        resp = self.client.post(reverse("token_obtain_pair"), {})
        self.assertEqual(resp.status_code, 400)

    def test_success_by_email(self):
        user = _make_user(email="obtain@example.com", password="testpass123")
        resp = self.client.post(
            reverse("token_obtain_pair"),
            {"email": "obtain@example.com", "password": "testpass123"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("access", resp.data)
        user.refresh_from_db()
        self.assertIsNotNone(user.last_login)

    def test_success_by_username_first_try(self):
        # Direct username auth succeeds on the first authenticate() -> the email
        # fallback lookup is skipped (79->89 branch).
        _make_user(username="directlogin", password="testpass123")
        resp = self.client.post(
            reverse("token_obtain_pair"),
            {"username": "directlogin", "password": "testpass123"},
        )
        self.assertEqual(resp.status_code, 200)

    def test_wrong_username_returns_401(self):
        # username that is not an email and does not exist:
        # authenticate() -> None, email lookup DoesNotExist -> pass -> 401
        resp = self.client.post(
            reverse("token_obtain_pair"),
            {"username": "nobody_here", "password": "whatever"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_wrong_password_for_existing_email_returns_401(self):
        # existing email but wrong password: authenticate(email) None -> lookup
        # finds user -> authenticate(username, wrong pw) None -> 401
        _make_user(email="known@example.com", password="rightpass123")
        resp = self.client.post(
            reverse("token_obtain_pair"),
            {"email": "known@example.com", "password": "wrongpass"},
        )
        self.assertEqual(resp.status_code, 401)


# =============================================================================
# CustomTokenRefreshView (sessions/views.py)
# =============================================================================


@override_settings(URL_PREFIX="")
class TokenRefreshTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = _make_user()

    def _tokens(self):
        return jwt_provider.create_tokens(self.user)

    def test_refresh_not_provided_returns_401(self):
        resp = self.client.post(reverse("token_refresh"), {})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_undecodable_token_returns_401(self):
        # Not blacklisted, but decode_token() returns None -> ERR_401_REFRESH_INVALID
        resp = self.client.post(reverse("token_refresh"), {"refresh": "not.a.jwt"})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_blacklisted_returns_401(self):
        _, refresh = self._tokens()
        with patch.object(jwt_provider, "is_blacklisted", return_value=True):
            resp = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_user_blacklisted_returns_401(self):
        _, refresh = self._tokens()
        with patch(
            "stapel_core.django.authentication.is_user_blacklisted",
            return_value=True,
        ):
            resp = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_revoked_session_returns_401(self):
        _, refresh = self._tokens()
        payload = jwt_provider.handler.decode_token(refresh, verify=False) or {}
        _make_session(self.user, jti=payload["jti"], is_revoked=True)
        resp = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_success_no_session_record(self):
        # No UserSession for this jti and no other sessions -> rotate returns
        # False -> refresh allowed through (legacy token path).
        _, refresh = self._tokens()
        resp = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("access", resp.data)

    def test_refresh_replay_with_other_active_session_returns_401(self):
        # A different active session exists but old_jti has no record ->
        # SessionService.rotate() treats it as a replay -> None -> 401.
        _, refresh = self._tokens()
        _make_session(self.user, device_name="another live session")
        resp = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_new_access_token_none_returns_401(self):
        _, refresh = self._tokens()
        with patch.object(
            jwt_provider, "create_tokens_from_data", return_value=(None, None)
        ):
            resp = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_user_gone_returns_401(self):
        _, refresh = self._tokens()
        self.user.delete()
        resp = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_get_from_cookie(self):
        # GET path exercises refresh_get + cookie extraction branch.
        _, refresh = self._tokens()
        self.client.cookies["refresh_token"] = refresh
        resp = self.client.get(reverse("token_refresh"))
        self.assertIn(resp.status_code, (200, 401))


# =============================================================================
# _issue_session_tokens (sessions/views.py)
# =============================================================================


class IssueSessionTokensTests(TestCase):
    def test_issue_creates_session_and_notifies(self):
        from stapel_auth.sessions.views import _issue_session_tokens

        user = _make_user()
        rf = RequestFactory()
        request = rf.post(
            "/auth/login/",
            HTTP_USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        )
        with patch(
            "stapel_auth.sessions.services.LoginNotificationService.check_and_notify"
        ) as notify:
            access, refresh = _issue_session_tokens(user, request)
        self.assertTrue(access and refresh)
        self.assertTrue(UserSession.objects.filter(user=user).exists())
        notify.assert_called_once()

    def test_issue_without_jti_skips_session(self):
        # decode returns empty payload -> jti '' -> no session created, no notify
        from stapel_auth.sessions.views import _issue_session_tokens

        user = _make_user()
        rf = RequestFactory()
        request = rf.post("/auth/login/")
        with patch.object(jwt_provider.handler, "decode_token", return_value={}), patch(
            "stapel_auth.sessions.services.LoginNotificationService.check_and_notify"
        ) as notify:
            access, refresh = _issue_session_tokens(user, request)
        self.assertTrue(access and refresh)
        self.assertFalse(UserSession.objects.filter(user=user).exists())
        notify.assert_not_called()

    def test_add_login_hints_sets_headers(self):
        from django.http import HttpResponse

        from stapel_auth.sessions.views import _add_login_hints

        resp = _add_login_hints(HttpResponse(), critical=True)
        self.assertIn("Accept-CH", resp)
        self.assertIn("Critical-CH", resp)
        resp2 = _add_login_hints(HttpResponse(), critical=False)
        self.assertIn("Accept-CH", resp2)
        self.assertNotIn("Critical-CH", resp2)


# =============================================================================
# services: _get_client_ip / _blacklist_jti
# =============================================================================


class ClientIpTests(TestCase):
    def test_none_request_returns_none(self):
        self.assertIsNone(svc._get_client_ip(None))

    def test_public_forwarded_for(self):
        rf = RequestFactory()
        req = rf.get("/", HTTP_X_FORWARDED_FOR="203.0.113.9, 10.0.0.1")
        self.assertEqual(svc._get_client_ip(req), "203.0.113.9")

    def test_private_forwarded_falls_back_to_real_ip(self):
        rf = RequestFactory()
        req = rf.get(
            "/",
            HTTP_X_FORWARDED_FOR="10.0.0.1, 192.168.1.1",
            HTTP_X_REAL_IP="198.51.100.7",
        )
        self.assertEqual(svc._get_client_ip(req), "198.51.100.7")

    def test_falls_back_to_remote_addr(self):
        rf = RequestFactory()
        req = rf.get("/", REMOTE_ADDR="198.51.100.42")
        self.assertEqual(svc._get_client_ip(req), "198.51.100.42")


class BlacklistJtiTests(TestCase):
    def test_empty_jti_is_noop(self):
        # Should return without touching TokenBlacklist
        with patch("stapel_core.core.token_blacklist.TokenBlacklist") as tb:
            svc._blacklist_jti("", timezone.now() + timedelta(days=1))
            tb.assert_not_called()

    def test_datetime_expiry_blacklists(self):
        fake = MagicMock()
        with patch(
            "stapel_core.core.token_blacklist.TokenBlacklist", return_value=fake
        ):
            svc._blacklist_jti("jti-1", timezone.now() + timedelta(days=1))
        fake.blacklist_token.assert_called_once()

    def test_unix_timestamp_expiry_blacklists(self):
        fake = MagicMock()
        future = (
            datetime.datetime.now(datetime.timezone.utc) + timedelta(days=1)
        ).timestamp()
        with patch(
            "stapel_core.core.token_blacklist.TokenBlacklist", return_value=fake
        ):
            svc._blacklist_jti("jti-2", future)
        fake.blacklist_token.assert_called_once()

    def test_past_expiry_skips_blacklist(self):
        fake = MagicMock()
        with patch(
            "stapel_core.core.token_blacklist.TokenBlacklist", return_value=fake
        ):
            svc._blacklist_jti("jti-3", timezone.now() - timedelta(days=1))
        fake.blacklist_token.assert_not_called()

    def test_exception_is_swallowed(self):
        with patch(
            "stapel_core.core.token_blacklist.TokenBlacklist",
            side_effect=Exception("boom"),
        ):
            # must not raise
            svc._blacklist_jti("jti-4", timezone.now() + timedelta(days=1))


# =============================================================================
# services: SessionService
# =============================================================================


class SessionServiceTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def test_create_with_request_parses_device(self):
        rf = RequestFactory()
        req = rf.get(
            "/",
            HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            HTTP_X_FORWARDED_FOR="203.0.113.5",
        )
        session = svc.SessionService.create(
            self.user, "jti-a", timezone.now() + timedelta(days=1), request=req
        )
        self.assertEqual(session.device_type, "desktop")
        self.assertEqual(session.ip_address, "203.0.113.5")

    def test_create_without_request(self):
        session = svc.SessionService.create(
            self.user, "jti-b", timezone.now() + timedelta(days=1)
        )
        self.assertEqual(session.device_name, "Unknown device")

    def test_rotate_success_updates_jti(self):
        s = _make_session(self.user, jti="old-jti", access_jti="old-acc")
        result = svc.SessionService.rotate(
            "old-jti",
            "new-jti",
            timezone.now() + timedelta(days=2),
            new_access_jti="new-acc",
        )
        self.assertTrue(result)
        s.refresh_from_db()
        self.assertEqual(s.jti, "new-jti")
        self.assertEqual(s.access_jti, "new-acc")

    def test_rotate_success_without_new_access_jti(self):
        s = _make_session(self.user, jti="old2", access_jti="keep-acc")
        result = svc.SessionService.rotate(
            "old2", "new2", timezone.now() + timedelta(days=2)
        )
        self.assertTrue(result)
        s.refresh_from_db()
        self.assertEqual(s.jti, "new2")
        self.assertEqual(s.access_jti, "keep-acc")  # unchanged when not supplied

    def test_rotate_revoked_returns_none(self):
        _make_session(self.user, jti="rev-jti", is_revoked=True)
        result = svc.SessionService.rotate(
            "rev-jti", "x", timezone.now() + timedelta(days=1)
        )
        self.assertIsNone(result)

    def test_rotate_missing_with_active_session_is_replay(self):
        _make_session(self.user, jti="live-jti")
        result = svc.SessionService.rotate(
            "ghost-jti",
            "x",
            timezone.now() + timedelta(days=1),
            user_id=self.user.id,
        )
        self.assertIsNone(result)

    def test_rotate_missing_no_sessions_is_legacy(self):
        result = svc.SessionService.rotate(
            "ghost-jti",
            "x",
            timezone.now() + timedelta(days=1),
            user_id=self.user.id,
        )
        self.assertFalse(result)

    def test_revoke_by_jti(self):
        _make_session(self.user, jti="rbj")
        self.assertTrue(svc.SessionService.revoke_by_jti("rbj"))
        self.assertFalse(svc.SessionService.revoke_by_jti("nonexistent"))

    def test_revoke_all_except_current(self):
        keep = _make_session(self.user, jti="keep", access_jti="keep-acc")
        drop = _make_session(self.user, jti="drop", access_jti="drop-acc")
        with patch("stapel_auth.sessions.services._blacklist_jti") as bl:
            svc.SessionService.revoke_all(self.user, except_jti="keep")
        keep.refresh_from_db()
        drop.refresh_from_db()
        self.assertFalse(keep.is_revoked)
        self.assertTrue(drop.is_revoked)
        # blacklists jti + access_jti of the dropped session
        self.assertEqual(bl.call_count, 2)

    def test_get_active_excludes_revoked_and_expired(self):
        active = _make_session(self.user, jti="act")
        _make_session(self.user, jti="rev", is_revoked=True)
        _make_session(
            self.user, jti="exp", expires_at=timezone.now() - timedelta(days=1)
        )
        result = list(svc.SessionService.get_active(self.user))
        self.assertEqual([s.id for s in result], [active.id])


# =============================================================================
# services: TokenService / AuditService / LoginNotificationService
# =============================================================================


class TokenServiceTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def test_verify_token_exception_returns_none(self):
        with patch.object(
            jwt_provider, "validate_token", side_effect=Exception("boom")
        ):
            self.assertIsNone(svc.TokenService.verify_token("bad"))

    def test_blacklist_token_exception_returns_false(self):
        with patch.object(
            jwt_provider, "blacklist_token", side_effect=Exception("boom")
        ):
            self.assertFalse(svc.TokenService.blacklist_token("bad"))


class AuditServiceTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def test_log_creates_row_with_request(self):
        from stapel_auth.models import AuthAuditLog

        rf = RequestFactory()
        req = rf.get("/", HTTP_USER_AGENT="agent/1.0", REMOTE_ADDR="198.51.100.1")
        svc.AuditService.log("login_success", user=self.user, request=req, extra="x")
        self.assertTrue(
            AuthAuditLog.objects.filter(user=self.user, event_type="login_success").exists()
        )

    def test_log_swallows_exceptions(self):
        with patch(
            "stapel_auth.models.AuthAuditLog.objects.create",
            side_effect=Exception("db down"),
        ):
            # Must not raise
            svc.AuditService.log("login_success", user=self.user)


class LoginNotificationServiceTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def test_check_and_notify_dispatches_task(self):
        session = _make_session(self.user)
        with patch("stapel_auth.tasks.evaluate_login_notification.delay") as delay:
            svc.LoginNotificationService.check_and_notify(self.user, session)
        delay.assert_called_once_with(str(self.user.id), str(session.id))

    def test_is_new_device_true_when_unique(self):
        session = _make_session(self.user, device_name="Brand New Phone")
        self.assertTrue(svc.LoginNotificationService.is_new_device(self.user, session))

    def test_is_new_device_false_when_prior_exists(self):
        _make_session(self.user, device_name="Repeat Device")
        session = _make_session(self.user, device_name="Repeat Device")
        self.assertFalse(svc.LoginNotificationService.is_new_device(self.user, session))

    def test_is_suspicious_ip_no_ip_returns_false(self):
        session = _make_session(self.user, ip_address=None)
        self.assertFalse(
            svc.LoginNotificationService.is_suspicious_ip(self.user, session)
        )

    def test_is_suspicious_ip_true_for_new_prefix(self):
        session = _make_session(self.user, ip_address="203.0.113.20")
        self.assertTrue(
            svc.LoginNotificationService.is_suspicious_ip(self.user, session)
        )

    def test_is_suspicious_ip_false_for_known_prefix(self):
        _make_session(self.user, ip_address="203.0.113.5")
        session = _make_session(self.user, ip_address="203.0.113.20")
        self.assertFalse(
            svc.LoginNotificationService.is_suspicious_ip(self.user, session)
        )
