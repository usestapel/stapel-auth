"""The middleware and the refresh view give one answer about a refresh token.

Production, 2026-09-19..24 (a client fleet): a browser kept presenting a
refresh jti its session had rotated away from. The refresh view refused it
27 times in five days; JWTAuthMiddleware minted 25 access tokens from it on
expired requests to this service. The client saw "refresh 401, /me 200" and
lost a 7.1 GB upload at its ``complete`` call. These tests walk that exact
shape through the real view and the real middleware.
"""
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from stapel_auth.models import UserSession
from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.views import _issue_session_tokens
from stapel_core.django.jwt.middleware import JWTAuthMiddleware
from stapel_core.django.jwt.provider import jwt_provider
from stapel_core.django.jwt.utils import jwt_cookie_names

User = get_user_model()


def _make_user():
    return User.objects.create_user(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )


def _middleware_mints(refresh):
    """What JWTAuthMiddleware does with an expired access token + this refresh."""
    _, refresh_name = jwt_cookie_names()
    req = RequestFactory().get("/api/v1/me/")
    req.COOKIES = {refresh_name: refresh}
    req.session = SessionStore()
    JWTAuthMiddleware(lambda r: HttpResponse()).process_request(req)
    return bool(getattr(req, "_jwt_refreshed", False))


@override_settings(
    URL_PREFIX="", JWT_REFRESH_ALLOWED=True,
    STAPEL_AUTH={"REFRESH_ROTATION_GRACE_SECONDS": 10},
)
class RefreshMiddlewareParityTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()
        _, self.refresh = _issue_session_tokens(
            self.user, None, path=SessionPath.PASSWORD
        )
        self.session = self.user.sessions.get()

    def _rotate(self, token):
        resp = self.client.post(reverse("token_refresh"), {"refresh": token})
        self.assertEqual(resp.status_code, 200, resp.content)
        return resp.data["refresh"]

    def _age_rotation(self):
        UserSession.objects.filter(pk=self.session.pk).update(
            rotated_at=timezone.now() - timedelta(minutes=5)
        )

    def test_a_superseded_jti_past_the_window_is_refused_by_both(self):
        current = self._rotate(self.refresh)
        self._age_rotation()

        view = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        self.assertEqual(view.status_code, 401)
        self.assertFalse(
            _middleware_mints(self.refresh),
            "the middleware minted from a refresh token the view refuses",
        )
        # The token the rotation handed out still works everywhere.
        self.assertTrue(_middleware_mints(current))

    def test_a_revoked_session_is_refused_by_both(self):
        UserSession.objects.filter(pk=self.session.pk).update(is_revoked=True)

        view = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        self.assertEqual(view.status_code, 401)
        self.assertFalse(_middleware_mints(self.refresh))

    def test_the_previous_jti_inside_the_window_is_honoured_by_both(self):
        self._rotate(self.refresh)

        self.assertTrue(_middleware_mints(self.refresh))
        view = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        self.assertEqual(view.status_code, 200)

    def test_a_live_session_is_honoured(self):
        self.assertTrue(_middleware_mints(self.refresh))
        self.assertIsNotNone(jwt_provider.refresh_access_token(self.refresh))
