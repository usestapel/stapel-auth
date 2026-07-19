"""Tests for `stapel_auth_hint` — the non-httponly companion cookie set
alongside the refresh-token JWT cookie by every redirect-based login flow
(QR `session_share` scan, magic-link verify) and cleared on logout.

Consumer-facing context (`@stapel/auth-react` incident, 2026-07-19): a
bearer-mode SPA cannot see httponly cookies via `document.cookie`, so it has
no way to tell "a redirect just minted a live session for me" from "there
was never a session" without an actual network probe. `bootstrapProbe:
"auto"` reads this cookie to decide. See `stapel_auth.hint_cookie` for the
full write-up and `sso_service.IssueSessionTests` /
`OAuthCallbackTests.test_callback_with_redirect_after_sets_cookies_not_url_tokens`
for the SSO/OAuth-callback coverage of the same contract.
"""

import uuid

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient, APITestCase

from stapel_auth.hint_cookie import HINT_COOKIE_NAME
from stapel_auth.magic_link.services import MagicLinkService
from stapel_auth.sessions.services import TokenService

User = get_user_model()


def _make_user(**kwargs):
    defaults = dict(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


def _create_token_for_user(user) -> tuple:
    from stapel_core.django.jwt.provider import jwt_provider

    return jwt_provider.create_tokens(user)


class QRScanHintCookieTests(APITestCase):
    """QR `session_share` scan — a browser-redirect flow (qr/views.py `scan()`)."""

    def setUp(self):
        self.owner = _make_user()
        access, _ = _create_token_for_user(self.owner)
        self.owner_token = access

    def _generate_session_share_key(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {self.owner_token}")
        resp = c.post(
            reverse("qr_generate"),
            {
                "type": "session_share",
                "redirect_url": "/",
                "allow_unauthenticated_scanner": True,
            },
        )
        return resp.data["key"]

    def test_scan_sets_hint_cookie_alongside_refresh_cookie(self):
        key = self._generate_session_share_key()
        response = self.client.get(
            reverse("qr_scan", kwargs={"key": key}), follow=False
        )
        self.assertIn(response.status_code, [301, 302])
        self.assertIn("stapel_refresh_jwt", response.cookies)
        self.assertIn(HINT_COOKIE_NAME, response.cookies)
        self.assertEqual(response.cookies[HINT_COOKIE_NAME].value, "1")

    def test_scan_hint_cookie_attributes_match_refresh_cookie(self):
        key = self._generate_session_share_key()
        response = self.client.get(
            reverse("qr_scan", kwargs={"key": key}), follow=False
        )
        refresh_cookie = response.cookies["stapel_refresh_jwt"]
        hint_cookie = response.cookies[HINT_COOKIE_NAME]

        self.assertEqual(hint_cookie["path"], refresh_cookie["path"])
        self.assertEqual(hint_cookie["samesite"], refresh_cookie["samesite"])
        self.assertEqual(hint_cookie["secure"], refresh_cookie["secure"])
        self.assertEqual(hint_cookie["max-age"], refresh_cookie["max-age"])
        # Non-httponly by design — this is the JS-readable signal auth-react
        # checks; the refresh cookie itself must stay httponly.
        self.assertFalse(hint_cookie["httponly"])
        self.assertTrue(refresh_cookie["httponly"])


class MagicLinkHintCookieTests(APITestCase):
    """Magic-link verify — a browser-redirect flow (magic_link/views.py `verify()`)."""

    def test_verify_sets_hint_cookie_alongside_refresh_cookie(self):
        user = _make_user()
        token = MagicLinkService.create(user, redirect_url="/home")
        response = self.client.get(reverse("magic_verify") + f"?token={token}")
        self.assertIn(response.status_code, [301, 302])
        self.assertIn("stapel_refresh_jwt", response.cookies)
        self.assertIn(HINT_COOKIE_NAME, response.cookies)
        self.assertEqual(response.cookies[HINT_COOKIE_NAME].value, "1")

    def test_verify_hint_cookie_attributes_match_refresh_cookie(self):
        user = _make_user()
        token = MagicLinkService.create(user, redirect_url="/home")
        response = self.client.get(reverse("magic_verify") + f"?token={token}")
        refresh_cookie = response.cookies["stapel_refresh_jwt"]
        hint_cookie = response.cookies[HINT_COOKIE_NAME]

        self.assertEqual(hint_cookie["path"], refresh_cookie["path"])
        self.assertEqual(hint_cookie["samesite"], refresh_cookie["samesite"])
        self.assertEqual(hint_cookie["secure"], refresh_cookie["secure"])
        self.assertEqual(hint_cookie["max-age"], refresh_cookie["max-age"])
        self.assertFalse(hint_cookie["httponly"])


class LogoutClearsHintCookieTests(APITestCase):
    def setUp(self):
        self.user = _make_user()

    def test_logout_clears_hint_cookie(self):
        refresh = TokenService.get_refresh_token_for_user(self.user)
        self.client.force_authenticate(user=self.user)
        self.client.cookies["stapel_jwt"] = str(refresh.access_token)
        self.client.cookies["stapel_refresh_jwt"] = str(refresh)
        self.client.cookies[HINT_COOKIE_NAME] = "1"

        response = self.client.post(reverse("logout"))

        self.assertEqual(response.status_code, 200)
        self.assertIn(HINT_COOKIE_NAME, response.cookies)
        cookie = response.cookies[HINT_COOKIE_NAME]
        self.assertTrue(cookie["max-age"] == 0 or cookie.value == "")

    def test_logout_get_clears_hint_cookie(self):
        refresh = TokenService.get_refresh_token_for_user(self.user)
        self.client.force_authenticate(user=self.user)
        self.client.cookies["stapel_jwt"] = str(refresh.access_token)
        self.client.cookies["stapel_refresh_jwt"] = str(refresh)
        self.client.cookies[HINT_COOKIE_NAME] = "1"

        response = self.client.get(reverse("logout"))

        self.assertEqual(response.status_code, 200)
        self.assertIn(HINT_COOKIE_NAME, response.cookies)
        cookie = response.cookies[HINT_COOKIE_NAME]
        self.assertTrue(cookie["max-age"] == 0 or cookie.value == "")
