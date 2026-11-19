"""The caller's own session, for a bearer client and for a cookie client.

A native client sends ``Authorization: Bearer <access>`` and no cookie. Access
tokens carry no session claim, so ``GET /sessions/`` used to mark nothing
``is_current`` and ``DELETE /sessions/`` ("sign out my other devices") revoked
the caller's own session too. The session is found through the access-token
ledger (``SessionAccessToken``) — see ``sessions.services.current_session``.

Every test signs in through the real choke point (``_issue_session_tokens``)
and calls the HTTP surface with the credentials a client actually holds.
"""
import uuid

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, override_settings
from django.urls import reverse
from rest_framework.test import APITestCase
from stapel_core.django.jwt.provider import jwt_provider
from stapel_core.django.jwt.utils import jwt_cookie_names

from stapel_auth.models import UserSession
from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.services import current_session, current_session_jti
from stapel_auth.sessions.views import _issue_session_tokens

User = get_user_model()


def _user():
    return User.objects.create_user(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )


def _jti(token):
    return (jwt_provider.handler.decode_token(token, verify=False) or {}).get("jti")


def _items(response):
    data = response.data
    return data.get("data", data) if isinstance(data, dict) else data


@override_settings(URL_PREFIX="", JWT_REFRESH_ALLOWED=True)
class BearerClientOwnSession(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = _user()
        # Three devices of one account, each a real sign-in.
        self.access, self.refresh = _issue_session_tokens(self.user, None, path=SessionPath.PASSWORD)
        self.other_access, _ = _issue_session_tokens(self.user, None, path=SessionPath.PASSWORD)
        self.third_access, _ = _issue_session_tokens(self.user, None, path=SessionPath.PASSWORD)
        self.mine = UserSession.objects.get(jti=_jti(self.refresh))
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")

    def test_list_marks_exactly_the_callers_session_current(self):
        response = self.client.get(reverse("sessions"))
        self.assertEqual(response.status_code, 200)
        flags = {item["id"]: item["is_current"] for item in _items(response)}
        self.assertEqual(len(flags), 3)
        self.assertEqual([sid for sid, cur in flags.items() if cur], [str(self.mine.pk)])

    def test_list_after_a_refresh_still_marks_the_session(self):
        """The rotated access token is a different jti of the same session."""
        rotated = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        self.assertEqual(rotated.status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {rotated.data['access']}")
        flags = {i["id"]: i["is_current"] for i in _items(self.client.get(reverse("sessions")))}
        self.assertTrue(flags[str(self.mine.pk)])
        self.assertEqual(sum(flags.values()), 1)

    def test_revoke_all_spares_the_caller_and_revokes_every_other(self):
        response = self.client.delete(reverse("sessions"))
        self.assertEqual(response.status_code, 200)
        alive = set(UserSession.objects.filter(user=self.user, is_revoked=False).values_list("pk", flat=True))
        self.assertEqual(alive, {self.mine.pk})
        # The caller is still signed in; the other devices are not.
        self.assertIsNotNone(jwt_provider.validate_token(self.access))
        self.assertEqual(self.client.get(reverse("me")).status_code, 200)
        self.assertIsNone(jwt_provider.validate_token(self.other_access))
        self.assertIsNone(jwt_provider.validate_token(self.third_access))

    def test_a_forged_access_token_naming_my_jti_selects_nothing(self):
        """An unsigned token carrying a real access jti must not be honoured."""
        import jwt as pyjwt

        payload = jwt_provider.handler.decode_token(self.access, verify=False)
        forged = pyjwt.encode(payload, "not-the-key", algorithm="HS256")
        request = RequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {forged}")
        request.user = self.user
        request.COOKIES = {}
        self.assertIsNone(current_session(request))

    def test_another_users_token_never_selects_my_session(self):
        stranger = _user()
        request = RequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {self.access}")
        request.user = stranger
        request.COOKIES = {}
        self.assertIsNone(current_session_jti(request))

    def test_logout_without_a_refresh_token_ends_the_bearers_session(self):
        response = self.client.post(reverse("logout"), {}, format="json")
        self.assertEqual(response.status_code, 200)
        self.mine.refresh_from_db()
        self.assertTrue(self.mine.is_revoked)
        self.client.credentials()
        refused = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        self.assertEqual(refused.status_code, 401)
        # The other devices are untouched.
        self.assertIsNotNone(jwt_provider.validate_token(self.other_access))

    def test_no_credential_spares_nothing(self):
        self.client.credentials()
        self.client.force_authenticate(self.user)
        self.client.delete(reverse("sessions"))
        self.assertFalse(UserSession.objects.filter(user=self.user, is_revoked=False).exists())


@override_settings(URL_PREFIX="", JWT_REFRESH_ALLOWED=True)
class CookieClientOwnSession(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = _user()
        self.access, self.refresh = _issue_session_tokens(self.user, None, path=SessionPath.PASSWORD)
        _issue_session_tokens(self.user, None, path=SessionPath.PASSWORD)
        self.mine = UserSession.objects.get(jti=_jti(self.refresh))
        access_name, refresh_name = jwt_cookie_names()
        self.client.cookies[access_name] = self.access
        self.client.cookies[refresh_name] = self.refresh

    def test_list_marks_the_cookie_session_current(self):
        flags = {i["id"]: i["is_current"] for i in _items(self.client.get(reverse("sessions")))}
        self.assertEqual([sid for sid, cur in flags.items() if cur], [str(self.mine.pk)])

    def test_revoke_all_spares_the_cookie_session(self):
        self.assertEqual(self.client.delete(reverse("sessions")).status_code, 200)
        alive = set(UserSession.objects.filter(user=self.user, is_revoked=False).values_list("pk", flat=True))
        self.assertEqual(alive, {self.mine.pk})

    def test_refresh_cookie_alone_identifies_the_session(self):
        """An expired access cookie re-minted by the middleware: only the
        refresh cookie names the session."""
        _access_name, refresh_name = jwt_cookie_names()
        request = RequestFactory().get("/")
        request.user = self.user
        request.COOKIES = {refresh_name: self.refresh}
        self.assertEqual(current_session_jti(request), self.mine.jti)
