"""A superseded refresh token presented again ends the session it belonged to.

Rotation makes a refresh token single-use. The same token coming back after
its successor was issued — outside the D413 grace window — means two parties
hold it; refusing only the late one left whoever rotated first (possibly the
thief) holding a live session.
"""
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from stapel_auth.models import UserSession
from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.views import _issue_session_tokens

User = get_user_model()


@override_settings(URL_PREFIX="", STAPEL_AUTH={"REFRESH_ROTATION_GRACE_SECONDS": 10})
class RefreshReuseDetectionTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            email=f"{uuid.uuid4().hex[:8]}@example.com",
            username=uuid.uuid4().hex[:12],
            password="testpass123",
        )
        _, self.refresh = _issue_session_tokens(self.user, None, path=SessionPath.PASSWORD)
        self.session = self.user.sessions.get()

    def _post(self, token):
        return self.client.post(reverse("token_refresh"), {"refresh": token})

    def test_reuse_after_the_window_revokes_the_whole_session(self):
        rotated = self._post(self.refresh)
        self.assertEqual(rotated.status_code, 200)
        successor = rotated.data["refresh"]
        UserSession.objects.filter(pk=self.session.pk).update(
            rotated_at=timezone.now() - timedelta(seconds=11)
        )

        replay = self._post(self.refresh)
        self.assertEqual(replay.status_code, 401)
        self.assertTrue(UserSession.objects.get(pk=self.session.pk).is_revoked)
        # The successor dies with the session — whoever holds it.
        self.assertEqual(self._post(successor).status_code, 401)

    def test_a_racing_tab_inside_the_window_revokes_nothing(self):
        self.assertEqual(self._post(self.refresh).status_code, 200)
        self.assertEqual(self._post(self.refresh).status_code, 200)
        self.assertFalse(UserSession.objects.get(pk=self.session.pk).is_revoked)
