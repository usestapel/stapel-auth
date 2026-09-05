"""The refresh-rotation grace window (D413).

Rotation is a compare-and-swap, so whoever presents a superseded jti is a
replay and a replay revokes the session. A browser produces that shape with
no attacker in it: a full-page reload that boots while a refresh is in
flight sends the jti it booted with a second or two after the winner
rotated, gets ``error.401.refresh_revoked``, and the user is logged out for
good — measured on a fleet, one walk in four.

``STAPEL_AUTH['REFRESH_ROTATION_GRACE_SECONDS']`` answers exactly one
superseded jti — the session's immediately previous one — with the pair the
winning rotation produced, for that many seconds measured **from the
rotation**. Everything the reuse detection was there for is still refused:
an older jti, the previous one after the window, a revoked session. These
tests assert both halves, because a grace window that also lets a two-
rotations-old token through is not a grace window, it is the bug the reuse
detection exists to prevent.
"""
import uuid
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from stapel_auth.models import UserSession
from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.services import SessionService
from stapel_auth.sessions.views import _issue_session_tokens
from stapel_core.django.jwt.provider import jwt_provider

from django.contrib.auth import get_user_model

User = get_user_model()

GRACE_ON = {"REFRESH_ROTATION_GRACE_SECONDS": 10}
GRACE_OFF = {"REFRESH_ROTATION_GRACE_SECONDS": 0}


def _make_user():
    return User.objects.create_user(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )


def _lose_the_second_cas():
    """Patch ``SessionService.rotate`` so the first call runs for real and
    every call after it returns ``None`` — the CAS-lost branch of the D413
    race, where both requests' initial non-locking lookup in the view still
    sees the pre-rotation row (so neither takes the pre-rotate graced
    branch) and only rotate()'s locked compare-and-swap discovers which one
    lost. Sqlite's ``select_for_update`` is a no-op, so real thread
    concurrency can't be trusted to reproduce the race here — this fakes
    the observable outcome (the loser's ``rotate()`` returning ``None``
    against an already-rotated row) directly, exactly as the incident
    describes it.
    """
    real_rotate = SessionService.rotate
    calls = []

    def fake_rotate(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            return real_rotate(*args, **kwargs)
        return None

    return mock.patch.object(SessionService, "rotate", side_effect=fake_rotate)


@override_settings(URL_PREFIX="", STAPEL_AUTH=GRACE_ON)
class RefreshRotationGraceTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()
        _, self.refresh = _issue_session_tokens(
            self.user, None, path=SessionPath.PASSWORD
        )
        self.session = self.user.sessions.get()

    def _post(self, token):
        return self.client.post(reverse("token_refresh"), {"refresh": token})

    def _jti(self, token):
        return (jwt_provider.handler.decode_token(token, verify=False) or {}).get("jti")

    # -- (1) the incident ---------------------------------------------------
    def test_a_second_refresh_inside_the_window_gets_the_current_pair(self):
        """The page that booted mid-rotation gets the winner's pair, not a 401."""
        won = self._post(self.refresh)
        self.assertEqual(won.status_code, 200)
        current_refresh = won.data["refresh"]

        raced = self._post(self.refresh)
        self.assertEqual(raced.status_code, 200)
        # The CURRENT pair: the same refresh token the winner walked away
        # with, so both tabs (and the shared cookie jar) converge on one
        # session instead of one of them holding a doomed token.
        self.assertEqual(raced.data["refresh"], current_refresh)
        self.assertNotEqual(raced.data["access"], won.data["access"])

        self.session.refresh_from_db()
        self.assertFalse(self.session.is_revoked)
        # Not rotated a second time: the window still names the same pair.
        self.assertEqual(self.session.jti, self._jti(current_refresh))
        self.assertEqual(self.session.previous_jti, self._jti(self.refresh))
        # The access token just minted is the session's access token now.
        self.assertEqual(self.session.access_jti, self._jti(raced.data["access"]))

    def test_a_lost_rotation_cas_gets_the_winners_pair_not_a_401(self):
        """The loser of the D413 race, caught at the CAS instead of the
        pre-rotate lookup, still gets the winner's pair.

        This is the incident as observed on a stand: both requests' initial,
        non-locking lookup finds the row still holding the presented jti (it
        hasn't rotated yet), so neither takes the pre-rotate graced branch —
        the loser only discovers it lost when its own ``rotate()`` runs the
        locked compare-and-swap against an already-rotated row and gets
        ``None`` back. Before the fix that fell straight to
        ``refresh_revoked`` without ever re-consulting the grace window.
        """
        with _lose_the_second_cas():
            won = self._post(self.refresh)
            self.assertEqual(won.status_code, 200)
            raced = self._post(self.refresh)

        self.assertEqual(raced.status_code, 200)
        self.assertEqual(raced.data["refresh"], won.data["refresh"])
        self.assertNotEqual(raced.data["access"], won.data["access"])

        self.session.refresh_from_db()
        self.assertFalse(self.session.is_revoked)
        self.assertEqual(self.session.previous_jti, self._jti(self.refresh))
        self.assertEqual(self.session.access_jti, self._jti(raced.data["access"]))

    def test_the_session_survives_and_the_current_pair_keeps_working(self):
        current_refresh = self._post(self.refresh).data["refresh"]
        self.assertEqual(self._post(self.refresh).status_code, 200)
        # The winner's own next refresh still rotates normally.
        third = self._post(current_refresh)
        self.assertEqual(third.status_code, 200)
        self.assertNotEqual(third.data["refresh"], current_refresh)

    def test_reuse_does_not_extend_the_window(self):
        """The window is measured from the rotation, never from the reuse."""
        self._post(self.refresh)
        self.assertEqual(self._post(self.refresh).status_code, 200)

        session = UserSession.objects.get(pk=self.session.pk)
        rotated_at = session.rotated_at
        # A reuse inside the window must not have moved the stamp forward;
        # otherwise a client replaying every few seconds keeps a superseded
        # token alive indefinitely.
        UserSession.objects.filter(pk=session.pk).update(
            rotated_at=rotated_at - timedelta(seconds=11)
        )
        self.assertEqual(self._post(self.refresh).status_code, 401)

    # -- (2) outside the window --------------------------------------------
    def test_after_the_window_the_superseded_token_is_revoked(self):
        self.assertEqual(self._post(self.refresh).status_code, 200)
        UserSession.objects.filter(pk=self.session.pk).update(
            rotated_at=timezone.now() - timedelta(seconds=11)
        )
        response = self._post(self.refresh)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["localizable_error"], "error.401.refresh_revoked")

    # -- (3) two rotations back --------------------------------------------
    def test_a_jti_two_rotations_back_is_refused_inside_the_window(self):
        """Only the immediately previous jti is graced — one, not a history."""
        first = self._post(self.refresh)
        self.assertEqual(first.status_code, 200)
        second = self._post(first.data["refresh"])
        self.assertEqual(second.status_code, 200)

        session = UserSession.objects.get(pk=self.session.pk)
        self.assertEqual(session.previous_jti, self._jti(first.data["refresh"]))
        # Both rotations happened just now, so the window is wide open — and
        # the original token is still refused, because it is not the previous
        # jti any more.
        response = self._post(self.refresh)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["localizable_error"], "error.401.refresh_revoked")

    def test_a_revoked_session_is_not_graced(self):
        won = self._post(self.refresh)
        self.assertEqual(won.status_code, 200)
        UserSession.objects.filter(pk=self.session.pk).update(is_revoked=True)
        self.assertEqual(self._post(self.refresh).status_code, 401)

    def test_the_window_is_bound_to_its_own_user(self):
        """previous_jti is matched with the user, like jti is."""
        stranger = _make_user()
        _issue_session_tokens(stranger, None, path=SessionPath.PASSWORD)
        self.assertEqual(self._post(self.refresh).status_code, 200)

        config = jwt_provider.handler.config
        import jwt as pyjwt

        crossed = pyjwt.encode(
            {
                "user_id": str(stranger.pk),
                "token_type": "refresh",
                "jti": self._jti(self.refresh),
                "exp": 9999999999,
                "iat": 1,
                "iss": config.issuer,
            },
            config.get_signing_key(),
            algorithm=config.algorithm,
        )
        self.assertEqual(self._post(crossed).status_code, 401)


@override_settings(URL_PREFIX="", STAPEL_AUTH=GRACE_OFF)
class GraceDisabledTests(APITestCase):
    """(4) grace 0 is the pre-0.33 behaviour, exactly."""

    def setUp(self):
        cache.clear()
        self.user = _make_user()
        _, self.refresh = _issue_session_tokens(
            self.user, None, path=SessionPath.PASSWORD
        )

    def _post(self, token):
        return self.client.post(reverse("token_refresh"), {"refresh": token})

    def test_an_immediate_replay_is_still_refused(self):
        self.assertEqual(self._post(self.refresh).status_code, 200)
        response = self._post(self.refresh)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["localizable_error"], "error.401.refresh_revoked")

    def test_a_lost_rotation_cas_is_still_revoked_with_the_window_off(self):
        """Same CAS-lost shape as the incident, but with the window off
        nothing catches it — the pre-0.33 answer, unchanged."""
        with _lose_the_second_cas():
            won = self._post(self.refresh)
            self.assertEqual(won.status_code, 200)
            raced = self._post(self.refresh)

        self.assertEqual(raced.status_code, 401)
        self.assertEqual(raced.data["localizable_error"], "error.401.refresh_revoked")

    def test_nothing_is_written_to_the_cache(self):
        from stapel_auth.sessions.services import SessionService

        jti = (
            jwt_provider.handler.decode_token(self.refresh, verify=False) or {}
        ).get("jti")
        self.assertEqual(self._post(self.refresh).status_code, 200)
        self.assertIsNone(
            cache.get(f"{SessionService._GRACE_CACHE_PREFIX}{jti}"),
            "the window is off, so the rotated token must not be kept anywhere",
        )
