"""The refresh endpoint's cryptographic trust boundary (audit AUTH-02).

What was wrong: ``_refresh_token`` decoded the submitted token with
``verify=False``, read ``user_id`` and ``jti`` out of it, loaded that user
and **signed a fresh token pair** — then, afterwards, asked the session
table whether the rotation was legitimate. A claim read from an unverified
JWT is not data, it is an argument the caller supplied; the endpoint was
minting tokens for whichever user id a stranger typed into a JWT-shaped
string, for any target that happened to have no tracked session row.

Every test here submits something that must never buy a token pair, and one
that must.
"""
import uuid
from datetime import timedelta
from unittest.mock import patch

import jwt as pyjwt
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.views import _issue_session_tokens
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


@override_settings(URL_PREFIX="")
class RefreshTrustBoundaryTests(APITestCase):
    def setUp(self):
        self.victim = _make_user(email="victim@example.com")

    def _post(self, token):
        return self.client.post(reverse("token_refresh"), {"refresh": token})

    def _config(self):
        jwt_provider._ensure_initialized()
        return jwt_provider.handler.config

    # -- the exploit itself -------------------------------------------------
    def test_forged_token_signed_with_the_wrong_key_is_refused(self):
        """The attack as described: a JWT-shaped string naming the victim."""
        config = self._config()
        forged = pyjwt.encode(
            {
                "user_id": str(self.victim.pk),
                "token_type": "refresh",
                "jti": uuid.uuid4().hex,
                "exp": 9999999999,
                "iat": 1,
                "iss": config.issuer,
            },
            "an-attacker-chosen-key",
            algorithm="HS256",
        )
        resp = self._post(forged)
        self.assertEqual(resp.status_code, 401)
        self.assertNotIn("access", resp.data)

    def test_unsigned_alg_none_token_is_refused(self):
        forged = pyjwt.encode(
            {
                "user_id": str(self.victim.pk),
                "token_type": "refresh",
                "jti": uuid.uuid4().hex,
                "exp": 9999999999,
            },
            key="",
            algorithm="none",
        )
        self.assertEqual(self._post(forged).status_code, 401)

    def test_garbage_is_refused(self):
        self.assertEqual(self._post("not.a.jwt").status_code, 401)

    # -- token confusion ----------------------------------------------------
    def test_an_access_token_is_not_a_refresh_token(self):
        """Same signing key, shorter life, far more exposure."""
        access, _ = _issue_session_tokens(
            self.victim, None, path=SessionPath.PASSWORD
        )
        self.assertEqual(self._post(access).status_code, 401)

    # -- expiry and issuer --------------------------------------------------
    def test_expired_refresh_token_is_refused(self):
        config = self._config()
        expired = pyjwt.encode(
            {
                "user_id": str(self.victim.pk),
                "token_type": "refresh",
                "jti": uuid.uuid4().hex,
                "exp": 1000,
                "iat": 1,
                "iss": config.issuer,
            },
            config.get_signing_key(),
            algorithm=config.algorithm,
        )
        self.assertEqual(self._post(expired).status_code, 401)

    def test_wrong_issuer_is_refused(self):
        config = self._config()
        if not config.issuer:
            self.skipTest("no issuer configured in this test settings module")
        wrong = pyjwt.encode(
            {
                "user_id": str(self.victim.pk),
                "token_type": "refresh",
                "jti": uuid.uuid4().hex,
                "exp": 9999999999,
                "iat": 1,
                "iss": "https://not-us.example",
            },
            config.get_signing_key(),
            algorithm=config.algorithm,
        )
        self.assertEqual(self._post(wrong).status_code, 401)

    # -- session binding ----------------------------------------------------
    def test_correctly_signed_token_with_an_unknown_jti_is_refused(self):
        """Signature alone must not be authority: the session must exist."""
        config = self._config()
        orphan = pyjwt.encode(
            {
                "user_id": str(self.victim.pk),
                "token_type": "refresh",
                "jti": uuid.uuid4().hex,
                "exp": 9999999999,
                "iat": 1,
                "iss": config.issuer,
            },
            config.get_signing_key(),
            algorithm=config.algorithm,
        )
        self.assertEqual(self._post(orphan).status_code, 401)

    def test_a_jti_belonging_to_another_user_cannot_rotate_this_one(self):
        other = _make_user(email="other@example.com")
        _issue_session_tokens(other, None, path=SessionPath.PASSWORD)
        other_session_jti = other.sessions.first().jti

        config = self._config()
        crossed = pyjwt.encode(
            {
                "user_id": str(self.victim.pk),
                "token_type": "refresh",
                "jti": other_session_jti,
                "exp": 9999999999,
                "iat": 1,
                "iss": config.issuer,
            },
            config.get_signing_key(),
            algorithm=config.algorithm,
        )
        self.assertEqual(self._post(crossed).status_code, 401)

    def test_a_replayed_refresh_token_is_refused_after_rotation(self):
        _, refresh = _issue_session_tokens(
            self.victim, None, path=SessionPath.PASSWORD
        )
        self.assertEqual(self._post(refresh).status_code, 200)
        # The same token again: its jti has been rotated away.
        self.assertEqual(self._post(refresh).status_code, 401)

    # -- rotation is a compare-and-swap, not a read-then-write -------------
    def test_rotation_reads_the_session_row_under_a_lock_in_one_transaction(self):
        """The concurrency half of AUTH-05, asserted where it is decidable.

        Two simultaneous refreshes of the same token used to both read the
        pre-rotation row, both decide "fine", and both mint — so a stolen
        refresh token stayed usable alongside the victim's. The fix is a
        locked read inside the same transaction as the write.

        The test asserts the mechanism rather than racing two threads,
        because the suite's SQLite backend has no row locks to lose:
        ``select_for_update()`` compiles to nothing there, so a race test
        would pass on a broken implementation. Here a rotation that dropped
        the lock or the transaction fails on every backend.
        """
        from django.db import connection, models

        from stapel_auth.sessions.services import SessionService

        _, refresh = _issue_session_tokens(
            self.victim, None, path=SessionPath.PASSWORD
        )
        payload = jwt_provider.handler.decode_token(refresh, verify=False)
        seen = {}
        original = models.QuerySet.select_for_update

        def _record(self, *args, **kwargs):
            seen["locked"] = True
            seen["in_atomic_block"] = connection.in_atomic_block
            return original(self, *args, **kwargs)

        with patch.object(models.QuerySet, "select_for_update", _record):
            rotated = SessionService.rotate(
                payload["jti"],
                "rotated-jti",
                timezone.now() + timedelta(days=1),
                user_id=str(self.victim.pk),
            )

        self.assertIs(rotated, True)
        self.assertTrue(seen.get("locked"), "the session row was read without a lock")
        self.assertTrue(
            seen.get("in_atomic_block"),
            "the locked read is outside a transaction, so the lock is released "
            "before the write it is supposed to protect",
        )

    # -- the happy path still works ----------------------------------------
    def test_a_real_tracked_refresh_token_still_refreshes(self):
        _, refresh = _issue_session_tokens(
            self.victim, None, path=SessionPath.PASSWORD
        )
        resp = self._post(refresh)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("access", resp.data)
        self.assertIn("refresh", resp.data)
        self.assertNotEqual(resp.data["refresh"], refresh)
