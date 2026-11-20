"""``user.session_expired``: a session that runs out unrevoked is announced.

Before this, a session ended by expiry wrote nothing anywhere, so state bound
to it elsewhere (a push device row) lived on until something unrelated
removed it. The sweep (``SessionService.announce_expired``, task
``sweep_expired_sessions``) announces each such session once.
"""
import datetime
import json
import uuid

import jsonschema
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.events import EVENT_USER_SESSION_EXPIRED, EVENT_USER_SESSION_REVOKED
from stapel_auth.models import UserSession
from stapel_auth.sessions.services import SessionService
from stapel_auth.tasks import BEAT_SCHEDULE, sweep_expired_sessions


def _user():
    return get_user_model().objects.create_user(
        email=f"{uuid.uuid4().hex[:10]}@example.com",
        username=f"u_{uuid.uuid4().hex[:10]}",
        password="testpass123!",
    )


def _payloads(topic):
    return [
        json.loads(row.event_json)["payload"]
        for row in OutboxEvent.objects.filter(topic=topic).order_by("created_at")
    ]


def _schema():
    from pathlib import Path

    import stapel_auth

    path = Path(stapel_auth.__file__).parent / "schemas" / "emits" / "user.session_expired.json"
    return json.loads(path.read_text())


class AnnounceExpiredTests(TestCase):
    def setUp(self):
        self.user = _user()
        self.now = timezone.now()

    def _session(self, *, expires_in, revoked=False):
        session = SessionService.create(
            self.user, uuid.uuid4().hex, self.now + datetime.timedelta(seconds=expires_in)
        )
        if revoked:
            SessionService.revoke_session(session)
        OutboxEvent.objects.all().delete()
        return session

    def test_expired_session_is_announced_with_a_schema_valid_payload(self):
        session = self._session(expires_in=-60)
        self.assertEqual(SessionService.announce_expired(), 1)
        payloads = _payloads(EVENT_USER_SESSION_EXPIRED)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["user_id"], str(self.user.pk))
        self.assertEqual(payloads[0]["session_id"], str(session.pk))
        jsonschema.validate(payloads[0], _schema())
        session.refresh_from_db()
        self.assertIsNotNone(session.expiry_announced_at)
        # Expiry is not revocation: the row and the security signal stay apart.
        self.assertFalse(session.is_revoked)
        self.assertEqual(_payloads(EVENT_USER_SESSION_REVOKED), [])

    def test_announced_once(self):
        self._session(expires_in=-60)
        SessionService.announce_expired()
        self.assertEqual(SessionService.announce_expired(), 0)
        self.assertEqual(len(_payloads(EVENT_USER_SESSION_EXPIRED)), 1)

    def test_live_and_revoked_sessions_are_not_announced(self):
        self._session(expires_in=3600)
        self._session(expires_in=-60, revoked=True)
        self.assertEqual(SessionService.announce_expired(), 0)
        self.assertEqual(_payloads(EVENT_USER_SESSION_EXPIRED), [])

    def test_bounded_batch_oldest_first_backlog_drains(self):
        old = self._session(expires_in=-300)
        mid = self._session(expires_in=-200)
        new = self._session(expires_in=-100)
        self.assertEqual(SessionService.announce_expired(limit=2), 2)
        first = {p["session_id"] for p in _payloads(EVENT_USER_SESSION_EXPIRED)}
        self.assertEqual(first, {str(old.pk), str(mid.pk)})
        self.assertEqual(SessionService.announce_expired(limit=2), 1)
        ids = [p["session_id"] for p in _payloads(EVENT_USER_SESSION_EXPIRED)]
        self.assertEqual(sorted(ids), sorted([str(old.pk), str(mid.pk), str(new.pk)]))

    def test_a_row_claimed_by_a_concurrent_sweep_is_not_announced_twice(self):
        from unittest import mock

        import stapel_core.comm as comm

        first = self._session(expires_in=-120)
        second = self._session(expires_in=-60)
        real_emit = comm.emit

        def emit_while_another_sweep_claims_the_next_row(*args, **kwargs):
            # Another sweeper read the same batch and committed its claim on
            # the second row after this one read the batch, before it got there.
            UserSession.objects.filter(pk=second.pk).update(expiry_announced_at=self.now)
            return real_emit(*args, **kwargs)

        with mock.patch.object(comm, "emit", side_effect=emit_while_another_sweep_claims_the_next_row):
            self.assertEqual(SessionService.announce_expired(), 1)
        ids = [p["session_id"] for p in _payloads(EVENT_USER_SESSION_EXPIRED)]
        self.assertEqual(ids, [str(first.pk)])

    def test_no_event_without_the_claim(self):
        """The event and the claim commit together: a failing emit leaves the
        row unclaimed for the next run."""
        from unittest import mock

        session = self._session(expires_in=-60)
        with mock.patch("stapel_core.comm.emit", side_effect=RuntimeError("bus down")):
            with self.assertRaises(RuntimeError):
                SessionService.announce_expired()
        session.refresh_from_db()
        self.assertIsNone(session.expiry_announced_at)
        self.assertEqual(SessionService.announce_expired(), 1)

    def test_task_and_beat_entry(self):
        self._session(expires_in=-60)
        self.assertEqual(sweep_expired_sessions(), 1)
        names = {entry["task"] for entry in BEAT_SCHEDULE.values()}
        self.assertIn("stapel_auth.tasks.sweep_expired_sessions", names)
