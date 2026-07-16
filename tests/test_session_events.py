"""user.session_created / user.session_revoked outbox events.

The schemas (schemas/emits/user.session_*.json) existed without any emit —
a silent contract lie. SessionService now writes both events to the
transactional outbox atomically with the UserSession row change, mirroring
staff_roles. These tests pin the emission points and validate the wire
payloads against the published schemas.
"""
import datetime
import json
import uuid

import jsonschema
from django.contrib.auth import get_user_model
from django.test import TestCase

from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.events import (
    EVENT_USER_SESSION_CREATED,
    EVENT_USER_SESSION_REVOKED,
)
from stapel_auth.sessions.services import SessionService


def _make_user(**kwargs):
    defaults = dict(
        email=f"{uuid.uuid4().hex[:10]}@example.com",
        username=f"u_{uuid.uuid4().hex[:10]}",
        password="testpass123!",
    )
    defaults.update(kwargs)
    return get_user_model().objects.create_user(**defaults)


def _event_payloads(topic):
    return [
        json.loads(row.event_json)["payload"]
        for row in OutboxEvent.objects.filter(topic=topic).order_by("created_at")
    ]


def _schema(name):
    from pathlib import Path

    import stapel_auth

    path = Path(stapel_auth.__file__).parent / "schemas" / "emits" / name
    return json.loads(path.read_text())


def _expires():
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)


class SessionCreatedEventTests(TestCase):
    def test_create_emits_schema_valid_payload(self):
        user = _make_user()
        session = SessionService.create(user, uuid.uuid4().hex, _expires())
        payloads = _event_payloads(EVENT_USER_SESSION_CREATED)
        self.assertEqual(len(payloads), 1)
        payload = payloads[0]
        self.assertEqual(payload["user_id"], str(user.pk))
        self.assertEqual(payload["session_id"], str(session.pk))
        # additionalProperties: false + required fields — the schema is law.
        jsonschema.validate(payload, _schema("user.session_created.json"))
        # No request → no IP; the non-nullable schema field must be absent.
        self.assertNotIn("ip_address", payload)


class SessionRevokedEventTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def _create_session(self, jti=None):
        # Sessions are created via the service (which emits created-events);
        # cut the noise so revoked-assertions start from a clean outbox.
        session = SessionService.create(self.user, jti or uuid.uuid4().hex, _expires())
        OutboxEvent.objects.all().delete()
        return session

    def test_revoke_by_jti_emits_once(self):
        session = self._create_session()
        self.assertTrue(SessionService.revoke_by_jti(session.jti))
        payloads = _event_payloads(EVENT_USER_SESSION_REVOKED)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["user_id"], str(self.user.pk))
        self.assertEqual(payloads[0]["session_id"], str(session.pk))
        jsonschema.validate(payloads[0], _schema("user.session_revoked.json"))

    def test_revoke_by_jti_idempotent_no_duplicate_event(self):
        session = self._create_session()
        self.assertTrue(SessionService.revoke_by_jti(session.jti))
        # Re-revoking still reports "row exists" but must not emit again.
        self.assertTrue(SessionService.revoke_by_jti(session.jti))
        self.assertEqual(len(_event_payloads(EVENT_USER_SESSION_REVOKED)), 1)

    def test_revoke_by_jti_missing_session_no_event(self):
        self.assertFalse(SessionService.revoke_by_jti("no-such-jti"))
        self.assertEqual(_event_payloads(EVENT_USER_SESSION_REVOKED), [])

    def test_revoke_session_emits_and_is_idempotent(self):
        session = self._create_session()
        SessionService.revoke_session(session)
        SessionService.revoke_session(session)
        payloads = _event_payloads(EVENT_USER_SESSION_REVOKED)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["session_id"], str(session.pk))

    def test_revoke_all_emits_per_session_and_honors_except_jti(self):
        keep = self._create_session(jti="keep-jti")
        s1 = SessionService.create(self.user, "gone-1", _expires())
        s2 = SessionService.create(self.user, "gone-2", _expires())
        OutboxEvent.objects.all().delete()

        SessionService.revoke_all(self.user, except_jti="keep-jti")

        payloads = _event_payloads(EVENT_USER_SESSION_REVOKED)
        revoked_ids = {p["session_id"] for p in payloads}
        self.assertEqual(revoked_ids, {str(s1.pk), str(s2.pk)})
        self.assertNotIn(str(keep.pk), revoked_ids)
        keep.refresh_from_db()
        self.assertFalse(keep.is_revoked)
