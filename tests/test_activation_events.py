"""user.deactivated / user.reactivated outbox events (#92).

Deactivation used to reach exactly one place — the session guard (0.15.0)
— and nothing downstream ever heard about it. These tests pin the
announcement: one event per REAL ``is_active`` transition, whoever flipped
the flag, and none at all for a re-save of an unchanged account.

They also pin the boundary that gives #92 its shape: ``user.deactivated``
is administrative and reversible; the GDPR erasure signal is a different
event (``user.deleted``) and this module must never emit it.
"""
import json
import uuid
from pathlib import Path

import jsonschema
from django.contrib.auth import get_user_model
from django.test import TestCase

from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.activation import (
    STATE_ACTIVE,
    STATE_SUSPENDED,
    account_state,
    deactivate_user,
    is_deactivated,
    reactivate_user,
)
from stapel_auth.events import (
    EVENT_REGISTRY,
    EVENT_USER_DEACTIVATED,
    EVENT_USER_REACTIVATED,
    UserDeactivatedPayload,
    UserReactivatedPayload,
)

User = get_user_model()


def _make_user(**kw):
    d = dict(
        email=f"{uuid.uuid4().hex[:10]}@example.com",
        username=f"u_{uuid.uuid4().hex[:10]}",
        password="testpass123!",
    )
    d.update(kw)
    return User.objects.create_user(**d)


def _payloads(topic):
    return [
        json.loads(row.event_json)["payload"]
        for row in OutboxEvent.objects.filter(topic=topic).order_by("created_at")
    ]


def _schema(name):
    import stapel_auth

    path = Path(stapel_auth.__file__).parent / "schemas" / "emits" / name
    return json.loads(path.read_text())


class DeactivationEventTests(TestCase):
    def test_deactivate_emits_once_and_validates_schema(self):
        user = _make_user()
        self.assertTrue(deactivate_user(user, reason="abuse"))
        user.refresh_from_db()
        self.assertFalse(user.is_active)

        payloads = _payloads(EVENT_USER_DEACTIVATED)
        self.assertEqual(
            payloads, [{"user_id": str(user.pk), "reason": "abuse"}]
        )
        jsonschema.validate(payloads[0], _schema("user.deactivated.json"))

    def test_actor_rides_the_payload(self):
        user = _make_user()
        actor = _make_user(is_staff=True)
        deactivate_user(user, reason="abuse", actor=actor)
        self.assertEqual(
            _payloads(EVENT_USER_DEACTIVATED),
            [{
                "user_id": str(user.pk),
                "actor_id": str(actor.pk),
                "reason": "abuse",
            }],
        )

    def test_reasonless_payload_omits_the_optional_fields(self):
        """The admin checkbox carries no reason and no actor — the payload
        must then simply not have the keys (the schema forbids nulls)."""
        user = _make_user()
        deactivate_user(user)
        payloads = _payloads(EVENT_USER_DEACTIVATED)
        self.assertEqual(payloads, [{"user_id": str(user.pk)}])
        jsonschema.validate(payloads[0], _schema("user.deactivated.json"))

    def test_second_deactivation_is_a_no_op(self):
        """Idempotence at the source: the second call is not a transition."""
        user = _make_user()
        self.assertTrue(deactivate_user(user))
        self.assertFalse(deactivate_user(user))
        self.assertEqual(len(_payloads(EVENT_USER_DEACTIVATED)), 1)

    def test_resaving_a_deactivated_user_emits_nothing(self):
        user = _make_user()
        deactivate_user(user)
        user.first_name = "Renamed"
        user.save()
        self.assertEqual(len(_payloads(EVENT_USER_DEACTIVATED)), 1)

    def test_raw_flag_flip_announces_too(self):
        """No service call: the field is flipped and saved, as an admin
        checkbox or a management shell does. The observer still announces —
        that is the whole reason it watches the field, not the call site."""
        user = _make_user()
        user.is_active = False
        user.save(update_fields=["is_active"])
        self.assertEqual(
            _payloads(EVENT_USER_DEACTIVATED), [{"user_id": str(user.pk)}]
        )

    def test_creating_an_inactive_user_emits_nothing(self):
        """An insert has no previous state, so it is not a transition."""
        _make_user(is_active=False)
        self.assertEqual(_payloads(EVENT_USER_DEACTIVATED), [])

    def test_unrelated_save_emits_nothing(self):
        user = _make_user()
        user.first_name = "Whoever"
        user.save(update_fields=["first_name"])
        self.assertEqual(_payloads(EVENT_USER_DEACTIVATED), [])
        self.assertEqual(_payloads(EVENT_USER_REACTIVATED), [])


class ReactivationEventTests(TestCase):
    def test_reactivate_emits_and_validates_schema(self):
        user = _make_user()
        deactivate_user(user)
        self.assertTrue(reactivate_user(user))
        user.refresh_from_db()
        self.assertTrue(user.is_active)

        payloads = _payloads(EVENT_USER_REACTIVATED)
        self.assertEqual(payloads, [{"user_id": str(user.pk)}])
        jsonschema.validate(payloads[0], _schema("user.reactivated.json"))

    def test_reactivating_an_active_user_is_a_no_op(self):
        user = _make_user()
        self.assertFalse(reactivate_user(user))
        self.assertEqual(_payloads(EVENT_USER_REACTIVATED), [])

    def test_actor_rides_the_reactivation_payload(self):
        user = _make_user()
        actor = _make_user(is_staff=True)
        deactivate_user(user)
        reactivate_user(user, actor=actor)
        self.assertEqual(
            _payloads(EVENT_USER_REACTIVATED),
            [{"user_id": str(user.pk), "actor_id": str(actor.pk)}],
        )

    def test_round_trip_leaves_one_event_each_way(self):
        user = _make_user()
        deactivate_user(user)
        reactivate_user(user)
        deactivate_user(user)
        self.assertEqual(len(_payloads(EVENT_USER_DEACTIVATED)), 2)
        self.assertEqual(len(_payloads(EVENT_USER_REACTIVATED)), 1)


class ActivationStateTests(TestCase):
    def test_state_vocabulary_tracks_the_session_guard(self):
        """``is_deactivated`` is the guard's own predicate, not a second
        reading of ``is_active`` — the two can never drift."""
        from stapel_auth.sessions.guard import account_disabled_error

        user = _make_user()
        self.assertEqual(account_state(user), STATE_ACTIVE)
        self.assertFalse(is_deactivated(user))
        self.assertIsNone(account_disabled_error(user))

        deactivate_user(user)
        self.assertEqual(account_state(user), STATE_SUSPENDED)
        self.assertTrue(is_deactivated(user))
        self.assertIsNotNone(account_disabled_error(user))

    def test_deactivation_is_not_a_deletion(self):
        """The account row and its auth records survive: ``suspended`` and
        ``deleted`` are different states with different mechanisms, and
        nothing in this path emits the GDPR signal."""
        user = _make_user()
        deactivate_user(user, reason="abuse")
        self.assertTrue(User.objects.filter(pk=user.pk).exists())
        self.assertEqual(OutboxEvent.objects.filter(topic="user.deleted").count(), 0)

    def test_events_are_registered(self):
        self.assertEqual(EVENT_USER_DEACTIVATED, "user.deactivated")
        self.assertEqual(EVENT_USER_REACTIVATED, "user.reactivated")
        self.assertIs(EVENT_REGISTRY[EVENT_USER_DEACTIVATED], UserDeactivatedPayload)
        self.assertIs(EVENT_REGISTRY[EVENT_USER_REACTIVATED], UserReactivatedPayload)
