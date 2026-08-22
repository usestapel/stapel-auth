"""user.created / user.updated — the owner-emitted user projection.

Two halves, pinned together on purpose.

The **owner** half asserts that a user row cannot be born in this module
without being announced: not through the OTP registration flow, not through
the login-grant guest mint, not through a bare ``create_user`` in a shell or
a data migration. That "whoever wrote it" property is the reason the emit
hangs off ``post_save`` instead of the six service functions, and it is what
a consumer's foreign keys end up depending on.

The **consumer** half asserts the property the whole design rests on: the
event path and the JWT path are the same writer. A row minted from a token
and then hit by a replayed event is one row, not two; an event applied twice
is one row; and the payload a consumer receives is byte-identical to the
claim set it would have received in a token.
"""
import json
import uuid
from pathlib import Path
from unittest import mock

import jsonschema
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from rest_framework.test import APIClient, APITestCase

from stapel_core.django.jwt.utils import serialize_user_to_jwt_data
from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.events import (
    EVENT_REGISTRY,
    EVENT_USER_CREATED,
    EVENT_USER_UPDATED,
    UserProjectionPayload,
)
from stapel_auth.user_projection import PROJECTED_FIELDS, projection_payload, replay

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


class ProjectionEventRegistryTests(TestCase):
    def test_registry_knows_both_names(self):
        self.assertEqual(EVENT_USER_CREATED, "user.created")
        self.assertEqual(EVENT_USER_UPDATED, "user.updated")
        self.assertIs(EVENT_REGISTRY[EVENT_USER_CREATED], UserProjectionPayload)
        self.assertIs(EVENT_REGISTRY[EVENT_USER_UPDATED], UserProjectionPayload)

    def test_schemas_are_committed_and_agree_with_each_other(self):
        created = _schema("user.created.json")
        updated = _schema("user.updated.json")
        # Same shape by design: user.updated carries the full claim set, not a
        # delta, so a consumer that missed the birth still lands a valid row.
        self.assertEqual(created["properties"], updated["properties"])
        self.assertEqual(created["required"], updated["required"])
        self.assertFalse(created["additionalProperties"])

    def test_schema_admits_exactly_the_jwt_claim_set(self):
        """The contract cannot drift from the serializer without failing here.

        This is the load-bearing assertion of the whole design: the payload is
        not a hand-picked field list, it is ``serialize_user_to_jwt_data``. A
        claim added there must be added to the schema, or every emit starts
        failing ``additionalProperties: false``.
        """
        staff = _make_user(is_staff=True, phone="+13115552368")
        staff.staff_roles = ["support"]
        staff.save()
        claims = serialize_user_to_jwt_data(staff)
        allowed = set(_schema("user.created.json")["properties"])
        self.assertEqual(set(claims) - allowed, set())
        # And the fields that are always present really are.
        self.assertLessEqual(set(_schema("user.created.json")["required"]), set(claims))


class OwnerEmissionTests(TestCase):
    """A user row cannot be born here without being announced."""

    def test_bare_create_emits_user_created_and_validates(self):
        user = _make_user()
        payloads = _payloads(EVENT_USER_CREATED)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["user_id"], str(user.pk))
        self.assertEqual(payloads[0]["email"], user.email)
        jsonschema.validate(payloads[0], _schema("user.created.json"))

    def test_payload_is_the_jwt_claim_set_verbatim(self):
        user = _make_user()
        self.assertEqual(
            _payloads(EVENT_USER_CREATED)[0], serialize_user_to_jwt_data(user)
        )
        self.assertEqual(projection_payload(user), serialize_user_to_jwt_data(user))

    def test_staff_roles_ride_along_for_staff_only(self):
        plain = _make_user()
        self.assertNotIn("staff_roles", projection_payload(plain))
        staff = _make_user(is_staff=True)
        staff.staff_roles = ["support", "auditor"]
        staff.save()
        # The birth event carries no roles yet (the field is set afterwards);
        # the update event does, sorted, exactly as the JWT claim would be.
        self.assertEqual(
            _payloads(EVENT_USER_UPDATED)[-1]["staff_roles"], ["auditor", "support"]
        )

    def test_projected_change_emits_user_updated(self):
        user = _make_user()
        user.email = "moved@example.com"
        user.save()
        payloads = _payloads(EVENT_USER_UPDATED)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["email"], "moved@example.com")
        self.assertEqual(payloads[0]["user_id"], str(user.pk))
        jsonschema.validate(payloads[0], _schema("user.updated.json"))

    def test_resaving_an_unchanged_user_says_nothing(self):
        user = _make_user()
        user.save()
        user.save()
        self.assertEqual(_payloads(EVENT_USER_UPDATED), [])

    def test_a_write_that_cannot_touch_a_projected_field_says_nothing(self):
        """``update_last_login`` is the hottest write in the module; it must
        not cost a SELECT, let alone an outbox row."""
        user = _make_user()
        with mock.patch(
            "stapel_auth.user_projection.projection_payload"
        ) as payload_of:
            user.last_login = user.date_joined
            user.save(update_fields=["last_login"])
        payload_of.assert_not_called()
        self.assertEqual(_payloads(EVENT_USER_UPDATED), [])

    def test_deactivation_announces_both_facts(self):
        """``user.deactivated`` says what happened; ``user.updated`` carries
        the field a shadow row has to mirror. Different consumers, both
        needed — the overlap is deliberate, not a double-emit bug."""
        from stapel_auth.activation import deactivate_user
        from stapel_auth.events import EVENT_USER_DEACTIVATED

        user = _make_user()
        deactivate_user(user, reason="abuse")
        self.assertEqual(len(_payloads(EVENT_USER_DEACTIVATED)), 1)
        self.assertIs(_payloads(EVENT_USER_UPDATED)[-1]["is_active"], False)

    def test_loaddata_is_silent(self):
        """``raw=True`` writes (fixtures) describe state being loaded, not a
        transition anyone should hear about."""
        from django.db.models.signals import post_save, pre_save

        user = _make_user()
        OutboxEvent.objects.all().delete()
        pre_save.send(sender=User, instance=user, raw=True)
        post_save.send(sender=User, instance=user, created=True, raw=True)
        self.assertEqual(OutboxEvent.objects.count(), 0)

    def test_a_failed_outbox_write_takes_the_user_row_with_it(self):
        """Outbox discipline, not best-effort fan-out.

        ``user.registered`` is a milestone and is swallowed on failure —
        a signup must not depend on a listener. ``user.created`` is the
        opposite kind of fact: a consumer's foreign keys resolve against it,
        so an account whose birth nobody recorded is precisely the silent
        defect this module closes. It commits with its row or not at all.
        Note what this does *not* couple to: the outbox write is a DB write
        to the same database, so a broker outage cannot reach it — only a
        failure that would have failed the user insert anyway.
        """
        from stapel_core.comm import actions

        def explode(event):
            raise RuntimeError("outbox write failed")

        with mock.patch.object(actions, "_emit_via_outbox", explode):
            with self.assertRaises(RuntimeError):
                _make_user()

    def test_replay_reannounces_existing_users_as_created(self):
        first, second = _make_user(), _make_user()
        OutboxEvent.objects.all().delete()
        self.assertEqual(replay(), 2)
        ids = {p["user_id"] for p in _payloads(EVENT_USER_CREATED)}
        self.assertEqual(ids, {str(first.pk), str(second.pk)})

    def test_backfill_command_runs(self):
        from io import StringIO

        from django.core.management import call_command

        _make_user()
        OutboxEvent.objects.all().delete()
        out = StringIO()
        call_command("emit_user_projection", "--dry-run", stdout=out)
        self.assertIn("would be announced", out.getvalue())
        self.assertEqual(OutboxEvent.objects.count(), 0)
        call_command("emit_user_projection", stdout=out)
        self.assertEqual(len(_payloads(EVENT_USER_CREATED)), 1)


class RegistrationFlowEmissionTests(APITestCase):
    """The two flows the fleet actually mints accounts through."""

    def setUp(self):
        from django.core.cache import cache

        cache.clear()
        self.client = APIClient()

    def test_otp_registration_emits_created(self):
        email = f"reg_{uuid.uuid4().hex[:8]}@example.com"
        self.client.post(reverse("email_request"), {"email": email})
        resp = self.client.post(
            reverse("email_verify"), {"email": email, "code": "0000"}
        )
        self.assertEqual(resp.status_code, 200)
        created = [p for p in _payloads(EVENT_USER_CREATED) if p["email"] == email]
        self.assertEqual(len(created), 1)
        jsonschema.validate(created[0], _schema("user.created.json"))

    def test_anonymous_guest_mint_emits_created(self):
        resp = self.client.post(reverse("anonymous"), {})
        self.assertEqual(resp.status_code, 201)
        guests = [
            p for p in _payloads(EVENT_USER_CREATED) if p.get("is_anonymous") is True
        ]
        self.assertEqual(len(guests), 1)
        self.assertEqual(guests[0]["auth_type"], "anonymous")
        jsonschema.validate(guests[0], _schema("user.created.json"))

    @override_settings(STAPEL_AUTH={"AUTH_LOGIN_GRANT": True})
    def test_login_grant_provisioning_emits_created(self):
        from stapel_auth.login_grant.services import (
            LoginGrantService,
            issue_login_grant,
        )

        token = issue_login_grant(
            email="granted@example.com", create_if_missing=True, language="ru"
        )
        user, created = LoginGrantService.exchange(token)
        self.assertTrue(created)
        granted = [
            p for p in _payloads(EVENT_USER_CREATED)
            if p["email"] == "granted@example.com"
        ]
        self.assertEqual(len(granted), 1)
        self.assertEqual(granted[0]["user_id"], str(user.pk))


@override_settings(JWT_CREATE_USERS_FROM_TOKEN=True)
class ConsumerTests(TestCase):
    """The reusable component — ``stapel_auth.projection``.

    The consumer's shadow table is, in this single-module harness, the same
    ``users`` table the owner writes. That is enough to pin what matters:
    the handler is the *same* materializer the JWT middleware uses, so a
    replayed event over a token-minted row is a no-op field sync rather than
    a second account.

    The class-level override is the harness telling the truth about which
    kind of service it is pretending to be: this suite's settings ship
    ``JWT_CREATE_USERS_FROM_TOKEN=False`` because they configure the identity
    *owner*, and a consumer is by definition the other answer.
    """

    def setUp(self):
        from stapel_auth.projection import handlers

        self.handlers = handlers

    def _event(self, payload, event_type=EVENT_USER_CREATED):
        from stapel_core.bus import Event

        return Event(event_type=event_type, service="auth", payload=payload)

    def test_the_two_topics_are_subscribed(self):
        from stapel_core.comm.registry import action_registry

        self.assertIn(EVENT_USER_CREATED, action_registry.names())
        self.assertIn(EVENT_USER_UPDATED, action_registry.names())

    def test_projects_a_user_this_service_has_never_seen(self):
        """The bug, in one test: a payload naming a user with no local row."""
        stranger_id = str(uuid.uuid4())
        payload = {
            "user_id": stranger_id,
            "username": f"seller_{uuid.uuid4().hex[:8]}",
            "email": "seller@example.com",
            "is_staff": False,
            "is_superuser": False,
            "is_active": True,
            "auth_type": "email",
            "is_anonymous": False,
        }
        self.assertFalse(User.objects.filter(pk=stranger_id).exists())
        self.handlers.project_user_created(self._event(payload))
        user = User.objects.get(pk=stranger_id)
        self.assertEqual(user.email, "seller@example.com")
        self.assertFalse(user.has_usable_password())

    def test_redelivery_is_idempotent(self):
        payload = projection_payload(_make_user())
        before = User.objects.count()
        self.handlers.project_user_created(self._event(payload))
        self.handlers.project_user_created(self._event(payload))
        self.assertEqual(User.objects.count(), before)

    def test_a_jwt_minted_row_then_an_event_replay_is_one_row(self):
        """The two writers meet on the same row — the divergence this design
        is built to make impossible."""
        from stapel_core.django.jwt.utils import get_or_create_user_from_jwt

        claims = {
            "user_id": str(uuid.uuid4()),
            "username": f"buyer_{uuid.uuid4().hex[:8]}",
            "email": "buyer@example.com",
            "is_staff": False,
            "is_superuser": False,
            "is_active": True,
        }
        from_token = get_or_create_user_from_jwt(claims)
        self.assertIsNotNone(from_token)
        before = User.objects.count()

        self.handlers.project_user_created(self._event(claims))
        self.handlers.project_user_updated(self._event(claims, EVENT_USER_UPDATED))
        self.assertEqual(User.objects.count(), before)
        self.assertEqual(
            str(User.objects.get(pk=claims["user_id"]).pk), str(from_token.pk)
        )

    def test_update_syncs_fields_onto_an_existing_row(self):
        user = _make_user()
        payload = dict(projection_payload(user), email="renamed@example.com")
        self.handlers.project_user_updated(self._event(payload, EVENT_USER_UPDATED))
        user.refresh_from_db()
        self.assertEqual(user.email, "renamed@example.com")

    @override_settings(JWT_CREATE_USERS_FROM_TOKEN=False)
    def test_the_identity_owner_ignores_its_own_facts(self):
        """A service that refuses to mint users from a token owns the
        original table; it must not mint them from an event either."""
        stranger_id = str(uuid.uuid4())
        payload = {
            "user_id": stranger_id,
            "username": "ghost",
            "email": None,
            "is_staff": False,
            "is_superuser": False,
            "is_active": True,
        }
        self.assertIsNone(self.handlers.apply_user_projection(payload))
        self.assertFalse(User.objects.filter(pk=stranger_id).exists())

    def test_a_payload_with_no_user_id_is_refused_loudly(self):
        with self.assertRaises(ValueError):
            self.handlers.apply_user_projection({"email": "x@example.com"})

    def test_a_failed_projection_raises_so_the_transport_can_retry(self):
        with mock.patch(
            "stapel_core.django.jwt.utils.get_or_create_user_from_jwt",
            return_value=None,
        ):
            with self.assertRaises(RuntimeError):
                self.handlers.apply_user_projection({"user_id": str(uuid.uuid4())})


class ProjectedFieldsTests(TestCase):
    def test_every_projected_field_is_real_on_the_stapel_user(self):
        concrete = {f.attname for f in User._meta.concrete_fields}
        self.assertEqual(set(PROJECTED_FIELDS) - concrete, set())
