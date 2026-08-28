"""``user.merged`` — the guest's rows survive sign-in, or they are lost silently.

Guest sign-in has two halves and only one of them is free:

- the guest verifies an authenticator NOBODY holds — ``REGISTERED``. The same
  row is flipped to registered, the user id never changes, and every record
  another module owns through it carries over by identity. No event needed.
- the guest verifies an authenticator an existing account ALREADY holds —
  ``MERGED``. The guest row is DELETED. Module foreign keys are
  ``on_delete=CASCADE`` (``stapel_listings.Favorite``,
  ``stapel_chat.ConversationParticipant`` / ``Message``), so without an
  announcement the visitor's saved listings and chat history vanish at the
  moment they sign in. ``user.merged`` is that announcement.

The two walks are tested side by side on purpose: "carry-over is free on the
REGISTERED path" is a claim about the id staying the same, and it is checked
here rather than assumed.

Schema validation is forced ON for these tests, so the committed
``schemas/emits/user.merged.json`` is enforced by the emit itself — a payload
that drifts from the contract fails the request, not just an assertion.
"""
import json
from contextlib import contextmanager
from pathlib import Path

import jsonschema
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from stapel_core.comm import subscribe_action
from stapel_core.comm.registry import action_registry
from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.events import (
    EVENT_USER_CREATED,
    EVENT_USER_MERGED,
    EVENT_USER_UPDATED,
)
from stapel_auth.otp.services import EmailVerificationService, PhoneVerificationService

User = get_user_model()

MOCK_CODE = "0000"


def _schema(name):
    import stapel_auth

    path = Path(stapel_auth.__file__).parent / "schemas" / "emits" / name
    return json.loads(path.read_text())


@contextmanager
def _collecting(action, schema_file):
    """Subscribe an in-test handler to *action* and yield its delivery list.

    The handler carries the COMMITTED schema, which is the only thing that
    makes ``VALIDATE_SCHEMAS`` mean anything here: the harness does not
    install ``stapel_core.django.taskstore``, and that app's ``ready()`` is
    what normally autoloads ``schemas/emits/*.json`` into the action
    registry. Without this line the flag is on and nothing is checked.

    Both registrations are process-global and neither has an unregister, so
    they are undone by hand on exit — otherwise one test's collector counts
    the next test's events.
    """
    delivered = []

    def handler(event):
        delivered.append(event)

    had_schema = action in action_registry._schemas
    previous = action_registry._schemas.get(action)
    subscribe_action(action, handler, schema=_schema(schema_file))
    try:
        yield delivered
    finally:
        action_registry._subscribers.get(action, []).remove(handler)
        if had_schema:
            action_registry._schemas[action] = previous
        else:
            action_registry._schemas.pop(action, None)


def _topics_in_order():
    return list(OutboxEvent.objects.order_by("pk").values_list("topic", flat=True))


@override_settings(URL_PREFIX="", STAPEL_COMM={"VALIDATE_SCHEMAS": True})
class GuestSignInCarryOverTests(APITestCase):
    """The full walk: mint a guest over HTTP, then sign it in."""

    def _mint_guest(self):
        """``POST /auth/api/v1/anonymous/`` → (guest id, client holding its JWT)."""
        response = APIClient().post(reverse("anonymous"), {}, format="json")
        self.assertIn(
            response.status_code,
            [status.HTTP_200_OK, status.HTTP_201_CREATED],
            response.content,
        )
        guest_id = response.data["user"]["id"]
        self.assertTrue(response.data["user"]["is_anonymous"])
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {response.data['tokens']['access']}"
        )
        return guest_id, client

    # ── email ───────────────────────────────────────────────────────────────

    def test_email_merge_announces_the_guest_it_deletes(self):
        taken = User.objects.create_user(
            username="taken_email_holder",
            email="taken@example.com",
            password="testpass123!",
        )
        guest_id, client = self._mint_guest()
        EmailVerificationService().send_verification_code("taken@example.com")

        with _collecting(EVENT_USER_MERGED, "user.merged.json") as delivered:
            with self.captureOnCommitCallbacks(execute=True):
                response = client.post(
                    reverse("email_verify"),
                    {"email": "taken@example.com", "code": MOCK_CODE},
                )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        self.assertEqual(response.data["status"], "MERGED")
        self.assertEqual(response.data["user"]["id"], str(taken.id))

        self.assertEqual(len(delivered), 1, "user.merged must be announced exactly once")
        payload = delivered[0].payload
        self.assertEqual(
            payload,
            {
                "from_user_id": str(guest_id),
                "into_user_id": str(taken.id),
                "reason": "anonymous_promotion",
            },
        )
        jsonschema.validate(payload, _schema("user.merged.json"))

    def test_email_registration_keeps_the_same_row_and_stays_quiet(self):
        guest_id, client = self._mint_guest()
        EmailVerificationService().send_verification_code("nobody@example.com")

        with _collecting(EVENT_USER_MERGED, "user.merged.json") as delivered:
            with self.captureOnCommitCallbacks(execute=True):
                response = client.post(
                    reverse("email_verify"),
                    {"email": "nobody@example.com", "code": MOCK_CODE},
                )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        self.assertEqual(response.data["status"], "REGISTERED")
        # The proof that carry-over is free here: same id, so every FK still
        # points at a live row.
        self.assertEqual(response.data["user"]["id"], str(guest_id))
        self.assertFalse(response.data["user"]["is_anonymous"])
        self.assertTrue(User.objects.filter(id=guest_id).exists())
        self.assertEqual(delivered, [], "nothing merged — nothing to announce")
        self.assertNotIn(EVENT_USER_MERGED, _topics_in_order())

    # ── phone ───────────────────────────────────────────────────────────────

    def test_phone_merge_announces_the_guest_it_deletes(self):
        taken = User.objects.create_user(
            username="taken_phone_holder",
            phone="+12345670001",
            auth_type="phone",
        )
        guest_id, client = self._mint_guest()
        PhoneVerificationService().send_verification_code("+12345670001")

        with _collecting(EVENT_USER_MERGED, "user.merged.json") as delivered:
            with self.captureOnCommitCallbacks(execute=True):
                response = client.post(
                    reverse("phone_verify"),
                    {"phone": "+12345670001", "code": MOCK_CODE},
                )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        self.assertEqual(response.data["status"], "MERGED")
        self.assertEqual(response.data["user"]["id"], str(taken.id))

        self.assertEqual(len(delivered), 1, "user.merged must be announced exactly once")
        payload = delivered[0].payload
        self.assertEqual(
            payload,
            {
                "from_user_id": str(guest_id),
                "into_user_id": str(taken.id),
                "reason": "anonymous_promotion",
            },
        )
        jsonschema.validate(payload, _schema("user.merged.json"))

    def test_phone_registration_keeps_the_same_row_and_stays_quiet(self):
        guest_id, client = self._mint_guest()
        PhoneVerificationService().send_verification_code("+12345670002")

        with _collecting(EVENT_USER_MERGED, "user.merged.json") as delivered:
            with self.captureOnCommitCallbacks(execute=True):
                response = client.post(
                    reverse("phone_verify"),
                    {"phone": "+12345670002", "code": MOCK_CODE},
                )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        self.assertEqual(response.data["status"], "REGISTERED")
        self.assertEqual(response.data["user"]["id"], str(guest_id))
        self.assertFalse(response.data["user"]["is_anonymous"])
        self.assertTrue(User.objects.filter(id=guest_id).exists())
        self.assertEqual(delivered, [], "nothing merged — nothing to announce")
        self.assertNotIn(EVENT_USER_MERGED, _topics_in_order())


@override_settings(URL_PREFIX="", STAPEL_COMM={"VALIDATE_SCHEMAS": True})
class MergedEventIsActionableTests(APITestCase):
    """What the consumer contract needs to hold at delivery time."""

    def setUp(self):
        self.taken = User.objects.create_user(
            username="survivor",
            email="survivor@example.com",
            password="testpass123!",
        )
        response = APIClient().post(reverse("anonymous"), {}, format="json")
        self.guest_id = response.data["user"]["id"]
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {response.data['tokens']['access']}"
        )
        EmailVerificationService().send_verification_code("survivor@example.com")

    def _merge(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("email_verify"),
                {"email": "survivor@example.com", "code": MOCK_CODE},
            )
        self.assertEqual(response.data["status"], "MERGED", response.content)
        return response

    def test_the_ids_mean_what_the_payload_says_they_mean(self):
        self._merge()
        payload = json.loads(
            OutboxEvent.objects.filter(topic=EVENT_USER_MERGED).get().event_json
        )["payload"]
        # into_user_id is the one a consumer reassigns ONTO — it must exist.
        self.assertTrue(User.objects.filter(id=payload["into_user_id"]).exists())
        # from_user_id is gone from auth by the time anyone reads the event;
        # a consumer that tries to resolve it against auth finds nothing.
        self.assertFalse(User.objects.filter(id=payload["from_user_id"]).exists())
        self.assertEqual(payload["from_user_id"], str(self.guest_id))

    def test_the_survivor_is_announced_before_the_reassignment_order(self):
        """A consumer told to reassign rows onto an account it has never seen
        must have learned of that account first.

        The announcement is whatever projection event names the survivor —
        ``user.created`` at birth, ``user.updated`` when the merge itself
        moves a projected field. Either way it is in the outbox ahead of
        ``user.merged``, which is what the save-then-emit order buys.
        """
        self._merge()
        rows = [
            (row.topic, json.loads(row.event_json)["payload"])
            for row in OutboxEvent.objects.order_by("pk")
        ]
        merged_at = next(
            i for i, (topic, _) in enumerate(rows) if topic == EVENT_USER_MERGED
        )
        survivor_id = rows[merged_at][1]["into_user_id"]
        announced_at = [
            i
            for i, (topic, payload) in enumerate(rows)
            if topic in (EVENT_USER_CREATED, EVENT_USER_UPDATED)
            and payload["user_id"] == survivor_id
        ]
        self.assertTrue(announced_at, "the survivor was never projected at all")
        self.assertLess(
            min(announced_at),
            merged_at,
            "the survivor must be announced before anyone is told to "
            "reassign rows onto it",
        )

    def test_the_announcement_and_the_deletion_are_one_transaction(self):
        """The guest row is deleted only where the event is also written, so
        the pair cannot come apart under a crash."""
        self._merge()
        self.assertFalse(User.objects.filter(id=self.guest_id).exists())
        self.assertEqual(
            OutboxEvent.objects.filter(topic=EVENT_USER_MERGED).count(), 1
        )


class MergedContractTests(APITestCase):
    def test_registry_and_committed_schema_agree_on_the_payload(self):
        from dataclasses import fields

        from stapel_auth.events import EVENT_REGISTRY, UserMergedPayload

        self.assertIs(EVENT_REGISTRY[EVENT_USER_MERGED], UserMergedPayload)
        schema = _schema("user.merged.json")
        self.assertEqual(
            {f.name for f in fields(UserMergedPayload)},
            set(schema["properties"]),
        )
        self.assertEqual(schema["required"], ["from_user_id", "into_user_id"])
        self.assertFalse(schema["additionalProperties"])
