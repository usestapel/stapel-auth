"""A guest account is an account, so it reaches the registration milestone.

The anonymous enroll used to be the one account-creating path that stayed
silent: every other creation site calls ``_notify_user_registered`` (OTP
email/phone, password register, OAuth, ``auth.provision_user``), the
anonymous branch did not. Downstream that reads as "this user does not
exist yet" — ``stapel_workspaces``' ``consume_auth_events`` bootstraps the
personal workspace off ``user.registered`` and nothing else, so a guest
landed with no workspace at all and every workspace-scoped surface answered
403 to them. On a consuming fleet that closed a ten-minute anonymous
trial: the product ruling there is that a guest may record, upload and read
their transcript, and the missing milestone is half of why they could not.

The payload carries ``is_anonymous`` so a listener that must NOT fire for a
guest can skip by the flag instead of guessing from ``auth_type``. Guessing
is what it would be: ``auth_type`` is ``"anonymous"`` at enroll but the SAME
user row keeps its rows and its id through
``promote_anonymous_session``, which rewrites ``auth_type`` to the anchor the
guest just proved. A consumer that stored "auth_type == anonymous" would be
holding a fact with an expiry date on it.
"""
import json
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_core.django.outbox.models import OutboxEvent

User = get_user_model()

DEVICE_ID = "9f1e7a4c2b8d6053e4a1c7f90b2d8e36"


def _registered_payloads():
    return [
        json.loads(row.event_json)["payload"]
        for row in OutboxEvent.objects.filter(topic="user.registered")
    ]


@override_settings(URL_PREFIX="")
class AnonymousEnrollAnnouncesRegistrationTests(APITestCase):
    def setUp(self):
        cache.clear()

    def test_minting_a_guest_emits_user_registered(self):
        """The milestone the workspaces consumer listens for."""
        resp = self.client.post(reverse("anonymous"), {}, format="json")
        self.assertEqual(resp.status_code, 201, resp.content)
        user_id = resp.json()["user"]["id"]

        mine = [p for p in _registered_payloads() if p["user_id"] == str(user_id)]
        self.assertEqual(
            len(mine), 1, "anonymous enroll emitted no user.registered milestone"
        )
        self.assertEqual(mine[0]["auth_type"], "anonymous")
        self.assertIsNone(mine[0]["email"])

    def test_the_payload_flags_the_guest(self):
        """``is_anonymous`` is how a listener skips a guest deliberately."""
        resp = self.client.post(reverse("anonymous"), {}, format="json")
        user_id = resp.json()["user"]["id"]
        payload = [p for p in _registered_payloads() if p["user_id"] == str(user_id)][0]
        self.assertIs(payload["is_anonymous"], True)

    def test_the_payload_still_validates_against_the_published_schema(self):
        import jsonschema

        import stapel_auth

        resp = self.client.post(reverse("anonymous"), {}, format="json")
        user_id = resp.json()["user"]["id"]
        payload = [p for p in _registered_payloads() if p["user_id"] == str(user_id)][0]
        schema = json.loads(
            (
                Path(stapel_auth.__file__).parent
                / "schemas"
                / "emits"
                / "user.registered.json"
            ).read_text()
        )
        jsonschema.validate(payload, schema)

    def test_reusing_a_guest_session_does_not_re_announce(self):
        """The milestone fires once per ACCOUNT, not once per call.

        The view answers 201 for a reused session too (it is the same
        contract from the caller's side), so a milestone tied to the
        response rather than to the row would bootstrap a second personal
        workspace on every page load a guest makes.
        """
        first = self.client.post(
            reverse("anonymous"), {"device_id": DEVICE_ID}, format="json",
            REMOTE_ADDR="10.0.0.9",
        )
        user_id = first.json()["user"]["id"]
        # Same device id, same address, inside the 60s slot — the view
        # reuses the row rather than minting.
        again = self.client_class().post(
            reverse("anonymous"), {"device_id": DEVICE_ID}, format="json",
            REMOTE_ADDR="10.0.0.9",
        )
        self.assertEqual(again.json()["user"]["id"], user_id, "expected a reuse")

        mine = [p for p in _registered_payloads() if p["user_id"] == str(user_id)]
        self.assertEqual(
            len(mine), 1, "a reused guest session announced itself a second time"
        )

    def test_a_registered_signup_is_flagged_not_anonymous(self):
        """The flag is present on every path, so a consumer may rely on it.

        An optional key that only appears on the guest path forces every
        listener to spell ``payload.get("is_anonymous", False)`` and makes a
        typo read as "not a guest" — the unsafe direction for a flag whose
        whole job is suppressing mail to accounts that have no address.
        """
        from stapel_auth.otp.views import _notify_user_registered

        user = User.objects.create(email="erin@example.com", auth_type="email")
        _notify_user_registered(user)

        mine = [p for p in _registered_payloads() if p["user_id"] == str(user.id)]
        self.assertEqual(len(mine), 1)
        self.assertIs(mine[0]["is_anonymous"], False)
