"""Every flow that establishes a deliverable address announces it.

**The defect.** ``user.contact.changed`` is the only thing a notification
service's contact mirror is made of, and for most of this library's life the
only producer of it was ``AuthenticatorChangeService._apply_change`` — the
*change my e-mail* flow. Registration emitted nothing. On a live fleet that
meant a mirror holding 41 relic rows next to an auth database holding 192
verified addresses, and payment receipts and "your summary is ready" letters
journalled as ``skipped — no email address for this recipient`` for months,
for accounts whose e-mail auth had the whole time.

**What this file is.** The enumeration, as a parametrised list: every way an
account can come to have an address, driven through the library's own entry
point, each asserting the same thing — an outbox row for
``user.contact.changed`` carrying that address. Run against the code as it
was before :mod:`stapel_auth.contact_projection`, every case but the two
``authenticator_change_*`` ones fails. That is the point of writing it as a
list rather than as ten separate tests: the twelfth login method is added by
someone who has never heard of the contact mirror, and a flow missing from
FLOWS is missing visibly, in one place, next to its ten siblings.

The second half is the architecture assertion proper: the observer is the
**only** producer. A future emit hand-rolled next to a new view would pass
its own flow's case here and still be the bug — a second writer of the same
fact, free to disagree with the first — so the choke point is pinned by
grep over the package, not by trust.
"""
import json
import pathlib
import uuid
from unittest.mock import patch

import jsonschema
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient, APITestCase

from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.contact_projection import (
    CONTACT_FIELDS,
    announce_contact,
    contact_payload,
)
from stapel_auth.events import (
    EVENT_REGISTRY,
    EVENT_USER_CONTACT_CHANGED,
    UserContactChangedPayload,
)

User = get_user_model()


def _contact_payloads(user_id=None):
    """Every ``user.contact.changed`` payload in the outbox, oldest first."""
    rows = OutboxEvent.objects.filter(
        topic=EVENT_USER_CONTACT_CHANGED
    ).order_by("created_at", "id")
    out = [json.loads(row.event_json)["payload"] for row in rows]
    if user_id is not None:
        out = [p for p in out if str(p.get("user_id")) == str(user_id)]
    return out


def _emit_schema():
    import stapel_auth

    path = (
        pathlib.Path(stapel_auth.__file__).parent
        / "schemas" / "emits" / "user.contact.changed.json"
    )
    return json.loads(path.read_text())


def _bearer_client_for(user) -> APIClient:
    from stapel_core.django.jwt.provider import jwt_provider

    access, _ = jwt_provider.create_tokens(user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client


def _uniq(prefix="u"):
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# ── the flows ────────────────────────────────────────────────────────────────
#
# Each entry returns the user whose address was just established. The name is
# the flow as an operator would name it in an incident; the callable is the
# library's own entry point for it, never a bare ``User.objects.create`` —
# a test that creates the row itself proves the observer and nothing about
# whether the flow reaches it.


def _flow_email_otp_registration(case):
    with patch(
        "stapel_auth.otp.services.EmailVerificationService.verify_code",
        return_value={"success": True},
    ):
        email = f"{_uniq()}@example.com"
        response = APIClient().post(
            reverse("email_verify"), {"email": email, "code": "1234"}
        )
        case.assertIn(response.status_code, (200, 201), response.data)
    return User.objects.get(email=email)


def _flow_phone_otp_registration(case):
    with patch(
        "stapel_auth.otp.services.PhoneVerificationService.verify_code",
        return_value={"success": True},
    ):
        phone = f"+7999{uuid.uuid4().int % 10_000_000:07d}"
        response = APIClient().post(
            reverse("phone_verify"), {"phone": phone, "code": "1234"}
        )
        case.assertIn(response.status_code, (200, 201), response.data)
    return User.objects.get(phone=phone)


def _flow_email_otp_guest_upgrade(case):
    guest = User.create_anonymous_user()
    client = _bearer_client_for(guest)
    with patch(
        "stapel_auth.otp.services.EmailVerificationService.verify_code",
        return_value={"success": True},
    ):
        email = f"{_uniq()}@example.com"
        response = client.post(
            reverse("email_verify"), {"email": email, "code": "1234"}
        )
        case.assertIn(response.status_code, (200, 201), response.data)
    guest.refresh_from_db()
    return guest


def _oauth_user_data(email, *, verified=True):
    from stapel_auth.oauth_providers import OAuthUserData

    return OAuthUserData(
        id=uuid.uuid4().hex,
        email=email,
        username=email.split("@")[0],
        avatar=None,
        email_verified=verified,
    )


def _resolve_oauth(user_data, request_user=None):
    from stapel_auth.otp.views import AuthViewSet

    return AuthViewSet()._resolve_oauth_user(
        "google", user_data, request_user=request_user
    )


def _flow_oauth_first_login(case):
    """The Google case. On a Google-first deployment this IS registration."""
    email = f"{_uniq()}@example.com"
    user, _status = _resolve_oauth(_oauth_user_data(email))
    return user


def _flow_oauth_guest_upgrade(case):
    guest = User.create_anonymous_user()
    email = f"{_uniq()}@example.com"
    user, _status = _resolve_oauth(_oauth_user_data(email), request_user=guest)
    return user


def _sso_org():
    from stapel_auth.models import Organization

    return Organization.objects.create(
        name="Acme", slug=_uniq("acme"), domain=f"{_uniq('d')}.example",
    )


def _flow_sso_first_login(case):
    from stapel_auth.sso_service import SSOUserService

    attrs = {"email": f"{_uniq()}@example.com", "first_name": "", "last_name": ""}
    user, _created = SSOUserService._provision(
        _sso_org(), attrs, None, None,
        promote_anonymous_session=lambda u, auth_type: None,
    )
    return user


def _flow_sso_guest_upgrade(case):
    from stapel_auth.otp.services import promote_anonymous_session
    from stapel_auth.sso_service import SSOUserService

    guest = User.create_anonymous_user()
    attrs = {"email": f"{_uniq()}@example.com", "first_name": "", "last_name": ""}
    user, _created = SSOUserService._provision(
        _sso_org(), attrs, None, guest,
        promote_anonymous_session=promote_anonymous_session,
    )
    return user


def _flow_password_registration(case):
    email = f"{_uniq()}@example.com"
    with override_settings(STAPEL_AUTH={"AUTH_PASSWORD_REGISTRATION": True}):
        response = APIClient().post(
            reverse("password_register"),
            {"email": email, "password": "brandnew456!"},
        )
        case.assertIn(response.status_code, (200, 201), response.data)
    return User.objects.get(email=email)


def _flow_admin_created_user(case):
    staff = User.objects.create_user(
        username=_uniq("staff"), email=f"{_uniq()}@example.com",
        password="staffpass123!", is_staff=True,
    )
    email = f"{_uniq()}@example.com"
    response = _bearer_client_for(staff).post(
        reverse("admin-users"), {"email": email, "mark_verified": True}
    )
    case.assertIn(response.status_code, (200, 201), getattr(response, "data", None))
    return User.objects.get(email=email)


def _flow_provision_user(case):
    from stapel_core.comm import call

    org = _uniq("org")
    result = call(
        "auth.provision_user",
        {
            "username": f"{org}/{_uniq('member')}",
            "email": f"{_uniq()}@example.com",
            "first_login_policies": [],
        },
    )
    case.assertNotIn("error", result, result)
    return User.objects.get(pk=result["user_id"])


def _flow_login_grant_provisioning(case):
    from stapel_auth.login_grant.services import LoginGrantService

    email = f"{_uniq()}@example.com"
    token = LoginGrantService.issue(
        email=email, verified_email=True, create_if_missing=True
    )
    user, _created = LoginGrantService.exchange(token)
    return user


def _flow_authenticator_change_email(case):
    from stapel_auth.otp.services import AuthenticatorChangeService

    user = User.objects.create_user(
        username=_uniq(), email=f"{_uniq()}@example.com", password="pw123456!",
        is_email_verified=True,
    )
    AuthenticatorChangeService._apply_change(
        user, "email", f"{_uniq()}@example.com"
    )
    return user


def _flow_authenticator_change_phone(case):
    from stapel_auth.otp.services import AuthenticatorChangeService

    user = User.objects.create_user(
        username=_uniq(), email=f"{_uniq()}@example.com", password="pw123456!",
    )
    AuthenticatorChangeService._apply_change(
        user, "phone", f"+7999{uuid.uuid4().int % 10_000_000:07d}"
    )
    return user


#: The enumeration. A new way to sign in belongs here the day it is written.
FLOWS = [
    ("email_otp_registration", _flow_email_otp_registration),
    ("phone_otp_registration", _flow_phone_otp_registration),
    ("email_otp_guest_upgrade", _flow_email_otp_guest_upgrade),
    ("oauth_first_login", _flow_oauth_first_login),
    ("oauth_guest_upgrade", _flow_oauth_guest_upgrade),
    ("sso_first_login", _flow_sso_first_login),
    ("sso_guest_upgrade", _flow_sso_guest_upgrade),
    ("password_registration", _flow_password_registration),
    ("admin_created_user", _flow_admin_created_user),
    ("provision_user", _flow_provision_user),
    ("login_grant_provisioning", _flow_login_grant_provisioning),
    ("authenticator_change_email", _flow_authenticator_change_email),
    ("authenticator_change_phone", _flow_authenticator_change_phone),
]


class EveryAddressEstablishingFlowAnnouncesItTests(APITestCase):
    """The parametrised architecture test."""

    def test_every_flow_emits_a_contact_event(self):
        schema = _emit_schema()
        missing = []
        for name, flow in FLOWS:
            with self.subTest(flow=name):
                OutboxEvent.objects.all().delete()
                try:
                    user = flow(self)
                except Exception as exc:  # pragma: no cover - diagnostic
                    self.fail(f"flow {name!r} did not run: {exc!r}")
                user.refresh_from_db()
                payloads = _contact_payloads(user.pk)
                if not payloads:
                    missing.append(name)
                    continue
                last = payloads[-1]
                jsonschema.validate(last, schema)
                self.assertEqual(str(last["user_id"]), str(user.pk))
                # The address on the wire is the address on the row — a
                # mirror fed a stale value writes to the wrong person.
                self.assertEqual(last["email"], user.email or "")
                self.assertEqual(
                    last["phone"], getattr(user, "phone", "") or ""
                )
                self.assertTrue(
                    last["email"] or last["phone"],
                    f"flow {name!r} announced an empty contact",
                )
        self.assertEqual(
            missing, [],
            "these account flows establish a deliverable address and "
            "announce nothing — a notification service will journal their "
            "users' transactional mail as 'skipped: no email address': "
            f"{missing}",
        )


class ChokePointTests(TestCase):
    """One producer of the fact, not one per flow."""

    def test_contact_projection_is_the_only_emitter_in_the_package(self):
        import stapel_auth

        root = pathlib.Path(stapel_auth.__file__).parent
        offenders = []
        for path in root.rglob("*.py"):
            rel = path.relative_to(root)
            # The package is laid out flat at the repo root
            # (package-dir={"stapel_auth": "."}), so rglob also walks the
            # workspace venv and the build tree. Neither is this module.
            if rel.parts[0].startswith(".") or rel.parts[0] in {
                "tests", "build", "dist", "migrations", "__pycache__", "docs",
            }:
                continue
            if rel.name in {"contact_projection.py", "events.py"}:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "TOPIC_USER_CONTACT_CHANGED" in text or \
                    "EVENT_USER_CONTACT_CHANGED" in text:
                offenders.append(str(rel))
        self.assertEqual(
            offenders, [],
            "the contact fact has exactly one producer — the observer in "
            "contact_projection.py. A second emit next to a view is free to "
            "disagree with it and is how the mirror drifted in the first "
            f"place: {offenders}",
        )

    def test_observer_is_registered_for_the_project_user_model(self):
        """Asserted behaviourally, not by reading Django's receiver table:
        the wiring that matters is "a save that establishes an address
        produces an event", and that is what a host loses if ``ready()``
        ever stops calling ``register_contact_projection_observer``."""
        OutboxEvent.objects.all().delete()
        user = User.objects.create_user(
            username=_uniq(), email=f"{_uniq()}@example.com", password="pw123456!",
        )
        self.assertEqual(len(_contact_payloads(user.pk)), 1)

    def test_registry_and_dataclass_agree_with_the_schema(self):
        self.assertIs(
            EVENT_REGISTRY[EVENT_USER_CONTACT_CHANGED],
            UserContactChangedPayload,
        )
        schema = _emit_schema()
        fields = set(UserContactChangedPayload.__dataclass_fields__)
        self.assertEqual(fields, set(schema["properties"]))


class ObserverBehaviourTests(TestCase):
    """The rules the observer is allowed to be quiet about."""

    def setUp(self):
        OutboxEvent.objects.all().delete()

    def test_guest_with_no_address_announces_nothing(self):
        guest = User.create_anonymous_user()
        self.assertEqual(_contact_payloads(guest.pk), [])

    def test_unrelated_save_announces_nothing(self):
        user = User.objects.create_user(
            username=_uniq(), email=f"{_uniq()}@example.com", password="pw123456!",
        )
        OutboxEvent.objects.all().delete()
        user.first_name = "Changed"
        user.save()
        self.assertEqual(_contact_payloads(user.pk), [])

    def test_update_last_login_fast_path_announces_nothing(self):
        user = User.objects.create_user(
            username=_uniq(), email=f"{_uniq()}@example.com", password="pw123456!",
        )
        OutboxEvent.objects.all().delete()
        from django.utils import timezone

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])
        self.assertEqual(_contact_payloads(user.pk), [])

    def test_verification_flag_alone_is_announced(self):
        """A mirror that stores the flags must hear the flip: an address
        going from unverified to proven is the moment a receipt may be sent
        to it."""
        user = User.objects.create_user(
            username=_uniq(), email=f"{_uniq()}@example.com", password="pw123456!",
        )
        OutboxEvent.objects.all().delete()
        user.is_email_verified = True
        user.save()
        payloads = _contact_payloads(user.pk)
        self.assertEqual(len(payloads), 1)
        self.assertTrue(payloads[0]["email_verified"])

    def test_losing_the_last_address_is_announced_as_empty(self):
        """The mirror must be told to stop writing — silence would leave it
        holding an address the account gave up."""
        user = User.objects.create_user(
            username=_uniq(), email=f"{_uniq()}@example.com", password="pw123456!",
        )
        OutboxEvent.objects.all().delete()
        user.email = ""
        user.save()
        payloads = _contact_payloads(user.pk)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["email"], "")

    def test_announce_contact_is_callable_and_idempotent_in_shape(self):
        user = User.objects.create_user(
            username=_uniq(), email=f"{_uniq()}@example.com", password="pw123456!",
        )
        OutboxEvent.objects.all().delete()
        self.assertTrue(announce_contact(user))
        self.assertTrue(announce_contact(user))
        payloads = _contact_payloads(user.pk)
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0], payloads[1])

    def test_contact_payload_never_carries_a_name(self):
        """Privacy surface: this event is addresses, not a profile."""
        user = User.objects.create_user(
            username=_uniq(), email=f"{_uniq()}@example.com", password="pw123456!",
            first_name="Ada", last_name="Lovelace",
        )
        payload = contact_payload(user)
        self.assertEqual(
            set(payload),
            {"user_id", "email", "phone", "email_verified", "phone_verified"},
        )

    def test_contact_fields_are_real_columns(self):
        concrete = {f.attname for f in User._meta.concrete_fields}
        self.assertTrue(set(CONTACT_FIELDS) & concrete)
