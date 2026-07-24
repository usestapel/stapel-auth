"""user.mfa_enabled / user.mfa_disabled outbox events (org-program §C3).

Account-level transition semantics: the events track the "has a strong
second factor" predicate (totp/passkey/otp_phone strong, otp_email weak),
not per-factor ticks. Covered emission points: TOTP confirm, TOTP disable
(code path and force path), the delayed-change execute task, passkey
registration_complete (add-first) and passkey deactivation (remove-last).
Payloads are validated against the committed schemas/emits/*.json.
"""
import json
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jsonschema
import pyotp
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.events import (
    EVENT_USER_MFA_DISABLED,
    EVENT_USER_MFA_ENABLED,
)
from stapel_auth.mfa.services import PasskeyService, TOTPService
from stapel_auth.models import PasskeyCredential, TOTPDevice

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


def _enroll_totp(user):
    """Real enrollment: setup + confirm with a valid first code."""
    setup = TOTPService.setup(user)
    code = pyotp.TOTP(setup["secret"]).now()
    return TOTPService.confirm(user, code)


def _register_passkey(user, cred_id: bytes):
    """Drive PasskeyService.registration_complete with the webauthn ceremony
    stubbed out — the transition/emit wiring under test lives after it."""
    verification = SimpleNamespace(
        credential_id=cred_id,
        credential_public_key=b"pk",
        sign_count=0,
        aaguid=None,
    )
    credential = SimpleNamespace(response=SimpleNamespace(transports=[]))
    cache.set(f"passkey_reg:{user.id}", b"challenge", 300)
    with patch("webauthn.verify_registration_response", return_value=verification), \
         patch.object(PasskeyService, "_build_registration_credential",
                      return_value=credential):
        return PasskeyService.registration_complete(user, {"id": "x"})


class TotpEventTests(TestCase):
    def test_confirm_emits_enabled_and_validates_schema(self):
        user = _make_user()
        _enroll_totp(user)
        payloads = _payloads(EVENT_USER_MFA_ENABLED)
        self.assertEqual(
            payloads, [{"user_id": str(user.pk), "factor": "totp"}]
        )
        jsonschema.validate(payloads[0], _schema("user.mfa_enabled.json"))

    def test_confirm_with_verified_phone_emits_nothing(self):
        """Already strong via otp_phone — no account-level transition."""
        user = _make_user(phone="+79991230010", is_phone_verified=True)
        _enroll_totp(user)
        self.assertEqual(_payloads(EVENT_USER_MFA_ENABLED), [])

    def test_disable_last_strong_emits_disabled(self):
        user = _make_user()
        _enroll_totp(user)
        device = TOTPDevice.objects.get(user=user)
        code = pyotp.TOTP(device.secret).now()
        self.assertTrue(TOTPService.disable(user, code=code))

        payloads = _payloads(EVENT_USER_MFA_DISABLED)
        self.assertEqual(
            payloads, [{"user_id": str(user.pk), "factor": "totp"}]
        )
        jsonschema.validate(payloads[0], _schema("user.mfa_disabled.json"))

    def test_disable_with_other_strong_factor_emits_nothing(self):
        user = _make_user()
        _enroll_totp(user)
        PasskeyCredential.objects.create(
            user=user, credential_id=b"keep-1", public_key=b"pk", sign_count=0
        )
        device = TOTPDevice.objects.get(user=user)
        code = pyotp.TOTP(device.secret).now()
        self.assertTrue(TOTPService.disable(user, code=code))
        self.assertEqual(_payloads(EVENT_USER_MFA_DISABLED), [])

    def test_force_disable_emits_disabled(self):
        user = _make_user()
        _enroll_totp(user)
        self.assertTrue(TOTPService.force_disable(user))
        self.assertEqual(
            _payloads(EVENT_USER_MFA_DISABLED),
            [{"user_id": str(user.pk), "factor": "totp"}],
        )

    def test_force_disable_without_device_emits_nothing(self):
        user = _make_user()
        self.assertFalse(TOTPService.force_disable(user))
        self.assertEqual(_payloads(EVENT_USER_MFA_DISABLED), [])


class DelayedChangeExecuteEventTests(TestCase):
    def test_execute_pending_totp_change_emits_disabled(self):
        from stapel_auth.models import (
            AuthenticatorChangeRequest,
            AuthenticatorChangeStatus,
        )
        from stapel_auth.tasks import execute_pending_changes

        user = _make_user()
        _enroll_totp(user)
        OutboxEvent.objects.all().delete()  # isolate the task's emission

        AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type="totp",
            old_value="",
            new_value="",
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() - timedelta(minutes=1),
        )
        executed = execute_pending_changes()
        self.assertEqual(executed, 1)
        self.assertFalse(TOTPService.is_enabled(user))
        self.assertEqual(
            _payloads(EVENT_USER_MFA_DISABLED),
            [{"user_id": str(user.pk), "factor": "totp"}],
        )


class PasskeyEventTests(TestCase):
    def test_first_passkey_emits_enabled(self):
        user = _make_user()
        _register_passkey(user, b"cred-first")
        self.assertEqual(
            _payloads(EVENT_USER_MFA_ENABLED),
            [{"user_id": str(user.pk), "factor": "passkey"}],
        )

    def test_second_passkey_emits_nothing_more(self):
        user = _make_user()
        _register_passkey(user, b"cred-1")
        _register_passkey(user, b"cred-2")
        self.assertEqual(len(_payloads(EVENT_USER_MFA_ENABLED)), 1)

    def test_deactivate_last_passkey_emits_disabled(self):
        user = _make_user()
        _register_passkey(user, b"cred-only")
        pc = PasskeyCredential.objects.get(user=user)
        PasskeyService.deactivate(user, pc)
        self.assertEqual(
            _payloads(EVENT_USER_MFA_DISABLED),
            [{"user_id": str(user.pk), "factor": "passkey"}],
        )

    def test_deactivate_one_of_two_emits_nothing(self):
        user = _make_user()
        _register_passkey(user, b"cred-a")
        _register_passkey(user, b"cred-b")
        pc = PasskeyCredential.objects.filter(user=user).first()
        PasskeyService.deactivate(user, pc)
        self.assertEqual(_payloads(EVENT_USER_MFA_DISABLED), [])

    def test_registration_clears_enrollment_flag(self):
        user = _make_user(mfa_enrollment_required=True)
        _register_passkey(user, b"cred-flag")
        user.refresh_from_db()
        self.assertFalse(user.mfa_enrollment_required)

    def test_events_registered_in_registry(self):
        from stapel_auth.events import (
            EVENT_REGISTRY,
            UserMfaDisabledPayload,
            UserMfaEnabledPayload,
        )

        self.assertIs(EVENT_REGISTRY[EVENT_USER_MFA_ENABLED], UserMfaEnabledPayload)
        self.assertIs(EVENT_REGISTRY[EVENT_USER_MFA_DISABLED], UserMfaDisabledPayload)
