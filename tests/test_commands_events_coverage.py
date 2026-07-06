"""Coverage tests for consume_gdpr command, events, errors, and gdpr branches.

Targets:
- stapel_auth.management.commands.consume_gdpr (whole module)
- stapel_auth.events (dataclass + registry)
- stapel_auth.errors (AuthErrorKeysView.get_service_errors)
- stapel_auth.gdpr (phone-only / no-email branches, missing REREGISTRATION_MODEL)
"""
import uuid

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings

User = get_user_model()


def _make_user(**kw):
    d = dict(
        email=f'{uuid.uuid4().hex[:8]}@example.com',
        username=uuid.uuid4().hex[:12],
        password='testpass123',
    )
    d.update(kw)
    return User.objects.create_user(**d)


def _make_phone_only_user():
    """User with a phone and no email — drives the phone branches in gdpr.py."""
    return User.objects.create_user(
        username=uuid.uuid4().hex[:12],
        email=None,
        phone='+14155552671',
        password='testpass123',
    )


# =============================================================================
# events.py
# =============================================================================

class EventsModuleTests(TestCase):
    def test_constants_and_backcompat_alias(self):
        from stapel_auth import events
        self.assertEqual(events.EVENT_USER_REGISTERED, 'user.registered')
        self.assertEqual(events.TOPIC_USER_REGISTERED, events.EVENT_USER_REGISTERED)

    def test_payload_dataclass_fields(self):
        from stapel_auth.events import UserRegisteredPayload
        p = UserRegisteredPayload(
            user_id='abc', auth_type='email', email='a@b.c',
            avatar_url='https://example.com/a.jpg',
        )
        self.assertEqual(p.user_id, 'abc')
        self.assertEqual(p.auth_type, 'email')
        self.assertEqual(p.email, 'a@b.c')
        self.assertEqual(p.avatar_url, 'https://example.com/a.jpg')

    def test_payload_email_defaults_none(self):
        from stapel_auth.events import UserRegisteredPayload
        p = UserRegisteredPayload(user_id='xyz', auth_type='anonymous')
        self.assertIsNone(p.email)

    def test_payload_avatar_url_defaults_none(self):
        from stapel_auth.events import UserRegisteredPayload
        p = UserRegisteredPayload(user_id='xyz', auth_type='email', email='a@b.c')
        self.assertIsNone(p.avatar_url)

    def test_registry_maps_event_to_payload(self):
        from stapel_auth.events import (
            EVENT_REGISTRY,
            EVENT_USER_REGISTERED,
            UserRegisteredPayload,
        )
        self.assertIs(EVENT_REGISTRY[EVENT_USER_REGISTERED], UserRegisteredPayload)


# =============================================================================
# errors.py — AuthErrorKeysView.get_service_errors
# =============================================================================

class AuthErrorKeysViewTests(TestCase):
    def test_get_service_errors_returns_auth_errors(self):
        from stapel_auth.errors import AUTH_ERRORS, AuthErrorKeysView
        view = AuthErrorKeysView()
        self.assertIs(view.get_service_errors(), AUTH_ERRORS)


# =============================================================================
# gdpr.py — phone-only / no-email branches + missing REREGISTRATION_MODEL
# =============================================================================

class GDPRProviderBranchTests(TestCase):
    def setUp(self):
        from stapel_auth.gdpr import AuthGDPRProvider
        self.provider = AuthGDPRProvider()

    def test_user_identifiers_phone_only(self):
        # Covers the no-email skip and the phone-append branch.
        user = _make_phone_only_user()
        ids = self.provider._user_identifiers(user.id)
        self.assertEqual(ids, [str(user.phone)])

    def test_delete_phone_only_user(self):
        # delete() on a user with phone and no email exercises the phone
        # PhoneVerification.delete branch and skips the email branch.
        user = _make_phone_only_user()
        # delete() clears auth-owned PII (sessions, tokens, verifications) but
        # not the User row itself; assert it completes without error.
        self.provider.delete(user.id)

    def test_store_reregistration_hashes_phone_only(self):
        from stapel_gdpr.models import ReRegistrationHash
        user = _make_phone_only_user()
        self.provider._store_reregistration_hashes(user.id)
        self.assertTrue(
            ReRegistrationHash.objects.filter(
                hash_type=ReRegistrationHash.TYPE_PHONE,
            ).exists()
        )
        # No email on this user — no email hash should be stored.
        self.assertFalse(
            ReRegistrationHash.objects.filter(
                hash_type=ReRegistrationHash.TYPE_EMAIL,
            ).exists()
        )

    @override_settings(STAPEL_AUTH={'REREGISTRATION_MODEL': ''})
    def test_store_reregistration_hashes_no_model_configured(self):
        from stapel_gdpr.models import ReRegistrationHash
        user = _make_user()
        # REREGISTRATION_MODEL is falsy -> early return, no hash written.
        self.provider._store_reregistration_hashes(user.id)
        self.assertFalse(ReRegistrationHash.objects.exists())


# =============================================================================
# management/commands/consume_gdpr.py
# =============================================================================

class ConsumeGdprCommandTests(TestCase):
    def _get_bus(self):
        from stapel_core.bus.router import get_bus
        return get_bus()

    def test_get_gdpr_provider_returns_auth_provider(self):
        from stapel_auth.gdpr import AuthGDPRProvider
        from stapel_auth.management.commands.consume_gdpr import Command
        self.assertIsInstance(Command().get_gdpr_provider(), AuthGDPRProvider)

    def test_command_dispatches_delete_event(self):
        from stapel_core.bus.event import Event
        from stapel_core.gdpr import GDPR_DELETE_COMPLETED, GDPR_DELETE_REQUESTED

        bus = self._get_bus()
        user = _make_user()
        correlation_id = str(uuid.uuid4())
        bus.publish(GDPR_DELETE_REQUESTED, Event(
            event_type=GDPR_DELETE_REQUESTED,
            service='gdpr',
            payload={'user_id': str(user.id), 'correlation_id': correlation_id},
        ))

        # MemoryBus.consume drains the queue then returns on timeout, so the
        # command completes without needing an explicit shutdown flag.
        call_command('consume_gdpr', poll_timeout=0.01)

        completed = [e for e in bus.events if e.event_type == GDPR_DELETE_COMPLETED]
        self.assertTrue(any(
            e.payload.get('correlation_id') == correlation_id for e in completed
        ))
