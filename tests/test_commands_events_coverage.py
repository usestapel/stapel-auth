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
    def test_constants(self):
        from stapel_auth import events
        self.assertEqual(events.EVENT_USER_REGISTERED, 'user.registered')

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

    def test_reregistration_hashes_carry_the_owning_library_scheme(self):
        """The erasure path must not write a row the owning library distrusts.

        This module used to compute its own digest — a bare unsalted
        sha256(email), recoverable from a wordlist — and named no scheme, so
        ReRegistrationHash's `unverified` default spoke for it. Such a row is
        ignored by lookups and reported by gdpr.E004, which is an ERROR: the
        identity service refuses to boot once one exists.

        Found on 2026-09-16 by a deliberate erasure drill on a live fleet. One
        erasure wrote three rows in the same second — one correct
        hmac-sha256-v1 and two unverified from here — and auth crash-looped on
        its next restart, hours later.
        """
        from stapel_gdpr.models import ReRegistrationHash
        from stapel_gdpr.reregistration import compute_hash

        user = _make_phone_only_user()
        self.provider._store_reregistration_hashes(user.id)

        rows = list(ReRegistrationHash.objects.all())
        self.assertTrue(rows)
        # Not one unverified row, from any path.
        self.assertEqual(
            [r for r in rows if r.scheme == ReRegistrationHash.SCHEME_UNVERIFIED],
            [],
            "the erasure path wrote a row with no recorded hash scheme",
        )
        for row in rows:
            self.assertEqual(row.scheme, ReRegistrationHash.SCHEME_HMAC_V1)

        # And the VALUE is the owning library's purpose-bound keyed HMAC,
        # not a digest this module invented.
        phone_row = ReRegistrationHash.objects.get(
            hash_type=ReRegistrationHash.TYPE_PHONE
        )
        self.assertEqual(
            phone_row.hash_value, compute_hash("phone", str(user.phone))
        )

    def test_the_bare_unsalted_digest_is_never_written(self):
        """The exact value the old implementation stored."""
        import hashlib

        from stapel_gdpr.models import ReRegistrationHash

        user = _make_phone_only_user()
        self.provider._store_reregistration_hashes(user.id)

        unsalted = hashlib.sha256(str(user.phone).lower().strip().encode()).hexdigest()
        self.assertFalse(
            ReRegistrationHash.objects.filter(hash_value=unsalted).exists(),
            "an unsalted digest of the identifier reached the database",
        )

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
