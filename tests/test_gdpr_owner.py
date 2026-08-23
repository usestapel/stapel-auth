"""stapel-auth answers the erasure protocol — probe, erase, receipt, once.

The finding this closes: auth was the ONE module in the fleet with no
``gdpr.owner.probe`` subscriber. It was a declared data owner, its
in-process provider really did erase, and the owners-health board still
reported ``auth: alive=false`` forever — because liveness is answered by
the subscriber that erases, and there was none to answer.

Auth is also the module that HOSTS stapel-gdpr, so the orchestrator's local
receipt and the comm receipt both run in one process for one account.
``test_hosting_gdpr_in_process_writes_exactly_one_receipt`` is the test that
had to exist before this could ship: two paths to one part must not produce
two receipts, and the honest receipt (with counts) must not be overwritten
by the second path's zeroes.
"""
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings

from stapel_core.comm import action_registry
from stapel_core.gdpr import register_gdpr_owner, registered_gdpr_owners

from stapel_auth.erasure import OWNER, SUBJECT_TYPES, erase_subject
from stapel_auth.models import (
    AuthAuditLog, AuthEventType, LinkedOAuthAccount, LoginAttempt,
    PasskeyCredential, RefreshTokenTracker, StaffRoleAssignment, TOTPDevice,
    UserSession, VerificationPreference,
)

#: The registration ``apps.ready()`` made. Same terms means the helper hands
#: back the existing registration rather than subscribing twice, so this is
#: both how the tests reach the handlers and an assertion that ready() ran.
AUTH_OWNER = register_gdpr_owner(OWNER, SUBJECT_TYPES, erase_subject)

#: Synchronous in-process comm: the receipt lands while execute_deletion is
#: still running, which is the tightest interleaving of the two receipt
#: paths a single process can produce.
inprocess = override_settings(
    STAPEL_COMM={"OUTBOX_ENABLED": False, "ACTION_TRANSPORT": "inprocess"},
)

#: One declared owner, kind inferred `local` because auth's GDPRProvider is
#: registered in this process — the fleet's own topology, where the module
#: that hosts the orchestrator is also one of its owners.
hosting_gdpr = override_settings(
    STAPEL_GDPR={
        "DATA_OWNERS": ["auth"],
        "DATA_OWNERS_VERSION": "test-auth-owner-1",
        "SUBJECT_TYPES": ["account"],
        "GRACE_PERIOD_DAYS": 0,
    },
)


def _event(**payload):
    return SimpleNamespace(payload=payload, event_id="evt-1", service="gdpr")


def _make_user(**kwargs):
    defaults = dict(
        email=f"{uuid.uuid4().hex[:10]}@example.com",
        username=f"u_{uuid.uuid4().hex[:10]}",
        password="testpass123!",
    )
    defaults.update(kwargs)
    return get_user_model().objects.create_user(**defaults)


def _trail(user):
    """One row in every table auth erases, so a count can be wrong out loud."""
    import datetime

    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    RefreshTokenTracker.objects.create(
        user=user, token=uuid.uuid4().hex, expires_at=expires,
    )
    UserSession.objects.create(user=user, jti=uuid.uuid4().hex, expires_at=expires)
    TOTPDevice.objects.create(user=user, secret="JBSWY3DPEHPK3PXP")
    PasskeyCredential.objects.create(
        user=user, credential_id=uuid.uuid4().hex.encode(), public_key=b"k", sign_count=0,
    )
    LoginAttempt.objects.create(
        identifier=user.email, attempt_type="failed", ip_address="203.0.113.7",
    )
    AuthAuditLog.objects.create(user=user, event_type=AuthEventType.LOGIN_SUCCESS)
    LinkedOAuthAccount.objects.create(
        user=user, provider="google", provider_user_id="g-1", email=user.email,
    )
    StaffRoleAssignment.objects.create(user=user, role_name="support")
    VerificationPreference.objects.create(user=user, scope="payments", enabled=True)


@pytest.mark.django_db
class TestRegistration:
    """What ``apps.ready()`` put on the bus."""

    def test_the_erasure_and_probe_handlers_are_subscribed(self):
        assert action_registry.handlers("gdpr.erasure.requested")
        assert action_registry.handlers("gdpr.owner.probe")
        # The deprecated account signal, until stapel-gdpr 0.6.0 drops it.
        assert action_registry.handlers("user.deleted")

    def test_the_owner_claims_the_account_and_nothing_else(self):
        assert registered_gdpr_owners()["auth"] == ("account",)
        assert OWNER == "auth" == __import__(
            "stapel_auth.gdpr", fromlist=["AuthGDPRProvider"]
        ).AuthGDPRProvider.section


@pytest.mark.django_db
class TestProbe:
    """`auth: alive=false` — the symptom this release exists to end."""

    def test_the_probe_is_answered_with_what_this_module_erases(self):
        correlation_id = str(uuid.uuid4())
        with patch("stapel_core.comm.emit") as m_emit:
            AUTH_OWNER.handle_owner_probe(_event(correlation_id=correlation_id))

        name, payload = m_emit.call_args.args
        assert name == "gdpr.owner.alive"
        assert payload == {
            "owner": "auth",
            "subject_types": ["account"],
            "correlation_id": correlation_id,
        }

    @inprocess
    @hosting_gdpr
    def test_the_answer_reaches_the_owners_health_row(self):
        """End to end in one process: probe out, alive back, board green.

        This is the prod symptom itself — the row that stayed
        ``last_alive_at=None`` while auth erased accounts perfectly well.
        """
        from stapel_gdpr.models import DataOwnerHealth
        from stapel_gdpr.orchestrator import gdpr_orchestrator

        gdpr_orchestrator.probe_data_owners()

        health = DataOwnerHealth.objects.get(owner="auth")
        assert health.last_probe_at is not None
        assert health.last_alive_at is not None
        assert health.answered_subject_types == ["account"]
        assert health.declared_subject_types == ["account"]


@pytest.mark.django_db
class TestErasure:
    """The receipt says what was erased, and only what was erased."""

    def test_the_trail_goes_and_the_receipt_counts_it(self):
        user = _make_user()
        _trail(user)
        correlation_id = str(uuid.uuid4())

        with patch("stapel_core.comm.emit") as m_emit:
            AUTH_OWNER.handle_erasure_requested(_event(
                request_id=1,
                correlation_id=correlation_id,
                subject_type="account",
                subject_key=str(user.pk),
            ))

        name, payload = m_emit.call_args.args
        assert name == "gdpr.section.erased"
        assert payload["owner"] == "auth"
        assert payload["subject_type"] == "account"
        assert payload["subject_key"] == str(user.pk)
        assert payload["correlation_id"] == correlation_id
        assert payload["receipt_id"] == f"auth:account:{user.pk}:{correlation_id}"
        assert payload["counts"] == {
            "refresh_tokens": 1,
            "sessions": 1,
            "totp_devices": 1,
            "passkeys": 1,
            "authenticator_changes": 0,
            "login_attempts": 1,
            "audit_log": 1,
            "sso_memberships": 0,
            "oauth_links": 1,
            "staff_roles": 1,
            "verification_preferences": 1,
        }
        assert not UserSession.objects.filter(user=user).exists()
        assert not LinkedOAuthAccount.objects.filter(user=user).exists()
        assert not StaffRoleAssignment.objects.filter(user=user).exists()
        assert not LoginAttempt.objects.filter(identifier=user.email).exists()

    def test_the_re_registration_hash_outlives_the_account(self):
        """The one thing an erasure leaves behind, and it names nobody."""
        import hashlib

        from stapel_gdpr.models import ReRegistrationHash

        user = _make_user()
        erase_subject("account", user.pk)

        digest = hashlib.sha256(user.email.lower().encode()).hexdigest()
        assert ReRegistrationHash.objects.filter(hash_value=digest).exists()

    def test_redelivery_erases_nothing_twice_and_mints_the_same_receipt(self):
        user = _make_user()
        _trail(user)
        event = _event(
            request_id=2,
            correlation_id="corr-redelivered",
            subject_type="account",
            subject_key=str(user.pk),
        )

        with patch("stapel_core.comm.emit") as m_emit:
            AUTH_OWNER.handle_erasure_requested(event)
            AUTH_OWNER.handle_erasure_requested(event)

        first, second = [call.args[1] for call in m_emit.call_args_list]
        assert first["counts"]["sessions"] == 1
        assert set(second["counts"].values()) == {0}
        assert first["receipt_id"] == second["receipt_id"]

    def test_an_unclaimed_subject_is_ignored_without_a_receipt(self):
        """gdpr creates a part only for owners that claim the type, so a
        receipt here would be answering for somebody else."""
        user = _make_user()
        _trail(user)

        with patch("stapel_core.comm.emit") as m_emit:
            AUTH_OWNER.handle_erasure_requested(_event(
                request_id=3,
                correlation_id="corr-workspace",
                subject_type="workspace",
                subject_key="ws-1",
            ))

        m_emit.assert_not_called()
        assert UserSession.objects.filter(user=user).exists()
        assert erase_subject("workspace", "ws-1") is None

    def test_the_deprecated_signal_runs_the_same_erasure(self):
        """user.deleted and gdpr.erasure.requested reach one implementation,
        so deleting the legacy handler deletes no erasure logic."""
        user = _make_user()
        _trail(user)

        with patch("stapel_core.comm.emit") as m_emit:
            AUTH_OWNER.handle_user_deleted(_event(
                user_id=str(user.pk), correlation_id="corr-legacy",
            ))

        name, payload = m_emit.call_args.args
        assert name == "gdpr.section.erased"
        assert payload["counts"]["sessions"] == 1
        assert payload["user_id"] == str(user.pk)
        assert not UserSession.objects.filter(user=user).exists()


@pytest.mark.django_db
class TestHostingTheOrchestrator:
    """Auth hosts stapel-gdpr: both receipt paths run here, in one process."""

    @inprocess
    @hosting_gdpr
    def test_hosting_gdpr_in_process_writes_exactly_one_receipt(self):
        """Three deliveries, one part, one receipt — and the true one.

        For a single account erasure this process runs, in order: the
        ``gdpr.erasure.requested`` subscriber (comm receipt), the in-process
        provider the orchestrator walks, its ``_record_local_receipts``, and
        the deprecated ``user.deleted`` subscriber. Only the first has
        anything left to erase; every later path must find the part already
        receipted and leave the honest counts alone.
        """
        from stapel_gdpr.models import AccountClosureRequest, ErasurePart
        from stapel_gdpr.orchestrator import GDPROrchestrator, gdpr_orchestrator
        from stapel_gdpr.owners import data_owner_report

        # Without this the test is vacuous: the local receipt path applies to
        # LOCAL owners only, and auth is one exactly because it hosts the
        # orchestrator that walks its provider.
        assert data_owner_report().owner("auth").is_local

        user = _make_user()
        _trail(user)

        receipts = []
        original_record = ErasurePart.record_receipt
        original_mark = GDPROrchestrator.mark_section_erased

        def spy_record(self, *args, **kwargs):
            receipts.append(("local", self.owner))
            return original_record(self, *args, **kwargs)

        def spy_mark(self, correlation_id, service, *args, **kwargs):
            done = ErasurePart.objects.filter(
                request__correlation_id=correlation_id,
                owner=service,
                state=ErasurePart.STATE_DONE,
            )
            was_done = done.exists()
            result = original_mark(self, correlation_id, service, *args, **kwargs)
            if not was_done and done.exists():
                receipts.append(("comm", service))
            return result

        with patch.object(ErasurePart, "record_receipt", spy_record), \
                patch.object(GDPROrchestrator, "mark_section_erased", spy_mark):
            closure = gdpr_orchestrator.initiate_closure(user.pk)
            gdpr_orchestrator.execute_deletion(closure)

        closure.refresh_from_db()
        parts = list(closure.erasure.parts.all())
        assert [p.owner for p in parts] == ["auth"]
        part = parts[0]

        # One receipt, from the subscriber — not two, and not the local
        # path's empty one overwriting the counts the subscriber measured.
        assert receipts == [("comm", "auth")]
        assert part.state == ErasurePart.STATE_DONE
        assert part.receipt_id == f"auth:account:{user.pk}:{closure.correlation_id}"
        assert part.counts["sessions"] == 1
        assert part.counts["oauth_links"] == 1

        # And the erasure really closed — the receipt is what the DELETED
        # flip is checked against.
        assert closure.status == AccountClosureRequest.STATUS_DELETED
        assert not UserSession.objects.filter(user=user).exists()
        assert not RefreshTokenTracker.objects.filter(user=user).exists()

    @inprocess
    @hosting_gdpr
    def test_a_redelivered_request_does_not_re_receipt_the_part(self):
        """At-least-once delivery reaches a part that is already done."""
        from stapel_gdpr.models import ErasurePart
        from stapel_gdpr.orchestrator import gdpr_orchestrator

        user = _make_user()
        _trail(user)
        closure = gdpr_orchestrator.initiate_closure(user.pk)
        gdpr_orchestrator.execute_deletion(closure)
        closure.refresh_from_db()

        part = closure.erasure.parts.get(owner="auth")
        before = (part.receipt_id, part.receipt_at, dict(part.counts))

        AUTH_OWNER.handle_erasure_requested(_event(
            request_id=closure.erasure.pk,
            correlation_id=closure.correlation_id,
            subject_type="account",
            subject_key=str(user.pk),
        ))

        part = ErasurePart.objects.get(pk=part.pk)
        assert (part.receipt_id, part.receipt_at, dict(part.counts)) == before
