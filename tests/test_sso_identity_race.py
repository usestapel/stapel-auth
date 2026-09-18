"""First login through SSO: the identity is the (org, subject) pair.

``get_or_create_user`` keyed the whole flow on the IdP's email and resolved it
with ``User.objects.get_or_create(email=...)``. Email is deliberately NOT
unique on the user model — a fleet merges accounts, keeps guest rows and lets
two products share a mailbox — so that call has no unique key to collide on:

* two first logins racing (an IdP that opens two tabs, a browser that retries
  the ACS, two pods behind the same callback) both read "no such user" and both
  INSERT. Django's own IntegrityError retry inside ``get_or_create`` cannot
  save it, because nothing raises: the second INSERT succeeds and the person
  now has two accounts;
* and once two rows exist, every later ``get_or_create(email=...)`` raises
  ``MultipleObjectsReturned`` — the login stops working at all.

The identity an IdP actually asserts is its subject (``NameID``/``sub``) inside
one org, and that pair IS unique. Resolving on it makes the conflict point a
real database constraint: the loser gets an ``IntegrityError``, re-reads the
winner's identity, and returns the one user.

Three shapes, the same three as the core's first-contact race:

* the deterministic one — the identity INSERT is forced to lose, and the
  recovery must return the winner's user without creating a second;
* the ambiguous email — a mailbox that already maps to two accounts must be a
  named, logged refusal, never a silent pick of whichever row came first;
* the concurrent one — two threads, two connections, one identity. SQLite
  cannot hold two writers, so it runs against a real Postgres in CI
  (``STAPEL_TEST_DATABASE_URL``) and skips elsewhere.
"""
import os
import threading
import uuid

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, connection, connections
from django.test import TestCase, TransactionTestCase

from stapel_auth.models import Organization, OrgMembership
from stapel_auth.sso_service import AmbiguousSSOEmail, SSOUserService

User = get_user_model()


def _org(slug="acmecorp", domain="acmecorp.com"):
    return Organization.objects.create(
        name="Acme Corp", slug=slug, domain=domain, sso_enforced=False,
    )


def _attrs(email="racer@acmecorp.com", subject="sub-race", **extra):
    payload = {
        "email": email,
        "first_name": "",
        "last_name": "",
        "subject_id": subject,
    }
    payload.update(extra)
    return payload


class TheIdentityIsTheSubjectNotTheEmail(TestCase):
    def setUp(self):
        self.org = _org()

    def test_a_returning_subject_is_resolved_without_the_email(self):
        """The IdP changed the person's address; it is the same person."""
        user, created = SSOUserService.get_or_create_user(
            self.org, _attrs(email="before@acmecorp.com", subject="sub-42")
        )
        assert created is True

        again, created_again = SSOUserService.get_or_create_user(
            self.org, _attrs(email="after@acmecorp.com", subject="sub-42")
        )
        assert created_again is False
        assert again.pk == user.pk
        assert User.objects.count() == 1

    def test_the_same_subject_in_another_org_is_another_identity(self):
        other = _org(slug="beta", domain="beta.com")
        first, _ = SSOUserService.get_or_create_user(
            self.org, _attrs(email="a@acmecorp.com", subject="sub-1")
        )
        second, _ = SSOUserService.get_or_create_user(
            other, _attrs(email="b@beta.com", subject="sub-1")
        )
        assert first.pk != second.pk

    def test_the_identity_pair_is_unique_in_the_database(self):
        user = User.objects.create_user(
            email="a@acmecorp.com", username="a", password="x"
        )
        twin = User.objects.create_user(
            email="a@acmecorp.com", username="b", password="x"
        )
        OrgMembership.objects.create(user=user, org=self.org, sso_subject_id="sub-9")
        with pytest.raises(IntegrityError):
            OrgMembership.objects.create(
                user=twin, org=self.org, sso_subject_id="sub-9"
            )

    def test_blank_subjects_do_not_collide(self):
        """Memberships created outside SSO carry no subject; the constraint
        must not turn "no identity" into one shared identity."""
        a = User.objects.create_user(email="x@acmecorp.com", username="x", password="p")
        b = User.objects.create_user(email="y@acmecorp.com", username="y", password="p")
        OrgMembership.objects.create(user=a, org=self.org, sso_subject_id="")
        OrgMembership.objects.create(user=b, org=self.org, sso_subject_id="")
        assert OrgMembership.objects.filter(sso_subject_id="").count() == 2


class TheLoserOfTheRace(TestCase):
    """The identity INSERT is the conflict point, and losing it is survivable."""

    def setUp(self):
        self.org = _org()

    def test_the_loser_returns_the_winners_user_and_creates_nobody(self):
        winner = User.objects.create_user(
            email="racer@acmecorp.com", username="winner", password="x"
        )
        OrgMembership.objects.create(
            user=winner, org=self.org, sso_subject_id="sub-race"
        )

        real_create = OrgMembership.objects.create
        state = {"fired": False}

        def create_once_losing(**kwargs):
            """The interleaving of the loser: its own identity row is already
            there by the time it inserts."""
            if not state["fired"]:
                state["fired"] = True
                raise IntegrityError("duplicate key value violates unique constraint")
            return real_create(**kwargs)

        # The loser cannot see the winner's row when it looks (it read before
        # the winner committed), and collides when it writes.
        seen = {"looked": False}
        real_get = OrgMembership.objects.get

        def blind_get(*args, **kwargs):
            if not seen["looked"] and "sso_subject_id" in kwargs:
                seen["looked"] = True
                raise OrgMembership.DoesNotExist("raced")
            return real_get(*args, **kwargs)

        with patch_manager(OrgMembership, get=blind_get, create=create_once_losing):
            user, created = SSOUserService.get_or_create_user(self.org, _attrs())

        assert created is False
        assert user.pk == winner.pk
        assert User.objects.count() == 1
        assert OrgMembership.objects.filter(org=self.org).count() == 1

    def test_an_integrity_error_that_is_not_the_identity_is_not_swallowed(self):
        """Recovery re-reads the identity exactly once; if it is still not
        there, the failure was something else and must surface."""
        def always_failing_create(**kwargs):
            raise IntegrityError("some other constraint")

        with patch_manager(OrgMembership, create=always_failing_create):
            with pytest.raises(IntegrityError):
                SSOUserService.get_or_create_user(self.org, _attrs())

        assert User.objects.count() == 0


class AnAmbiguousEmail(TestCase):
    def setUp(self):
        self.org = _org()

    def test_two_accounts_on_one_address_are_a_named_refusal(self):
        for i in (1, 2):
            User.objects.create_user(
                email="twins@acmecorp.com", username=f"twin{i}", password="x"
            )
        with pytest.raises(AmbiguousSSOEmail):
            SSOUserService.get_or_create_user(
                self.org, _attrs(email="twins@acmecorp.com", subject="sub-new")
            )

    def test_the_refusal_is_logged_with_the_count(self, caplog=None):
        import logging

        for i in (1, 2, 3):
            User.objects.create_user(
                email="twins@acmecorp.com", username=f"twin{i}", password="x"
            )
        with self.assertLogs("stapel_auth.sso_service", level=logging.ERROR) as logs:
            with pytest.raises(AmbiguousSSOEmail):
                SSOUserService.get_or_create_user(
                    self.org, _attrs(email="twins@acmecorp.com", subject="sub-new")
                )
        assert any("3" in line for line in logs.output)

    def test_one_account_still_links(self):
        existing = User.objects.create_user(
            email="single@acmecorp.com", username="single", password="x"
        )
        user, created = SSOUserService.get_or_create_user(
            self.org, _attrs(email="single@acmecorp.com", subject="sub-single")
        )
        assert created is False
        assert user.pk == existing.pk


class patch_manager:
    """Swap named methods on a model's default manager for the block.

    A manager double rather than a mock of the service: the INSERT that fails
    has to be the real one everywhere else, or the test proves nothing about
    the recovery path.
    """

    def __init__(self, model, **methods):
        self.manager = model.objects
        self.methods = methods
        self.originals = {}

    def __enter__(self):
        for name, replacement in self.methods.items():
            self.originals[name] = getattr(self.manager, name)
            setattr(self.manager, name, replacement)
        return self

    def __exit__(self, *exc):
        for name, original in self.originals.items():
            setattr(self.manager, name, original)
        return False


requires_postgres = pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="needs a real Postgres: set STAPEL_TEST_DATABASE_URL",
)


@requires_postgres
class TwoFirstLoginsAtOnce(TransactionTestCase):
    """The real interleaving, on a server that can hold two writers."""

    def test_two_threads_one_user(self):
        org = _org(slug=f"race-{uuid.uuid4().hex[:8]}", domain="race.example")
        subject = f"sub-{uuid.uuid4().hex[:8]}"
        email = f"{subject}@race.example"
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def login():
            barrier.wait()
            try:
                user, created = SSOUserService.get_or_create_user(
                    org, _attrs(email=email, subject=subject)
                )
                results.append(user.pk)
            except Exception as exc:  # recorded, asserted on below
                errors.append(exc)
            finally:
                connections.close_all()

        threads = [threading.Thread(target=login) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors, errors
        assert len(set(results)) == 1, results
        assert User.objects.filter(email=email).count() == 1
        assert OrgMembership.objects.filter(
            org=org, sso_subject_id=subject
        ).count() == 1

    def test_the_suite_honoured_the_database_url(self):
        """This job cannot go green by quietly running on SQLite."""
        assert os.environ.get("STAPEL_TEST_DATABASE_URL")
        assert connection.vendor == "postgresql"
