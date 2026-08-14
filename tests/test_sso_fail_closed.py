"""SSO: what the assertion does NOT say must not be read as consent.

Four accept-by-default branches (audit 2026-08-11), all of the same shape —
a field is absent, so the check that would have used it is skipped:

* ``Conditions`` absent — the assertion has no validity window and never
  expires, so one captured assertion stays a working credential;
* ``AudienceRestriction`` absent — the assertion is addressed to nobody in
  particular, so an assertion the IdP minted for a DIFFERENT SP is accepted
  here;
* ``InResponseTo`` absent — the response answers no request of ours, so the
  single-use correlation has nothing to bite on (IdP-initiated login CSRF);
* an existing local account with the same email — handed to the IdP on the
  strength of a string, with no ``email_verified`` anywhere in the picture.

Each one is now a refusal with its own named opt-out, and each opt-out is
exercised here too: a switch nobody proves still works is not an opt-out.
"""
import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from lxml import etree

from stapel_auth.models import Organization, OrgMembership
from stapel_auth.sso_service import SAMLService, SSOUserService

User = get_user_model()

_SP = "https://app.example.com"
_URLS = {"FRONTEND_URL": _SP, "BACKEND_URL": _SP}

_NS = 'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'


def _assertion(conditions: str = "", subject: str = "") -> etree._Element:
    return etree.fromstring(
        f'<saml:Assertion {_NS} ID="_a1">'
        f"{subject}{conditions}"
        f"<saml:Subject><saml:NameID>bob@acmecorp.com</saml:NameID></saml:Subject>"
        f"</saml:Assertion>".encode()
    )


def _window(not_after: str = "2999-01-01T00:00:00Z", audience: str | None = None) -> str:
    aud = (
        f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>"
        f"</saml:AudienceRestriction>"
        if audience
        else ""
    )
    return f'<saml:Conditions NotOnOrAfter="{not_after}">{aud}</saml:Conditions>'


def _org(slug="acmecorp", domain="acmecorp.com"):
    return Organization.objects.create(
        name="Acme Corp", slug=slug, domain=domain, sso_enforced=False
    )


def _user(email):
    return User.objects.create_user(
        email=email, username=f"u_{uuid.uuid4().hex[:10]}", password="x"
    )


@override_settings(**_URLS)
class ConditionsAreMandatoryTests(TestCase):
    def test_an_assertion_without_conditions_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            SAMLService._validate_conditions(_assertion())
        self.assertIn("Conditions", str(ctx.exception))

    def test_conditions_without_an_expiry_are_refused(self):
        assertion = _assertion(conditions=f"<saml:Conditions {_NS}/>")
        with self.assertRaises(ValueError) as ctx:
            SAMLService._validate_conditions(assertion)
        self.assertIn("NotOnOrAfter", str(ctx.exception))

    def test_a_windowed_assertion_still_passes(self):
        SAMLService._validate_conditions(_assertion(conditions=_window()))

    def test_an_expired_window_is_still_refused(self):
        with self.assertRaises(ValueError):
            SAMLService._validate_conditions(
                _assertion(conditions=_window(not_after="2000-01-01T00:00:00Z"))
            )

    @override_settings(STAPEL_AUTH={**_URLS, "SAML_REQUIRE_CONDITIONS": False})
    def test_the_requirement_can_be_switched_off_explicitly(self):
        SAMLService._validate_conditions(_assertion())


@override_settings(**_URLS)
class AudienceIsMandatoryTests(TestCase):
    def test_an_assertion_addressed_to_nobody_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            SAMLService._validate_audience(_assertion(conditions=_window()), "acmecorp")
        self.assertIn("AudienceRestriction", str(ctx.exception))

    def test_an_assertion_for_another_sp_is_refused(self):
        assertion = _assertion(
            conditions=_window(audience="https://other-sp.example.com/saml/metadata/")
        )
        with self.assertRaises(ValueError):
            SAMLService._validate_audience(assertion, "acmecorp")

    def test_our_own_entity_id_passes(self):
        assertion = _assertion(
            conditions=_window(audience=SAMLService.sp_entity_id("acmecorp"))
        )
        SAMLService._validate_audience(assertion, "acmecorp")

    @override_settings(STAPEL_AUTH={**_URLS, "SAML_REQUIRE_AUDIENCE": False})
    def test_the_requirement_can_be_switched_off_explicitly(self):
        SAMLService._validate_audience(_assertion(conditions=_window()), "acmecorp")


@override_settings(**_URLS)
class UnsolicitedResponsesAreRefusedTests(TestCase):
    def test_a_response_with_no_in_response_to_is_refused(self):
        response_root = etree.fromstring(
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'
        )
        with self.assertRaises(ValueError) as ctx:
            SAMLService._validate_in_response_to(
                _assertion(conditions=_window()), response_root, "acmecorp"
            )
        self.assertIn("InResponseTo", str(ctx.exception))

    @override_settings(STAPEL_AUTH={**_URLS, "SAML_ALLOW_IDP_INITIATED": True})
    def test_idp_initiated_can_be_switched_on_explicitly(self):
        response_root = etree.fromstring(
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'
        )
        SAMLService._validate_in_response_to(
            _assertion(conditions=_window()), response_root, "acmecorp"
        )

    def test_an_in_response_to_that_matches_no_request_is_still_refused(self):
        response_root = etree.fromstring(
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            b' InResponseTo="_never-issued"/>'
        )
        with self.assertRaises(ValueError):
            SAMLService._validate_in_response_to(
                _assertion(conditions=_window()), response_root, "acmecorp"
            )


class ExistingAccountIsNotClaimedByEmailAloneTests(TestCase):
    """An IdP may not be handed an account it never proved it owns."""

    def setUp(self):
        self.org = _org()
        self.attrs = {"first_name": "", "last_name": "", "subject_id": "sub-1"}

    def _login(self, email):
        return SSOUserService.get_or_create_user(self.org, {**self.attrs, "email": email})

    def test_an_outside_address_cannot_take_over_a_local_account(self):
        victim = _user("victim@gmail.com")
        with self.assertRaises(ValueError):
            self._login("victim@gmail.com")
        victim.refresh_from_db()
        self.assertFalse(OrgMembership.objects.filter(user=victim).exists())

    def test_the_org_domain_is_still_authoritative_for_its_own_addresses(self):
        existing = _user("bob@acmecorp.com")
        user, created = self._login("bob@acmecorp.com")
        self.assertFalse(created)
        self.assertEqual(user.pk, existing.pk)

    def test_a_lookalike_domain_does_not_pass_for_the_org_domain(self):
        _user("bob@evil-acmecorp.com")
        with self.assertRaises(ValueError):
            self._login("bob@evil-acmecorp.com")

    def test_an_org_with_no_domain_claims_nothing_by_email(self):
        self.org = _org(slug="nodomain", domain="")
        _user("someone@anywhere.com")
        with self.assertRaises(ValueError):
            self._login("someone@anywhere.com")

    def test_an_existing_membership_is_the_link_and_keeps_working(self):
        """A member with an off-domain address (contractor, personal alias)
        still logs in — the membership is the deliberate act."""
        member = _user("contractor@gmail.com")
        OrgMembership.objects.create(user=member, org=self.org, sso_subject_id="sub-1")
        user, created = self._login("contractor@gmail.com")
        self.assertFalse(created)
        self.assertEqual(user.pk, member.pk)

    def test_a_fresh_address_is_still_provisioned_just_in_time(self):
        """The refusal is about CLAIMING an account, not about creating one."""
        user, created = self._login("newbie@anywhere.com")
        self.assertTrue(created)
        self.assertTrue(OrgMembership.objects.filter(user=user, org=self.org).exists())

    @override_settings(STAPEL_AUTH={"SSO_LINK_EXISTING_BY_EMAIL": True})
    def test_email_linking_can_be_switched_back_on_explicitly(self):
        existing = _user("victim@gmail.com")
        user, created = self._login("victim@gmail.com")
        self.assertFalse(created)
        self.assertEqual(user.pk, existing.pk)
