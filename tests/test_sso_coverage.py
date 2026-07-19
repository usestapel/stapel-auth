"""Coverage-focused tests for SSO service/views and step-up verification factors.

Targets the branch/error paths in ``sso_service``, ``sso_views`` and
``verification_factors`` that the primary suites (``test_sso``,
``test_verification``) leave uncovered: SAML assertion validation helpers,
OIDC discovery/id_token fallback, JIT session issuing, view error redirects,
and each verification factor's initiate/verify matrix.
"""
import base64
import sys
import uuid
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from lxml import etree
from rest_framework.test import APIClient, APITestCase

from stapel_auth.models import Organization, OrgMembership, SSOConfig
from stapel_auth.sso_service import OIDCService, SAMLService, SSOUserService
from stapel_auth.verification_factors import (
    EmailOtpFactor,
    FactorInitiationError,
    PasskeyFactor,
    PhoneOtpFactor,
    TotpFactor,
)

User = get_user_model()

FRONTEND = "https://app.example.com"
BACKEND = "https://app.example.com"
_OVERRIDE = {"FRONTEND_URL": FRONTEND, "BACKEND_URL": BACKEND}

_SAML_NS = 'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
_SAMLP_NS = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'


def _make_org(slug="acmecorp", domain="acmecorp.com", enforced=False):
    return Organization.objects.create(
        name="Acme Corp", slug=slug, domain=domain, sso_enforced=enforced,
    )


def _make_saml_config(org, **kw):
    defaults = dict(
        org=org,
        protocol=SSOConfig.PROTOCOL_SAML,
        is_active=True,
        saml_entity_id="https://idp.acmecorp.com",
        saml_sso_url="https://idp.acmecorp.com/sso/saml",
        saml_x509_cert="MIID...",
        attr_email="email",
        attr_first_name="firstName",
        attr_last_name="lastName",
    )
    defaults.update(kw)
    return SSOConfig.objects.create(**defaults)


def _make_oidc_config(org, **kw):
    defaults = dict(
        org=org,
        protocol=SSOConfig.PROTOCOL_OIDC,
        is_active=True,
        oidc_client_id="client_id_123",
        oidc_client_secret="secret_xyz",
        oidc_discovery_url="https://idp.acmecorp.com/.well-known/openid-configuration",
    )
    defaults.update(kw)
    return SSOConfig.objects.create(**defaults)


def _staff():
    uid = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        email=f"staff_{uid}@iron.com", username=f"staff_{uid}", password="pass",
        is_staff=True,
    )


def _el(xml: str):
    return etree.fromstring(xml.encode())


# =============================================================================
# SAMLService: import guard, DOCTYPE guard, cert normalisation
# =============================================================================


@override_settings(**_OVERRIDE)
class SAMLServiceParseGuardTests(TestCase):
    def setUp(self):
        self.org = _make_org()
        self.cfg = _make_saml_config(self.org)

    def test_missing_saml_deps_raises_runtime_error(self):
        # Simulate lxml/signxml not installed → RuntimeError with install hint.
        b64 = base64.b64encode(b"<x/>").decode()
        with patch.dict(sys.modules, {"lxml": None, "signxml": None}):
            with self.assertRaises(RuntimeError):
                SAMLService.parse_response(self.cfg, b64, org_slug="acmecorp")

    def test_doctype_in_response_is_rejected(self):
        b64 = base64.b64encode(b'<!DOCTYPE foo [<!ENTITY x "y">]><r/>').decode()
        with self.assertRaises(ValueError):
            SAMLService.parse_response(self.cfg, b64, org_slug="acmecorp")

    def test_pem_wrapped_cert_is_used_as_is(self):
        # cert already starting with '-----' skips the PEM-wrapping branch.
        pem = "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----"
        cfg = _make_saml_config(
            _make_org(slug="pemorg", domain="pem.com"), saml_x509_cert=pem,
        )
        b64 = base64.b64encode(b"<x/>").decode()
        mock_verified = MagicMock()
        mock_verified.signed_xml.find.return_value = None
        with patch("signxml.XMLVerifier") as MockV, patch(
            "lxml.etree.fromstring", return_value=MagicMock()
        ):
            MockV.return_value.verify.return_value = mock_verified
            with patch.object(SAMLService, "_validate_conditions"), patch.object(
                SAMLService, "_extract_attributes", return_value={"email": "a@b.com"}
            ):
                out = SAMLService.parse_response(cfg, b64)
        self.assertEqual(out["email"], "a@b.com")
        # The verifier received the un-modified PEM cert.
        _, kwargs = MockV.return_value.verify.call_args
        self.assertEqual(kwargs["x509_cert"], pem)


# =============================================================================
# SAMLService: _validate_conditions
# =============================================================================


class ValidateConditionsTests(TestCase):
    def test_no_conditions_returns(self):
        assertion = _el(f"<saml:Assertion {_SAML_NS}/>")
        self.assertIsNone(SAMLService._validate_conditions(assertion))

    def test_empty_conditions_no_bounds(self):
        assertion = _el(
            f"<saml:Assertion {_SAML_NS}><saml:Conditions/></saml:Assertion>"
        )
        self.assertIsNone(SAMLService._validate_conditions(assertion))

    def test_valid_time_window_passes(self):
        assertion = _el(
            f'<saml:Assertion {_SAML_NS}><saml:Conditions '
            f'NotBefore="2000-01-01T00:00:00Z" '
            f'NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:Assertion>'
        )
        self.assertIsNone(SAMLService._validate_conditions(assertion))

    def test_not_yet_valid_raises(self):
        assertion = _el(
            f'<saml:Assertion {_SAML_NS}><saml:Conditions '
            f'NotBefore="2099-01-01T00:00:00Z"/></saml:Assertion>'
        )
        with self.assertRaises(ValueError):
            SAMLService._validate_conditions(assertion)

    def test_expired_raises(self):
        assertion = _el(
            f'<saml:Assertion {_SAML_NS}><saml:Conditions '
            f'NotOnOrAfter="2000-01-01T00:00:00Z"/></saml:Assertion>'
        )
        with self.assertRaises(ValueError):
            SAMLService._validate_conditions(assertion)


class ParseSamlInstantTests(TestCase):
    def test_fractional_seconds_format(self):
        dt = SAMLService._parse_saml_instant("2020-01-01T00:00:00.123Z")
        self.assertEqual(dt.year, 2020)

    def test_invalid_timestamp_raises(self):
        with self.assertRaises(ValueError):
            SAMLService._parse_saml_instant("not-a-date")


# =============================================================================
# SAMLService: _validate_in_response_to / replay / attribute extraction
# =============================================================================


class InResponseToTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_uses_response_root_in_response_to(self):
        # Assertion has no SubjectConfirmationData → fall back to Response root.
        assertion = _el(f"<saml:Assertion {_SAML_NS}/>")
        response_root = _el(f'<samlp:Response {_SAMLP_NS} InResponseTo="_abc"/>')
        cache.set("saml_req:acmecorp:_abc", "1", 300)
        SAMLService._validate_in_response_to(assertion, response_root, "acmecorp")
        # consumed exactly once
        self.assertIsNone(cache.get("saml_req:acmecorp:_abc"))

    def test_no_in_response_to_is_allowed(self):
        assertion = _el(f"<saml:Assertion {_SAML_NS}/>")
        response_root = _el(f"<samlp:Response {_SAMLP_NS}/>")
        self.assertIsNone(
            SAMLService._validate_in_response_to(assertion, response_root, "acmecorp")
        )


class AssertionReplayTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_missing_id_raises(self):
        assertion = _el(f"<saml:Assertion {_SAML_NS}/>")
        with self.assertRaises(ValueError):
            SAMLService._check_assertion_replay(assertion)

    def test_no_not_after_uses_fallback_ttl(self):
        assertion = _el(f'<saml:Assertion {_SAML_NS} ID="_id1"/>')
        # first acceptance succeeds
        SAMLService._check_assertion_replay(assertion)
        # replay of same ID is rejected
        with self.assertRaises(ValueError):
            SAMLService._check_assertion_replay(assertion)


@override_settings(**_OVERRIDE)
class ValidateAudienceTests(TestCase):
    def test_no_audience_restriction_returns(self):
        assertion = _el(
            f"<saml:Assertion {_SAML_NS}><saml:Conditions/></saml:Assertion>"
        )
        self.assertIsNone(SAMLService._validate_audience(assertion, "acmecorp"))

    def test_matching_audience_passes(self):
        expected = SAMLService.sp_entity_id("acmecorp")
        assertion = _el(
            f"<saml:Assertion {_SAML_NS}><saml:Conditions>"
            f"<saml:AudienceRestriction><saml:Audience>{expected}</saml:Audience>"
            f"</saml:AudienceRestriction></saml:Conditions></saml:Assertion>"
        )
        self.assertIsNone(SAMLService._validate_audience(assertion, "acmecorp"))

    def test_mismatched_audience_raises(self):
        assertion = _el(
            f"<saml:Assertion {_SAML_NS}><saml:Conditions>"
            f"<saml:AudienceRestriction><saml:Audience>https://evil/</saml:Audience>"
            f"</saml:AudienceRestriction></saml:Conditions></saml:Assertion>"
        )
        with self.assertRaises(ValueError):
            SAMLService._validate_audience(assertion, "acmecorp")


class InResponseToSCDTests(TestCase):
    def setUp(self):
        cache.clear()

    def _assertion_with_scd(self, in_response_to):
        return _el(
            f"<saml:Assertion {_SAML_NS}><saml:Subject>"
            f"<saml:SubjectConfirmation><saml:SubjectConfirmationData "
            f'InResponseTo="{in_response_to}"/></saml:SubjectConfirmation>'
            f"</saml:Subject></saml:Assertion>"
        )

    def test_scd_in_response_to_consumed_from_cache(self):
        assertion = self._assertion_with_scd("_scd1")
        response_root = _el(f"<samlp:Response {_SAMLP_NS}/>")
        cache.set("saml_req:acmecorp:_scd1", "1", 300)
        SAMLService._validate_in_response_to(assertion, response_root, "acmecorp")
        self.assertIsNone(cache.get("saml_req:acmecorp:_scd1"))

    def test_unknown_in_response_to_raises(self):
        assertion = self._assertion_with_scd("_ghost")
        response_root = _el(f"<samlp:Response {_SAMLP_NS}/>")
        with self.assertRaises(ValueError):
            SAMLService._validate_in_response_to(assertion, response_root, "acmecorp")


class AssertionReplayWithExpiryTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_not_after_present_sets_ttl(self):
        assertion = _el(
            f'<saml:Assertion {_SAML_NS} ID="_exp1"><saml:Conditions '
            f'NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:Assertion>'
        )
        # first accept succeeds, replay rejected
        SAMLService._check_assertion_replay(assertion)
        with self.assertRaises(ValueError):
            SAMLService._check_assertion_replay(assertion)


@override_settings(**_OVERRIDE)
class ParseResponseOrchestrationTests(TestCase):
    def setUp(self):
        self.cfg = _make_saml_config(_make_org())

    def test_nested_assertion_and_org_slug_validation(self):
        # signed_xml.find returns a (non-None) nested Assertion and org_slug is
        # given → the audience/in-response-to/replay validators are invoked.
        nested = _el(f'<saml:Assertion {_SAML_NS} ID="_n1"/>')
        mock_verified = MagicMock()
        mock_verified.signed_xml.find.return_value = nested
        b64 = base64.b64encode(b"<x/>").decode()
        with patch("signxml.XMLVerifier") as MockV, patch(
            "lxml.etree.fromstring", return_value=MagicMock()
        ):
            MockV.return_value.verify.return_value = mock_verified
            with patch.object(SAMLService, "_validate_conditions") as m_cond, patch.object(
                SAMLService, "_validate_audience"
            ) as m_aud, patch.object(
                SAMLService, "_validate_in_response_to"
            ) as m_irt, patch.object(
                SAMLService, "_check_assertion_replay"
            ) as m_replay, patch.object(
                SAMLService, "_extract_attributes", return_value={"email": "z@z.com"}
            ):
                out = SAMLService.parse_response(self.cfg, b64, org_slug="acmecorp")
        self.assertEqual(out["email"], "z@z.com")
        m_cond.assert_called_once()
        m_aud.assert_called_once()
        m_irt.assert_called_once()
        m_replay.assert_called_once()


class ExtractAttributesTests(TestCase):
    def setUp(self):
        self.cfg = _make_saml_config(_make_org())

    def test_attribute_without_value_is_skipped(self):
        assertion = _el(
            f"<saml:Assertion {_SAML_NS}>"
            f"<saml:Subject><saml:NameID>bob@x.com</saml:NameID></saml:Subject>"
            f'<saml:AttributeStatement>'
            f'<saml:Attribute Name="empty"/>'
            f'<saml:Attribute Name="email">'
            f"<saml:AttributeValue>bob@x.com</saml:AttributeValue>"
            f"</saml:Attribute>"
            f"</saml:AttributeStatement></saml:Assertion>"
        )
        attrs = SAMLService._extract_attributes(assertion, self.cfg)
        self.assertEqual(attrs["email"], "bob@x.com")


# =============================================================================
# OIDCService: discovery + id_token fallback
# =============================================================================


@override_settings(**_OVERRIDE)
class OIDCServiceExtraTests(TestCase):
    def setUp(self):
        self.cfg = _make_oidc_config(_make_org())
        OIDCService._discovery_cache.clear()

    def test_discover_fetches_and_caches(self):
        payload = {"authorization_endpoint": "https://idp/auth"}
        resp = MagicMock()
        resp.json.return_value = payload
        with patch("requests.get", return_value=resp) as mock_get:
            first = OIDCService._discover("https://idp/.well-known")
            # second call is served from cache (no extra HTTP)
            second = OIDCService._discover("https://idp/.well-known")
        self.assertEqual(first, payload)
        self.assertEqual(second, payload)
        self.assertEqual(mock_get.call_count, 1)

    def test_exchange_code_falls_back_to_id_token(self):
        discovery = {
            "token_endpoint": "https://idp/token",
            # no userinfo_endpoint → id_token decode path
        }
        state_data = {"verifier": "v", "state": "s", "nonce": "n"}
        token_resp = MagicMock()
        token_resp.json.return_value = {"id_token": "the.jwt.token"}
        claims = {
            "sub": "sub-xyz",
            "email": "Carol@Acme.com",
            "name": "Carol Danvers",
        }
        with patch.object(OIDCService, "_discover", return_value=discovery), patch(
            "requests.post", return_value=token_resp
        ), patch("jwt.decode", return_value=claims):
            attrs = OIDCService.exchange_code("acmecorp", self.cfg, "code", state_data)
        self.assertEqual(attrs["email"], "carol@acme.com")
        self.assertEqual(attrs["subject_id"], "sub-xyz")
        self.assertEqual(attrs["first_name"], "Carol")
        self.assertEqual(attrs["last_name"], "Danvers")


# =============================================================================
# SSOUserService.issue_session_and_redirect (end to end)
# =============================================================================


@override_settings(**_OVERRIDE)
class IssueSessionTests(TestCase):
    def setUp(self):
        cache.clear()
        self.org = _make_org()
        self.user = User.objects.create_user(
            email="live@acmecorp.com", username="live", password="x",
        )
        OrgMembership.objects.create(user=self.user, org=self.org)

    def test_issues_session_and_redirects_to_frontend(self):
        # Regression: this method used to call sessions.views._issue_session_tokens
        # (which registers the refresh jti as a UserSession) and then create a
        # second UserSession from the same jti -> IntegrityError on the DB
        # unique(jti) constraint. Run fully end-to-end with the real
        # SessionService and assert exactly one session row is persisted.
        from stapel_auth.models import UserSession
        from stapel_auth.sessions.services import LoginNotificationService

        request = RequestFactory().post("/auth/api/v1/sso/acmecorp/saml/acs/")
        with patch.object(LoginNotificationService, "check_and_notify"):
            response = SSOUserService.issue_session_and_redirect(
                self.user, self.org, request
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], f"{FRONTEND}/")
        # JWT cookies were set on the redirect.
        self.assertTrue(any(response.cookies))
        self.assertEqual(UserSession.objects.filter(user=self.user).count(), 1)
        # `stapel_auth_hint` (auth-react bootstrapProbe "auto" gate,
        # 2026-07-19) rides every redirect-based cookie mint, SSO included.
        from stapel_auth.hint_cookie import HINT_COOKIE_NAME

        self.assertIn(HINT_COOKIE_NAME, response.cookies)
        self.assertEqual(response.cookies[HINT_COOKIE_NAME].value, "1")

    def test_redirects_when_no_session_created(self):
        # SessionService.create returns None (e.g. jti absent) → the notify
        # branch is skipped but the redirect still issues.
        from stapel_auth.sessions.services import LoginNotificationService, SessionService

        request = RequestFactory().post("/auth/api/v1/sso/acmecorp/saml/acs/")
        with patch.object(
            SessionService, "create", return_value=None
        ), patch.object(LoginNotificationService, "check_and_notify") as m_notify:
            response = SSOUserService.issue_session_and_redirect(
                self.user, self.org, request
            )
        self.assertEqual(response.status_code, 302)
        m_notify.assert_not_called()


# =============================================================================
# sso_views: domain lookup / login / ACS / callback / admin error branches
# =============================================================================


@override_settings(**_OVERRIDE)
class DomainLookupExtraTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        cache.clear()

    def test_org_without_config_returns_no_sso(self):
        # Org matched by domain but has no SSOConfig → DoesNotExist branch.
        _make_org(domain="noconf.com")
        resp = self.client.get(reverse("sso_lookup"), {"domain": "noconf.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data["sso_required"])
        self.assertIsNone(resp.data["org_slug"])


@override_settings(**_OVERRIDE)
class SSOLoginErrorTests(APITestCase):
    def setUp(self):
        cache.clear()
        OIDCService._discovery_cache.clear()
        self.org = _make_org()

    def test_saml_build_error_returns_500(self):
        _make_saml_config(self.org)
        with patch.object(
            SAMLService, "build_authn_request", side_effect=Exception("boom")
        ):
            resp = self.client.get(reverse("sso_login", kwargs={"slug": "acmecorp"}))
        self.assertEqual(resp.status_code, 500)

    def test_oidc_authorize_error_returns_500(self):
        _make_oidc_config(self.org)
        with patch.object(
            OIDCService, "authorization_url", side_effect=Exception("boom")
        ):
            resp = self.client.get(reverse("sso_login", kwargs={"slug": "acmecorp"}))
        self.assertEqual(resp.status_code, 500)

    def test_unknown_protocol_returns_400(self):
        cfg = _make_saml_config(self.org)
        # Bypass model validation: store a protocol that is neither SAML nor OIDC.
        SSOConfig.objects.filter(pk=cfg.pk).update(protocol="ldap")
        resp = self.client.get(reverse("sso_login", kwargs={"slug": "acmecorp"}))
        self.assertEqual(resp.status_code, 400)


@override_settings(**_OVERRIDE)
class SAMLACSErrorTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.org = _make_org()

    def test_protocol_mismatch_redirects_not_configured(self):
        _make_oidc_config(self.org)  # ACS expects SAML
        url = reverse("sso_saml_acs", kwargs={"slug": "acmecorp"})
        resp = self.client.post(url, {"SAMLResponse": base64.b64encode(b"<x/>").decode()})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=sso_not_configured", resp["Location"])

    def test_jit_value_error_redirects_invalid_response(self):
        _make_saml_config(self.org)
        url = reverse("sso_saml_acs", kwargs={"slug": "acmecorp"})
        bad_attrs = {"subject_id": "", "email": "", "first_name": "", "last_name": ""}
        with patch.object(SAMLService, "parse_response", return_value=bad_attrs):
            resp = self.client.post(
                url, {"SAMLResponse": base64.b64encode(b"<x/>").decode()}
            )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=sso_invalid_response", resp["Location"])


@override_settings(**_OVERRIDE)
class OIDCCallbackErrorTests(APITestCase):
    def setUp(self):
        cache.clear()
        OIDCService._discovery_cache.clear()
        self.org = _make_org()

    def _store_state(self, state="teststate"):
        import json

        data = {"state": state, "nonce": "n", "verifier": "v", "org_slug": "acmecorp"}
        cache.set(f"oidc_state:{state}", json.dumps(data), 600)

    def test_unknown_org_redirects(self):
        url = reverse("sso_oidc_callback", kwargs={"slug": "nobody"})
        resp = self.client.get(url, {"code": "c", "state": "s"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=sso_org_not_found", resp["Location"])

    def test_protocol_mismatch_redirects(self):
        _make_saml_config(self.org)  # callback expects OIDC
        url = reverse("sso_oidc_callback", kwargs={"slug": "acmecorp"})
        resp = self.client.get(url, {"code": "c", "state": "s"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=sso_not_configured", resp["Location"])

    def test_exchange_exception_redirects(self):
        _make_oidc_config(self.org)
        self._store_state()
        url = reverse("sso_oidc_callback", kwargs={"slug": "acmecorp"})
        with patch.object(
            OIDCService, "exchange_code", side_effect=Exception("network")
        ):
            resp = self.client.get(url, {"code": "c", "state": "teststate"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=sso_invalid_response", resp["Location"])

    def test_jit_value_error_redirects(self):
        _make_oidc_config(self.org)
        self._store_state()
        url = reverse("sso_oidc_callback", kwargs={"slug": "acmecorp"})
        bad_attrs = {"subject_id": "", "email": "", "first_name": "", "last_name": ""}
        with patch.object(OIDCService, "exchange_code", return_value=bad_attrs):
            resp = self.client.get(url, {"code": "c", "state": "teststate"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=sso_invalid_response", resp["Location"])

    def test_inactive_user_redirects_account_disabled(self):
        _make_oidc_config(self.org)
        self._store_state()
        User.objects.create_user(
            email="off@acmecorp.com", username="off", password="x", is_active=False,
        )
        good = {
            "subject_id": "s", "email": "off@acmecorp.com",
            "first_name": "", "last_name": "",
        }
        url = reverse("sso_oidc_callback", kwargs={"slug": "acmecorp"})
        with patch.object(OIDCService, "exchange_code", return_value=good):
            resp = self.client.get(url, {"code": "c", "state": "teststate"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=account_disabled", resp["Location"])


class SSOAdminNotFoundTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        from stapel_core.django.jwt.provider import jwt_provider

        access, _ = jwt_provider.create_tokens(_staff())
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def test_update_unknown_org_404(self):
        resp = self.client.patch(
            reverse("sso_org", kwargs={"slug": "nobody"}),
            {"sso_enforced": True}, format="json",
        )
        self.assertEqual(resp.status_code, 404)

    def test_delete_unknown_org_404(self):
        resp = self.client.delete(reverse("sso_org", kwargs={"slug": "nobody"}))
        self.assertEqual(resp.status_code, 404)

    def test_upsert_config_unknown_org_404(self):
        resp = self.client.put(
            reverse("sso_org_config", kwargs={"slug": "nobody"}),
            {"protocol": "saml", "is_active": True}, format="json",
        )
        self.assertEqual(resp.status_code, 404)


# =============================================================================
# verification_factors: per-factor initiate/verify matrix
# =============================================================================


def _vuser(**kw):
    d = dict(
        email=f"vf-{uuid.uuid4().hex[:8]}@example.com",
        username=f"vf_{uuid.uuid4().hex[:8]}",
        password="testpass123",
    )
    d.update(kw)
    return User.objects.create_user(**d)


class EmailOtpFactorTests(TestCase):
    def test_verify_empty_code_returns_false(self):
        self.assertFalse(EmailOtpFactor().verify(_vuser(), {}, {"code": ""}))

    def test_verify_delegates_to_service(self):
        user = _vuser()
        with patch(
            "stapel_auth.otp.services.EmailVerificationService"
        ) as MockSvc:
            MockSvc.return_value.verify_code.return_value = {"success": True}
            self.assertTrue(EmailOtpFactor().verify(user, {}, {"code": "1234"}))
            MockSvc.return_value.verify_code.assert_called_once_with(user.email, "1234")


class PhoneOtpFactorTests(TestCase):
    def test_initiate_returns_masked_target(self):
        user = _vuser(phone="+12025550142")
        with patch("stapel_auth.otp.services.PhoneVerificationService") as MockSvc:
            MockSvc.return_value.send_verification_code.return_value = {"success": True}
            out = PhoneOtpFactor().initiate(user, {})
        self.assertIn("target", out)
        self.assertIn("*", out["target"])

    def test_initiate_send_failure_raises(self):
        user = _vuser(phone="+12025550142")
        with patch("stapel_auth.otp.services.PhoneVerificationService") as MockSvc:
            MockSvc.return_value.send_verification_code.return_value = {"error": "rate"}
            with self.assertRaises(FactorInitiationError):
                PhoneOtpFactor().initiate(user, {})

    def test_initiate_none_result_raises(self):
        user = _vuser(phone="+12025550142")
        with patch("stapel_auth.otp.services.PhoneVerificationService") as MockSvc:
            MockSvc.return_value.send_verification_code.return_value = None
            with self.assertRaises(FactorInitiationError):
                PhoneOtpFactor().initiate(user, {})

    def test_verify_empty_code_returns_false(self):
        self.assertFalse(PhoneOtpFactor().verify(_vuser(), {}, {}))

    def test_verify_delegates_to_service(self):
        user = _vuser(phone="+12025550142")
        with patch("stapel_auth.otp.services.PhoneVerificationService") as MockSvc:
            MockSvc.return_value.verify_code.return_value = {"success": True}
            self.assertTrue(PhoneOtpFactor().verify(user, {}, {"code": "9999"}))


class TotpFactorTests(TestCase):
    def test_verify_with_code(self):
        user = _vuser()
        with patch("stapel_auth.mfa.services.TOTPService") as MockSvc:
            MockSvc.verify_code.return_value = True
            self.assertTrue(TotpFactor().verify(user, {}, {"code": "123456"}))
            MockSvc.verify_code.assert_called_once_with(user, "123456")

    def test_verify_with_backup_code(self):
        user = _vuser()
        with patch("stapel_auth.mfa.services.TOTPService") as MockSvc:
            MockSvc.verify_backup_code.return_value = True
            self.assertTrue(
                TotpFactor().verify(user, {}, {"backup_code": "abcd-efgh"})
            )
            MockSvc.verify_backup_code.assert_called_once_with(user, "abcd-efgh")

    def test_verify_no_input_returns_false(self):
        with patch("stapel_auth.mfa.services.TOTPService"):
            self.assertFalse(TotpFactor().verify(_vuser(), {}, {}))


class PasskeyFactorTests(TestCase):
    def test_initiate_returns_options(self):
        user = _vuser()
        with patch("stapel_auth.mfa.services.PasskeyService") as MockSvc:
            MockSvc.authentication_begin.return_value = ("sess-1", '{"challenge": "c"}')
            out = PasskeyFactor().initiate(user, {})
        self.assertEqual(out["session_key"], "sess-1")
        self.assertEqual(out["options"], {"challenge": "c"})

    def test_initiate_dict_options_passthrough(self):
        user = _vuser()
        with patch("stapel_auth.mfa.services.PasskeyService") as MockSvc:
            MockSvc.authentication_begin.return_value = ("sess-2", {"challenge": "c"})
            out = PasskeyFactor().initiate(user, {})
        self.assertEqual(out["options"], {"challenge": "c"})

    def test_initiate_failure_raises(self):
        user = _vuser()
        with patch("stapel_auth.mfa.services.PasskeyService") as MockSvc:
            MockSvc.authentication_begin.side_effect = Exception("boom")
            with self.assertRaises(FactorInitiationError):
                PasskeyFactor().initiate(user, {})

    def test_verify_missing_payload_returns_false(self):
        self.assertFalse(PasskeyFactor().verify(_vuser(), {}, {}))

    def test_verify_success_matches_user(self):
        user = _vuser()
        with patch("stapel_auth.mfa.services.PasskeyService") as MockSvc:
            MockSvc.authentication_complete.return_value = (user, None)
            ok = PasskeyFactor().verify(
                user, {}, {"session_key": "s", "credential": {"id": "x"}}
            )
        self.assertTrue(ok)

    def test_verify_different_user_returns_false(self):
        user = _vuser()
        other = _vuser()
        with patch("stapel_auth.mfa.services.PasskeyService") as MockSvc:
            MockSvc.authentication_complete.return_value = (other, None)
            ok = PasskeyFactor().verify(
                user, {}, {"session_key": "s", "credential": {"id": "x"}}
            )
        self.assertFalse(ok)

    def test_verify_value_error_returns_false(self):
        user = _vuser()
        with patch("stapel_auth.mfa.services.PasskeyService") as MockSvc:
            MockSvc.authentication_complete.side_effect = ValueError("bad")
            ok = PasskeyFactor().verify(
                user, {}, {"session_key": "s", "credential": {"id": "x"}}
            )
        self.assertFalse(ok)

    def test_verify_unexpected_error_returns_false(self):
        user = _vuser()
        with patch("stapel_auth.mfa.services.PasskeyService") as MockSvc:
            MockSvc.authentication_complete.side_effect = Exception("boom")
            ok = PasskeyFactor().verify(
                user, {}, {"session_key": "s", "credential": {"id": "x"}}
            )
        self.assertFalse(ok)
