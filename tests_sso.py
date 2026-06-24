"""Tests for SSO — SAML 2.0 and OIDC flows, JIT provisioning, admin CRUD."""
import base64
import json
import uuid
import zlib
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from .models import Organization, OrgMembership, SSOConfig
from .sso_service import OIDCService, SAMLService, SSOUserService

User = get_user_model()

FRONTEND = 'https://app.example.com'
BACKEND  = 'https://app.example.com'

_OVERRIDE = {
    'FRONTEND_URL': FRONTEND,
    'BACKEND_URL':  BACKEND,
}


# =============================================================================
# Helpers
# =============================================================================

def _make_org(slug='acmecorp', domain='acmecorp.com', enforced=False):
    return Organization.objects.create(
        name='Acme Corp', slug=slug, domain=domain, sso_enforced=enforced,
    )


def _make_saml_config(org):
    return SSOConfig.objects.create(
        org=org,
        protocol=SSOConfig.PROTOCOL_SAML,
        is_active=True,
        saml_entity_id='https://idp.acmecorp.com',
        saml_sso_url='https://idp.acmecorp.com/sso/saml',
        saml_x509_cert='MIID...',
        attr_email='email',
        attr_first_name='firstName',
        attr_last_name='lastName',
    )


def _make_oidc_config(org):
    return SSOConfig.objects.create(
        org=org,
        protocol=SSOConfig.PROTOCOL_OIDC,
        is_active=True,
        oidc_client_id='client_id_123',
        oidc_client_secret='secret_xyz',
        oidc_discovery_url='https://idp.acmecorp.com/.well-known/openid-configuration',
    )


def _staff_user():
    uid = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        email=f'staff_{uid}@iron.com', username=f'staff_{uid}', password='pass', is_staff=True,
    )


def _normal_user():
    uid = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        email=f'user_{uid}@iron.com', username=f'user_{uid}', password='pass',
    )


# Minimal SAMLResponse that our mock will "verify"
_FAKE_SAML_RESPONSE_B64 = base64.b64encode(b'<fake/>').decode()


# =============================================================================
# Unit: SAMLService
# =============================================================================

@override_settings(**_OVERRIDE)
class SAMLServiceTests(TestCase):

    def setUp(self):
        self.org = _make_org()
        self.cfg = _make_saml_config(self.org)

    def test_sp_entity_id_contains_slug(self):
        eid = SAMLService.sp_entity_id('acmecorp')
        self.assertIn('acmecorp', eid)
        self.assertIn('/saml/metadata/', eid)

    def test_acs_url_contains_slug(self):
        acs = SAMLService.acs_url('acmecorp')
        self.assertIn('acmecorp', acs)
        self.assertIn('/saml/acs/', acs)

    def test_generate_metadata_is_xml(self):
        xml = SAMLService.generate_metadata('acmecorp')
        self.assertIn('EntityDescriptor', xml)
        self.assertIn('AssertionConsumerService', xml)
        self.assertIn('/saml/acs/', xml)
        self.assertIn('acmecorp', xml)

    def test_build_authn_request_redirects_to_idp(self):
        cache.clear()
        url, req_id = SAMLService.build_authn_request('acmecorp', self.cfg)
        self.assertTrue(url.startswith('https://idp.acmecorp.com/sso/saml'))
        self.assertIn('SAMLRequest=', url)
        self.assertTrue(req_id.startswith('_'))

    def test_authn_request_saml_request_decodable(self):
        cache.clear()
        url, _ = SAMLService.build_authn_request('acmecorp', self.cfg)
        qs = dict(p.split('=', 1) for p in url.split('?', 1)[1].split('&'))
        from urllib.parse import unquote
        raw_b64 = unquote(qs['SAMLRequest'])
        deflated = base64.b64decode(raw_b64)
        # Raw inflate (wbits=-15 = no zlib header/trailer)
        xml = zlib.decompress(deflated, wbits=-15)
        self.assertIn(b'AuthnRequest', xml)
        self.assertIn(b'acmecorp', xml)

    def test_extract_attributes_parses_real_xml(self):
        """_extract_attributes correctly parses a SAML Assertion element with lxml."""
        from lxml import etree
        assertion_xml = (
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<saml:Subject><saml:NameID>bob@acmecorp.com</saml:NameID></saml:Subject>'
            '<saml:AttributeStatement>'
            '<saml:Attribute Name="email">'
            '<saml:AttributeValue>bob@acmecorp.com</saml:AttributeValue>'
            '</saml:Attribute>'
            '<saml:Attribute Name="firstName">'
            '<saml:AttributeValue>Bob</saml:AttributeValue>'
            '</saml:Attribute>'
            '<saml:Attribute Name="lastName">'
            '<saml:AttributeValue>Builder</saml:AttributeValue>'
            '</saml:Attribute>'
            '</saml:AttributeStatement>'
            '</saml:Assertion>'
        )
        assertion = etree.fromstring(assertion_xml.encode())
        attrs = SAMLService._extract_attributes(assertion, self.cfg)
        self.assertEqual(attrs['email'], 'bob@acmecorp.com')
        self.assertEqual(attrs['first_name'], 'Bob')
        self.assertEqual(attrs['last_name'], 'Builder')
        self.assertEqual(attrs['subject_id'], 'bob@acmecorp.com')

    def test_parse_response_verifies_signature(self):
        """parse_response passes the decoded XML to XMLVerifier and returns attrs."""
        mock_verified = MagicMock()
        mock_verified.signed_xml.find.return_value = None  # no nested Assertion

        with patch('signxml.XMLVerifier') as MockVerifier, \
             patch('lxml.etree.fromstring', return_value=MagicMock()):
            MockVerifier.return_value.verify.return_value = mock_verified
            with patch.object(SAMLService, '_validate_conditions'), \
                 patch.object(SAMLService, '_extract_attributes', return_value={
                     'subject_id': 'bob@acmecorp.com',
                     'email': 'bob@acmecorp.com',
                     'first_name': 'Bob',
                     'last_name': 'Smith',
                 }):
                result = SAMLService.parse_response(self.cfg, _FAKE_SAML_RESPONSE_B64)

        self.assertEqual(result['email'], 'bob@acmecorp.com')
        MockVerifier.return_value.verify.assert_called_once()


# =============================================================================
# Unit: OIDCService
# =============================================================================

@override_settings(**_OVERRIDE)
class OIDCServiceTests(TestCase):

    def setUp(self):
        self.org = _make_org()
        self.cfg = _make_oidc_config(self.org)
        self._discovery = {
            'authorization_endpoint': 'https://idp.acmecorp.com/authorize',
            'token_endpoint': 'https://idp.acmecorp.com/token',
            'userinfo_endpoint': 'https://idp.acmecorp.com/userinfo',
        }
        OIDCService._discovery_cache.clear()

    def _patch_discover(self):
        return patch.object(OIDCService, '_discover', return_value=self._discovery)

    def test_authorization_url_contains_client_id(self):
        with self._patch_discover():
            url, state_data = OIDCService.authorization_url('acmecorp', self.cfg)
        self.assertIn('client_id=client_id_123', url)
        self.assertIn('code_challenge=', url)
        self.assertIn('code_challenge_method=S256', url)
        self.assertIn('state', state_data)
        self.assertIn('verifier', state_data)

    def test_authorization_url_has_pkce_challenge(self):
        import hashlib
        with self._patch_discover():
            url, state_data = OIDCService.authorization_url('acmecorp', self.cfg)
        verifier = state_data['verifier'].encode()
        expected_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier).digest())
            .rstrip(b'=').decode()
        )
        self.assertIn(f'code_challenge={expected_challenge}', url)

    def test_exchange_code_returns_user_attrs(self):
        import requests as real_requests
        state_data = {'verifier': 'abc', 'nonce': 'n', 'state': 's', 'org_slug': 'acmecorp'}
        mock_token_resp = MagicMock()
        mock_token_resp.json.return_value = {'access_token': 'tok123'}
        mock_userinfo_resp = MagicMock()
        mock_userinfo_resp.json.return_value = {
            'sub': 'sub-001',
            'email': 'alice@acmecorp.com',
            'given_name': 'Alice',
            'family_name': 'Wonder',
        }
        with self._patch_discover(), \
             patch.object(real_requests, 'post', return_value=mock_token_resp), \
             patch.object(real_requests, 'get', return_value=mock_userinfo_resp):
            attrs = OIDCService.exchange_code('acmecorp', self.cfg, 'auth_code', state_data)

        self.assertEqual(attrs['email'], 'alice@acmecorp.com')
        self.assertEqual(attrs['first_name'], 'Alice')
        self.assertEqual(attrs['subject_id'], 'sub-001')


# =============================================================================
# Unit: SSOUserService
# =============================================================================

class SSOUserServiceTests(TestCase):

    def setUp(self):
        self.org = _make_org()

    def test_creates_new_user_on_first_login(self):
        attrs = {'email': 'newbie@acmecorp.com', 'first_name': 'New', 'last_name': 'Bie', 'subject_id': 'sub-1'}
        user, created = SSOUserService.get_or_create_user(self.org, attrs)
        self.assertTrue(created)
        self.assertEqual(user.email, 'newbie@acmecorp.com')
        self.assertEqual(user.first_name, 'New')
        self.assertTrue(OrgMembership.objects.filter(user=user, org=self.org).exists())

    def test_links_existing_user_by_email(self):
        existing = User.objects.create_user(
            email='existing@acmecorp.com', username='existing', password='x',
        )
        attrs = {'email': 'existing@acmecorp.com', 'first_name': '', 'last_name': '', 'subject_id': 'sub-2'}
        user, created = SSOUserService.get_or_create_user(self.org, attrs)
        self.assertFalse(created)
        self.assertEqual(user.pk, existing.pk)

    def test_upserts_org_membership_subject_id(self):
        attrs = {'email': 'bob@acmecorp.com', 'first_name': '', 'last_name': '', 'subject_id': 'sub-999'}
        user, _ = SSOUserService.get_or_create_user(self.org, attrs)
        membership = OrgMembership.objects.get(user=user, org=self.org)
        self.assertEqual(membership.sso_subject_id, 'sub-999')

    def test_syncs_name_on_existing_nameless_user(self):
        existing = User.objects.create_user(
            email='noname@acmecorp.com', username='noname', password='x',
            first_name='', last_name='',
        )
        attrs = {'email': 'noname@acmecorp.com', 'first_name': 'John', 'last_name': 'Doe', 'subject_id': 's'}
        user, _ = SSOUserService.get_or_create_user(self.org, attrs)
        user.refresh_from_db()
        self.assertEqual(user.first_name, 'John')

    def test_raises_on_missing_email(self):
        attrs = {'email': '', 'first_name': '', 'last_name': '', 'subject_id': 's'}
        with self.assertRaises(ValueError):
            SSOUserService.get_or_create_user(self.org, attrs)


# =============================================================================
# Integration: Domain lookup
# =============================================================================

class SSODomainLookupTests(APITestCase):

    def setUp(self):
        self.client = APIClient()
        cache.clear()

    def test_unknown_domain_returns_no_sso(self):
        resp = self.client.get(reverse('sso_lookup'), {'domain': 'unknown.com'})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data['sso_required'])
        self.assertIsNone(resp.data['org_slug'])

    def test_known_domain_not_enforced(self):
        org = _make_org(domain='beta.com', enforced=False)
        _make_saml_config(org)
        resp = self.client.get(reverse('sso_lookup'), {'domain': 'beta.com'})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data['sso_required'])
        self.assertEqual(resp.data['org_slug'], 'acmecorp')

    def test_known_domain_enforced(self):
        org = _make_org(domain='enforced.com', enforced=True)
        _make_saml_config(org)
        resp = self.client.get(reverse('sso_lookup'), {'domain': 'enforced.com'})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['sso_required'])
        self.assertEqual(resp.data['protocol'], 'saml')

    def test_inactive_config_returns_no_sso(self):
        org = _make_org(domain='inactive.com', enforced=True)
        SSOConfig.objects.create(
            org=org, protocol=SSOConfig.PROTOCOL_SAML, is_active=False,
            saml_entity_id='x', saml_sso_url='https://x.com', saml_x509_cert='x',
        )
        resp = self.client.get(reverse('sso_lookup'), {'domain': 'inactive.com'})
        self.assertFalse(resp.data['sso_required'])

    def test_missing_domain_param(self):
        resp = self.client.get(reverse('sso_lookup'))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data['sso_required'])


# =============================================================================
# Integration: SAML metadata endpoint
# =============================================================================

@override_settings(**_OVERRIDE)
class SAMLMetadataViewTests(APITestCase):

    def setUp(self):
        self.org = _make_org()

    def test_returns_xml(self):
        resp = self.client.get(reverse('sso_saml_metadata', kwargs={'slug': 'acmecorp'}))
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'EntityDescriptor', resp.content)
        self.assertIn(b'AssertionConsumerService', resp.content)

    def test_unknown_org_returns_404(self):
        resp = self.client.get(reverse('sso_saml_metadata', kwargs={'slug': 'nobody'}))
        self.assertEqual(resp.status_code, 404)


# =============================================================================
# Integration: SAML login initiation
# =============================================================================

@override_settings(**_OVERRIDE)
class SSOLoginViewTests(APITestCase):
    """Unified /sso/<slug>/login/ dispatches to SAML or OIDC based on org config."""

    def setUp(self):
        cache.clear()
        OIDCService._discovery_cache.clear()
        self.org = _make_org()

    def test_unknown_org_returns_404(self):
        resp = self.client.get(reverse('sso_login', kwargs={'slug': 'nobody'}))
        self.assertEqual(resp.status_code, 404)

    def test_no_config_returns_400(self):
        resp = self.client.get(reverse('sso_login', kwargs={'slug': 'acmecorp'}))
        self.assertEqual(resp.status_code, 400)

    def test_inactive_config_returns_400(self):
        SSOConfig.objects.create(
            org=self.org, protocol=SSOConfig.PROTOCOL_SAML, is_active=False,
            saml_entity_id='x', saml_sso_url='https://idp.com', saml_x509_cert='x',
        )
        resp = self.client.get(reverse('sso_login', kwargs={'slug': 'acmecorp'}))
        self.assertEqual(resp.status_code, 400)

    def test_saml_redirects_to_idp(self):
        _make_saml_config(self.org)
        resp = self.client.get(reverse('sso_login', kwargs={'slug': 'acmecorp'}))
        self.assertEqual(resp.status_code, 302)
        self.assertIn('idp.acmecorp.com', resp['Location'])
        self.assertIn('SAMLRequest=', resp['Location'])

    def test_oidc_redirects_to_idp(self):
        _make_oidc_config(self.org)
        discovery = {
            'authorization_endpoint': 'https://idp.acmecorp.com/authorize',
            'token_endpoint': 'https://idp.acmecorp.com/token',
        }
        with patch.object(OIDCService, '_discover', return_value=discovery):
            resp = self.client.get(reverse('sso_login', kwargs={'slug': 'acmecorp'}))
        self.assertEqual(resp.status_code, 302)
        self.assertIn('idp.acmecorp.com/authorize', resp['Location'])
        self.assertIn('client_id=client_id_123', resp['Location'])


# =============================================================================
# Integration: SAML ACS
# =============================================================================

@override_settings(**_OVERRIDE)
class SAMLACSViewTests(APITestCase):

    def setUp(self):
        cache.clear()
        self.org = _make_org()
        self.cfg = _make_saml_config(self.org)
        self.url = reverse('sso_saml_acs', kwargs={'slug': 'acmecorp'})

    def test_no_saml_response_redirects_with_error(self):
        resp = self.client.post(self.url, {})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('error=sso_invalid_response', resp['Location'])

    def test_invalid_response_redirects_with_error(self):
        with patch('signxml.XMLVerifier') as MockV, \
             patch('lxml.etree.fromstring', return_value=MagicMock()):
            MockV.return_value.verify.side_effect = Exception('bad signature')
            resp = self.client.post(self.url, {'SAMLResponse': _FAKE_SAML_RESPONSE_B64})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('error=sso_invalid_response', resp['Location'])

    def test_valid_response_creates_user_and_redirects(self):
        good_attrs = {
            'subject_id': 'alice@acmecorp.com',
            'email': 'alice@acmecorp.com',
            'first_name': 'Alice',
            'last_name': 'Corp',
        }
        with patch.object(SAMLService, 'parse_response', return_value=good_attrs), \
             patch.object(SSOUserService, 'issue_session_and_redirect') as mock_issue:
            from django.http import HttpResponseRedirect
            mock_issue.return_value = HttpResponseRedirect(f'{FRONTEND}/')
            resp = self.client.post(self.url, {'SAMLResponse': _FAKE_SAML_RESPONSE_B64})

        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('error=', resp['Location'])
        self.assertTrue(User.objects.filter(email='alice@acmecorp.com').exists())

    def test_unknown_org_redirects_with_error(self):
        url = reverse('sso_saml_acs', kwargs={'slug': 'nobody'})
        resp = self.client.post(url, {'SAMLResponse': _FAKE_SAML_RESPONSE_B64})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('error=sso_org_not_found', resp['Location'])

    def test_disabled_user_redirects_with_error(self):
        User.objects.create_user(
            email='disabled@acmecorp.com', username='disabled', password='x', is_active=False,
        )
        good_attrs = {
            'subject_id': 'disabled@acmecorp.com',
            'email': 'disabled@acmecorp.com',
            'first_name': '', 'last_name': '',
        }
        with patch.object(SAMLService, 'parse_response', return_value=good_attrs):
            resp = self.client.post(self.url, {'SAMLResponse': _FAKE_SAML_RESPONSE_B64})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('error=account_disabled', resp['Location'])


# =============================================================================
# Integration: OIDC callback
# =============================================================================

@override_settings(**_OVERRIDE)
class OIDCCallbackViewTests(APITestCase):

    def setUp(self):
        cache.clear()
        OIDCService._discovery_cache.clear()
        self.org = _make_org()
        self.cfg = _make_oidc_config(self.org)
        self.url = reverse('sso_oidc_callback', kwargs={'slug': 'acmecorp'})

    def _store_state(self, state='teststate'):
        state_data = {'state': state, 'nonce': 'n', 'verifier': 'v', 'org_slug': 'acmecorp'}
        cache.set(f'oidc_state:{state}', json.dumps(state_data), 600)
        return state_data

    def test_no_code_redirects_with_error(self):
        self._store_state()
        resp = self.client.get(self.url, {'state': 'teststate'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('error=sso_invalid_response', resp['Location'])

    def test_invalid_state_redirects_with_error(self):
        resp = self.client.get(self.url, {'code': 'abc', 'state': 'badstate'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('error=sso_invalid_response', resp['Location'])

    def test_idp_error_redirects(self):
        resp = self.client.get(self.url, {'error': 'access_denied'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('error=sso_invalid_response', resp['Location'])

    def test_valid_callback_creates_user(self):
        self._store_state()
        good_attrs = {
            'subject_id': 'sub-bob',
            'email': 'bob@acmecorp.com',
            'first_name': 'Bob',
            'last_name': 'Corp',
        }
        with patch.object(OIDCService, 'exchange_code', return_value=good_attrs), \
             patch.object(SSOUserService, 'issue_session_and_redirect') as mock_issue:
            from django.http import HttpResponseRedirect
            mock_issue.return_value = HttpResponseRedirect(f'{FRONTEND}/')
            resp = self.client.get(self.url, {'code': 'authcode', 'state': 'teststate'})

        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('error=', resp['Location'])
        self.assertTrue(User.objects.filter(email='bob@acmecorp.com').exists())

    def test_state_consumed_on_use(self):
        """Second callback with the same state must fail (replay protection)."""
        self._store_state()
        good_attrs = {'subject_id': 's', 'email': 'x@y.com', 'first_name': '', 'last_name': ''}
        from django.http import HttpResponseRedirect
        with patch.object(OIDCService, 'exchange_code', return_value=good_attrs), \
             patch.object(SSOUserService, 'issue_session_and_redirect',
                          return_value=HttpResponseRedirect(f'{FRONTEND}/')):
            self.client.get(self.url, {'code': 'code1', 'state': 'teststate'})

        # Second request with same state
        resp2 = self.client.get(self.url, {'code': 'code2', 'state': 'teststate'})
        self.assertIn('error=sso_invalid_response', resp2['Location'])


# =============================================================================
# Integration: Admin CRUD
# =============================================================================

class SSOAdminCRUDTests(APITestCase):

    def setUp(self):
        self.staff = _staff_user()
        self.regular = _normal_user()
        self.client = APIClient()

    def _auth(self, user):
        from stapel_core.django.jwt_provider import jwt_provider
        access, _ = jwt_provider.create_tokens(user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')

    def test_non_staff_cannot_list_orgs(self):
        self._auth(self.regular)
        resp = self.client.get(reverse('sso_orgs'))
        self.assertEqual(resp.status_code, 403)

    def test_unauthenticated_cannot_list_orgs(self):
        resp = self.client.get(reverse('sso_orgs'))
        self.assertEqual(resp.status_code, 401)

    def test_staff_can_list_empty_orgs(self):
        self._auth(self.staff)
        resp = self.client.get(reverse('sso_orgs'))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, [])

    def test_staff_can_create_org(self):
        self._auth(self.staff)
        resp = self.client.post(reverse('sso_orgs'), {
            'name': 'Acme', 'slug': 'acme', 'domain': 'acme.com',
        }, format='json')
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data['slug'], 'acme')
        self.assertTrue(Organization.objects.filter(slug='acme').exists())

    def test_duplicate_slug_returns_409(self):
        _make_org(slug='acmecorp', domain='acmecorp.com')
        self._auth(self.staff)
        resp = self.client.post(reverse('sso_orgs'), {
            'name': 'Acme 2', 'slug': 'acmecorp', 'domain': 'acme2.com',
        }, format='json')
        self.assertEqual(resp.status_code, 409)

    def test_get_org_not_found(self):
        self._auth(self.staff)
        resp = self.client.get(reverse('sso_org', kwargs={'slug': 'nobody'}))
        self.assertEqual(resp.status_code, 404)

    def test_get_org_includes_config(self):
        org = _make_org()
        _make_saml_config(org)
        self._auth(self.staff)
        resp = self.client.get(reverse('sso_org', kwargs={'slug': 'acmecorp'}))
        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(resp.data['config'])
        self.assertEqual(resp.data['config']['protocol'], 'saml')

    def test_get_org_config_null_when_not_configured(self):
        _make_org()
        self._auth(self.staff)
        resp = self.client.get(reverse('sso_org', kwargs={'slug': 'acmecorp'}))
        self.assertIsNone(resp.data['config'])

    def test_update_org_sso_enforced(self):
        _make_org(enforced=False)
        self._auth(self.staff)
        resp = self.client.patch(reverse('sso_org', kwargs={'slug': 'acmecorp'}),
                                 {'sso_enforced': True}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(Organization.objects.get(slug='acmecorp').sso_enforced)

    def test_upsert_saml_config(self):
        _make_org()
        self._auth(self.staff)
        payload = {
            'protocol': 'saml',
            'is_active': True,
            'saml_entity_id': 'https://okta.acmecorp.com',
            'saml_sso_url': 'https://okta.acmecorp.com/sso',
            'saml_x509_cert': 'MIID...',
        }
        resp = self.client.put(reverse('sso_org_config', kwargs={'slug': 'acmecorp'}),
                               payload, format='json')
        self.assertEqual(resp.status_code, 200)
        cfg = SSOConfig.objects.get(org__slug='acmecorp')
        self.assertEqual(cfg.protocol, 'saml')
        self.assertEqual(cfg.saml_entity_id, 'https://okta.acmecorp.com')

    def test_upsert_oidc_config(self):
        _make_org()
        self._auth(self.staff)
        payload = {
            'protocol': 'oidc',
            'is_active': True,
            'oidc_client_id': 'cid',
            'oidc_client_secret': 'csec',
            'oidc_discovery_url': 'https://idp.com/.well-known/openid-configuration',
        }
        resp = self.client.put(reverse('sso_org_config', kwargs={'slug': 'acmecorp'}),
                               payload, format='json')
        self.assertEqual(resp.status_code, 200)
        cfg = SSOConfig.objects.get(org__slug='acmecorp')
        self.assertEqual(cfg.protocol, 'oidc')
        self.assertEqual(cfg.oidc_client_id, 'cid')

    def test_patch_config_partial_update(self):
        org = _make_org()
        _make_saml_config(org)
        self._auth(self.staff)
        resp = self.client.patch(reverse('sso_org_config', kwargs={'slug': 'acmecorp'}),
                                 {'is_active': False}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(SSOConfig.objects.get(org__slug='acmecorp').is_active)

    def test_delete_org(self):
        _make_org()
        self._auth(self.staff)
        resp = self.client.delete(reverse('sso_org', kwargs={'slug': 'acmecorp'}))
        self.assertEqual(resp.status_code, 204)
        self.assertFalse(Organization.objects.filter(slug='acmecorp').exists())

    def test_delete_cascades_config(self):
        org = _make_org()
        _make_saml_config(org)
        self._auth(self.staff)
        self.client.delete(reverse('sso_org', kwargs={'slug': 'acmecorp'}))
        self.assertFalse(SSOConfig.objects.filter(org__slug='acmecorp').exists())
