"""Tests for the stapel-core upgrade changes.

Covers: SAML audience / InResponseTo / assertion-replay validation, OTP and
TOTP lockout throttling, QR device binding (nonce cookie) and
allow_unauthenticated_scanner, composable URL factories, GDPR lazy model
resolution, auth_settings routing for mock OTP flags, and user.registered
signal + comm emit.
"""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from stapel_auth.models import Organization, SSOConfig
from stapel_auth.sso_service import SAMLService

User = get_user_model()

FRONTEND = 'https://app.example.com'
_OVERRIDE = {'FRONTEND_URL': FRONTEND, 'BACKEND_URL': FRONTEND}

_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol'
_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'


def _create_tokens(user):
    from stapel_core.django.jwt.provider import jwt_provider

    return jwt_provider.create_tokens(user)


def _saml_instant(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def _build_saml_response(
    *,
    assertion_id='_assertion_1',
    in_response_to=None,
    audience=None,
    not_on_or_after=None,
    email='alice@acmecorp.com',
):
    now = datetime.now(dt_timezone.utc)
    not_before = _saml_instant(now - timedelta(minutes=5))
    not_after = _saml_instant(not_on_or_after or (now + timedelta(minutes=5)))
    irt_resp = f' InResponseTo="{in_response_to}"' if in_response_to else ''
    scd_irt = f' InResponseTo="{in_response_to}"' if in_response_to else ''
    audience_xml = (
        f'<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>'
        f'</saml:AudienceRestriction>'
        if audience
        else ''
    )
    xml = (
        f'<samlp:Response xmlns:samlp="{_SAMLP}" xmlns:saml="{_SAML}"'
        f' ID="_resp_{uuid.uuid4().hex}" Version="2.0"{irt_resp}>'
        f'<saml:Assertion ID="{assertion_id}" Version="2.0">'
        f'<saml:Subject>'
        f'<saml:NameID>{email}</saml:NameID>'
        f'<saml:SubjectConfirmation>'
        f'<saml:SubjectConfirmationData{scd_irt} NotOnOrAfter="{not_after}"/>'
        f'</saml:SubjectConfirmation>'
        f'</saml:Subject>'
        f'<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}">'
        f'{audience_xml}'
        f'</saml:Conditions>'
        f'<saml:AttributeStatement>'
        f'<saml:Attribute Name="email">'
        f'<saml:AttributeValue>{email}</saml:AttributeValue>'
        f'</saml:Attribute>'
        f'</saml:AttributeStatement>'
        f'</saml:Assertion>'
        f'</samlp:Response>'
    )
    return base64.b64encode(xml.encode()).decode()


def _fake_verifier_patch():
    """Patch signxml so parse_response 'verifies' and hands back the real XML."""
    p = patch('signxml.XMLVerifier')
    mock = p.start()
    mock.return_value.verify.side_effect = lambda root, **kw: SimpleNamespace(
        signed_xml=root
    )
    return p


# =============================================================================
# 1. SAML: AudienceRestriction / InResponseTo / assertion replay
# =============================================================================


@override_settings(**_OVERRIDE)
class SAMLSecurityValidationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.org = Organization.objects.create(
            name='Acme', slug='acmecorp', domain='acmecorp.com'
        )
        self.cfg = SSOConfig.objects.create(
            org=self.org,
            protocol=SSOConfig.PROTOCOL_SAML,
            saml_entity_id='https://idp.acmecorp.com',
            saml_sso_url='https://idp.acmecorp.com/sso',
            saml_x509_cert='MIID...',
        )
        self.entity_id = SAMLService.sp_entity_id('acmecorp')
        self._verifier = _fake_verifier_patch()
        self.addCleanup(self._verifier.stop)

    def _store_request_id(self, request_id):
        cache.set(f'saml_req:acmecorp:{request_id}', '1', 600)

    def test_valid_response_with_audience_and_in_response_to(self):
        req_id = f'_{uuid.uuid4().hex}'
        self._store_request_id(req_id)
        b64 = _build_saml_response(in_response_to=req_id, audience=self.entity_id)
        attrs = SAMLService.parse_response(self.cfg, b64, org_slug='acmecorp')
        self.assertEqual(attrs['email'], 'alice@acmecorp.com')
        # The request id is consumed — single use.
        self.assertIsNone(cache.get(f'saml_req:acmecorp:{req_id}'))

    def test_wrong_audience_rejected(self):
        req_id = f'_{uuid.uuid4().hex}'
        self._store_request_id(req_id)
        b64 = _build_saml_response(
            in_response_to=req_id, audience='https://some-other-sp.example.com/'
        )
        with self.assertRaisesRegex(ValueError, 'audience'):
            SAMLService.parse_response(self.cfg, b64, org_slug='acmecorp')

    def test_unknown_in_response_to_rejected(self):
        b64 = _build_saml_response(
            in_response_to='_never_issued', audience=self.entity_id
        )
        with self.assertRaisesRegex(ValueError, 'InResponseTo'):
            SAMLService.parse_response(self.cfg, b64, org_slug='acmecorp')

    def test_in_response_to_single_use(self):
        req_id = f'_{uuid.uuid4().hex}'
        self._store_request_id(req_id)
        b64 = _build_saml_response(
            assertion_id='_a_first', in_response_to=req_id, audience=self.entity_id
        )
        SAMLService.parse_response(self.cfg, b64, org_slug='acmecorp')
        # Same request id again (fresh assertion id): the id was consumed.
        b64_second = _build_saml_response(
            assertion_id='_a_second', in_response_to=req_id, audience=self.entity_id
        )
        with self.assertRaisesRegex(ValueError, 'InResponseTo'):
            SAMLService.parse_response(self.cfg, b64_second, org_slug='acmecorp')

    def test_assertion_replay_rejected(self):
        req_id = f'_{uuid.uuid4().hex}'
        self._store_request_id(req_id)
        b64 = _build_saml_response(
            assertion_id='_replayed', in_response_to=req_id, audience=self.entity_id
        )
        SAMLService.parse_response(self.cfg, b64, org_slug='acmecorp')
        # Re-arm the request id: replay must be caught by the assertion ID cache.
        self._store_request_id(req_id)
        with self.assertRaisesRegex(ValueError, 'replay'):
            SAMLService.parse_response(self.cfg, b64, org_slug='acmecorp')

    def test_unsolicited_response_without_in_response_to_allowed(self):
        b64 = _build_saml_response(audience=self.entity_id)
        attrs = SAMLService.parse_response(self.cfg, b64, org_slug='acmecorp')
        self.assertEqual(attrs['email'], 'alice@acmecorp.com')

    def test_missing_audience_restriction_allowed(self):
        b64 = _build_saml_response()
        attrs = SAMLService.parse_response(self.cfg, b64, org_slug='acmecorp')
        self.assertEqual(attrs['email'], 'alice@acmecorp.com')


# =============================================================================
# 2. OTP / TOTP throttling (LockoutService)
# =============================================================================


class EmailOtpLockoutTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.email = f'lockout_{uuid.uuid4().hex[:8]}@example.com'
        resp = self.client.post(reverse('email_request'), {'email': self.email})
        self.assertEqual(resp.status_code, 200)

    def _verify(self, code):
        return self.client.post(
            reverse('email_verify'), {'email': self.email, 'code': code}
        )

    def test_five_failed_codes_lock_the_identifier(self):
        for i in range(4):
            resp = self._verify('9999')
            self.assertEqual(resp.status_code, 400, i)
        resp = self._verify('9999')
        self.assertEqual(resp.status_code, 423)
        self.assertEqual(
            resp.data['localizable_error'], 'error.423.account_locked'
        )
        # Even the correct code is rejected while locked.
        resp = self._verify('0000')
        self.assertEqual(resp.status_code, 423)

    def test_successful_verify_clears_lockout_counter(self):
        from stapel_auth.security.services import LockoutService

        self._verify('9999')
        resp = self._verify('0000')
        self.assertEqual(resp.status_code, 200)
        is_locked, _ = LockoutService.check(self.email)
        self.assertFalse(is_locked)
        attempts_key, _ = LockoutService._keys(self.email)
        self.assertIsNone(cache.get(attempts_key))


class PhoneOtpLockoutTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.phone = '+12025550001'
        resp = self.client.post(reverse('phone_request'), {'phone': self.phone})
        self.assertEqual(resp.status_code, 200)

    def test_locked_identifier_returns_423(self):
        from stapel_auth.security.services import LockoutService

        for _ in range(4):
            LockoutService.record_failure(self.phone)
        resp = self.client.post(
            reverse('phone_verify'), {'phone': self.phone, 'code': '9999'}
        )
        self.assertEqual(resp.status_code, 423)
        # And stays locked for the correct code.
        resp = self.client.post(
            reverse('phone_verify'), {'phone': self.phone, 'code': '0000'}
        )
        self.assertEqual(resp.status_code, 423)


class TOTPChallengeLockoutTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            username=f'totp_{uuid.uuid4().hex[:8]}', password='pass'
        )
        from stapel_auth.mfa.services import TOTPService

        import pyotp

        setup = TOTPService.setup(self.user)
        self.secret = setup['secret']
        TOTPService.confirm(self.user, pyotp.TOTP(self.secret).now())

    def _wrong_code(self):
        import pyotp

        good = pyotp.TOTP(self.secret).now()
        return str((int(good) + 1) % 1000000).zfill(6)

    def test_challenge_verify_locks_after_failures(self):
        from stapel_auth.mfa.services import TOTPService

        token = TOTPService.create_challenge(str(self.user.id))
        for i in range(4):
            resp = self.client.post(
                reverse('totp_challenge_verify'),
                {'challenge_token': token, 'code': self._wrong_code()},
            )
            self.assertEqual(resp.status_code, 400, i)
        resp = self.client.post(
            reverse('totp_challenge_verify'),
            {'challenge_token': token, 'code': self._wrong_code()},
        )
        self.assertEqual(resp.status_code, 423)
        # Challenge was burned by the service after 5 failures.
        self.assertIsNone(cache.get(f'totp_challenge:{token}'))

    def test_resolve_challenge_invalidates_after_five_failures(self):
        import pyotp

        from stapel_auth.mfa.services import TOTPService

        token = TOTPService.create_challenge(str(self.user.id))
        for _ in range(5):
            self.assertIsNone(
                TOTPService.resolve_challenge(token, code=self._wrong_code())
            )
        self.assertIsNone(cache.get(f'totp_challenge:{token}'))
        # Even the correct code no longer works: the challenge is gone.
        good = pyotp.TOTP(self.secret).now()
        self.assertIsNone(TOTPService.resolve_challenge(token, code=good))

    def test_resolve_challenge_success_before_limit(self):
        import pyotp

        from stapel_auth.mfa.services import TOTPService

        token = TOTPService.create_challenge(str(self.user.id))
        TOTPService.resolve_challenge(token, code=self._wrong_code())
        user = TOTPService.resolve_challenge(
            token, code=pyotp.TOTP(self.secret).now()
        )
        self.assertEqual(user, self.user)


# =============================================================================
# 3. QR device binding
# =============================================================================


@override_settings(URL_PREFIX='')
class QRDeviceBindingTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def test_generate_sets_httponly_nonce_cookie(self):
        resp = self.client.post(reverse('qr_generate'), {'type': 'login_request'})
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        key = resp.data['key']
        cookie = resp.cookies.get(f'stapel_qr_{key}')
        self.assertIsNotNone(cookie)
        self.assertTrue(cookie['httponly'])

    def test_status_polling_requires_nonce_cookie(self):
        resp = self.client.post(reverse('qr_generate'), {'type': 'login_request'})
        key = resp.data['key']

        # Generating device (has the cookie) can poll.
        ok = self.client.get(reverse('qr_status', kwargs={'key': key}))
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.data['status'], 'pending')

        # A different device (no cookie) cannot.
        stranger = APIClient()
        denied = stranger.get(reverse('qr_status', kwargs={'key': key}))
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(
            denied.data['localizable_error'], 'error.403.qr_device_mismatch'
        )

    def test_tokens_only_claimable_by_generating_device(self):
        resp = self.client.post(reverse('qr_generate'), {'type': 'login_request'})
        key = resp.data['key']

        approver = User.objects.create_user(
            username=f'approver_{uuid.uuid4().hex[:6]}', password='pass'
        )
        access, _ = _create_tokens(approver)
        scanner = APIClient()
        scanner.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        confirm = scanner.post(reverse('qr_confirm', kwargs={'key': key}))
        self.assertEqual(confirm.status_code, 200)

        # Attacker who stole the key from the QR image cannot claim tokens.
        attacker = APIClient()
        denied = attacker.get(reverse('qr_status', kwargs={'key': key}))
        self.assertEqual(denied.status_code, 403)

        # The generating device claims them.
        claimed = self.client.get(reverse('qr_status', kwargs={'key': key}))
        self.assertEqual(claimed.status_code, 200)
        self.assertEqual(claimed.data['status'], 'fulfilled')
        self.assertIsNotNone(claimed.data['access_token'])

    def test_session_share_status_not_nonce_gated(self):
        owner = User.objects.create_user(
            username=f'owner_{uuid.uuid4().hex[:6]}', password='pass'
        )
        access, _ = _create_tokens(owner)
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        resp = c.post(reverse('qr_generate'), {'type': 'session_share'})
        key = resp.data['key']
        stranger = APIClient()
        ok = stranger.get(reverse('qr_status', kwargs={'key': key}))
        self.assertEqual(ok.status_code, 200)


# =============================================================================
# 4. Composable URL factories
# =============================================================================


# (route, name) snapshot of the pre-factory monolithic urls.py.
_EXPECTED_URLS = {
    'token_obtain_pair': 'token/',
    'token_refresh': 'token/refresh/',
    'email_request': 'email/request/',
    'email_verify': 'email/verify/',
    'phone_request': 'phone/request/',
    'phone_verify': 'phone/verify/',
    'oauth_login': 'oauth/login/',
    'oauth_authorize': 'oauth/<str:provider>/authorize/',
    'oauth_callback': 'oauth/<str:provider>/callback/',
    'oauth_callback_noslash': 'oauth/<str:provider>/callback',
    'anonymous': 'anonymous/',
    'me': 'me/',
    'logout': 'logout/',
    'verify_token': 'verify/',
    'phone_instant_request_old': 'phone/change/instant/request-old/',
    'phone_instant_verify_old': 'phone/change/instant/verify-old/',
    'phone_instant_request_new': 'phone/change/instant/request-new/',
    'phone_instant_verify_new': 'phone/change/instant/verify-new/',
    'email_instant_request_old': 'email/change/instant/request-old/',
    'email_instant_verify_old': 'email/change/instant/verify-old/',
    'email_instant_request_new': 'email/change/instant/request-new/',
    'email_instant_verify_new': 'email/change/instant/verify-new/',
    'phone_delayed_initiate': 'phone/change/delayed/initiate/',
    'phone_delayed_status': 'phone/change/delayed/status/',
    'phone_delayed_cancel': 'phone/change/delayed/cancel/',
    'email_delayed_initiate': 'email/change/delayed/initiate/',
    'email_delayed_status': 'email/change/delayed/status/',
    'email_delayed_cancel': 'email/change/delayed/cancel/',
    'password_login': 'password/login/',
    'password_methods': 'password/methods/',
    'password_change': 'password/change/',
    'password_change_otp_request': 'password/change/otp/request/',
    'password_change_otp_verify': 'password/change/otp/verify/',
    'password_reset_email_request': 'password/reset/email/request/',
    'password_reset_email_verify': 'password/reset/email/verify/',
    'password_reset_phone_request': 'password/reset/phone/request/',
    'password_reset_phone_verify': 'password/reset/phone/verify/',
    'password_register': 'password/register/',
    'qr_generate': 'qr/generate/',
    'qr_status': 'qr/<str:key>/status/',
    'qr_scan': 'qr/<str:key>/scan/',
    'qr_confirm': 'qr/<str:key>/confirm/',
    'qr_reject': 'qr/<str:key>/reject/',
    'sessions': 'sessions/',
    'session_revoke': 'sessions/<str:session_id>/',
    'session_confirm': 'sessions/<str:session_id>/confirm/',
    'security_status': 'security/status/',
    'security_audit': 'security/audit/',
    'revoke_suspicious': 'security/revoke-suspicious/',
    'totp_setup': 'totp/setup/',
    'totp_setup_confirm': 'totp/setup/confirm/',
    'totp_disable': 'totp/disable/',
    'totp_disable_otp_request': 'totp/disable-otp/request/',
    'totp_challenge_verify': 'totp/challenge/verify/',
    'totp_step_up': 'totp/step-up/',
    'magic_request': 'magic/request/',
    'magic_verify': 'magic/verify/',
    'passkey_list': 'passkey/',
    'passkey_register_begin': 'passkey/register/begin/',
    'passkey_register_complete': 'passkey/register/complete/',
    'passkey_auth_begin': 'passkey/authenticate/begin/',
    'passkey_auth_complete': 'passkey/authenticate/complete/',
    'passkey_destroy': 'passkey/<str:pk>/',
    'sso_lookup': 'sso/lookup/',
    'sso_login': 'sso/<slug:slug>/login/',
    'sso_saml_metadata': 'sso/<slug:slug>/saml/metadata/',
    'sso_saml_acs': 'sso/<slug:slug>/saml/acs/',
    'sso_oidc_callback': 'sso/<slug:slug>/oidc/callback/',
    'sso_orgs': 'sso/orgs/',
    'sso_org': 'sso/orgs/<slug:slug>/',
    'sso_org_config': 'sso/orgs/<slug:slug>/config/',
    'jwks': '.well-known/jwks.json',
    'openid-configuration': '.well-known/openid-configuration',
    'oauth2_introspect': 'oauth2/introspect/',
    'verification_preferences': 'verification/preferences/',
    'verification_info': 'verification/<str:challenge_id>/',
    'verification_initiate': 'verification/<str:challenge_id>/initiate/',
    'verification_complete': 'verification/<str:challenge_id>/complete/',
    'capabilities': 'capabilities/',
    'admin-users': 'admin-users/',
    'admin-audit': 'admin/audit/',
}


class URLFactoryEquivalenceTests(TestCase):
    def _collect(self, patterns):
        from django.urls import URLPattern

        found = {}
        for p in patterns:
            if isinstance(p, URLPattern) and p.name:
                found[p.name] = str(p.pattern)
        return found

    def test_assembled_urlpatterns_identical_to_monolith(self):
        from stapel_auth import urls as auth_urls

        actual = self._collect(auth_urls.urlpatterns)
        self.assertEqual(actual, _EXPECTED_URLS)

    def test_router_urls_still_included(self):
        # DefaultRouter include (service-keys) survives the split.
        self.assertEqual(reverse('service-keys-list'), '/service-keys')

    def test_factories_cover_expected_urls_exactly_once(self):
        from stapel_auth import urls as auth_urls

        combined = {}
        for factory in (
            auth_urls.get_sessions_urls,
            auth_urls.get_otp_urls,
            auth_urls.get_oauth_urls,
            auth_urls.get_admin_api_urls,
            auth_urls.get_password_urls,
            auth_urls.get_qr_urls,
            auth_urls.get_security_urls,
            auth_urls.get_mfa_urls,
            auth_urls.get_magic_link_urls,
            auth_urls.get_sso_urls,
            auth_urls.get_openid_urls,
            auth_urls.get_verification_urls,
        ):
            part = self._collect(factory(enabled=True))
            overlap = set(part) & set(combined)
            self.assertFalse(overlap, f'{factory.__name__} duplicates {overlap}')
            combined.update(part)
        self.assertEqual(combined, _EXPECTED_URLS)

    def test_factories_gated_by_feature_flags(self):
        from stapel_auth import urls as auth_urls

        # Password auth is disabled by default → factory yields nothing.
        with override_settings(STAPEL_AUTH={}):
            self.assertEqual(auth_urls.get_password_urls(), [])
            self.assertTrue(auth_urls.get_qr_urls())  # default True
        with override_settings(STAPEL_AUTH={'AUTH_PASSWORD_LOGIN': True}):
            self.assertTrue(auth_urls.get_password_urls())
        with override_settings(STAPEL_AUTH={'AUTH_QR_LOGIN': False}):
            self.assertEqual(auth_urls.get_qr_urls(), [])
        # Explicit argument overrides the flags.
        with override_settings(STAPEL_AUTH={}):
            self.assertTrue(auth_urls.get_password_urls(enabled=True))
            self.assertEqual(auth_urls.get_magic_link_urls(enabled=False), [])
        # Passkey paths drop out of mfa when the flag is off; TOTP stays.
        with override_settings(STAPEL_AUTH={'AUTH_PASSKEY_LOGIN': False}):
            names = set(self._collect(auth_urls.get_mfa_urls()))
            self.assertIn('totp_setup', names)
            self.assertNotIn('passkey_list', names)


# =============================================================================
# 5. GDPR lazy model resolution
# =============================================================================


class GDPRLazyModelTests(TestCase):
    def test_default_setting_points_at_stapel_gdpr(self):
        from stapel_auth.conf import auth_settings

        self.assertEqual(
            auth_settings.REREGISTRATION_MODEL,
            'stapel_gdpr.models.ReRegistrationHash',
        )

    def test_missing_model_degrades_to_warning(self):
        from stapel_auth.gdpr import AuthGDPRProvider

        user = User.objects.create_user(
            username=f'gdpr_{uuid.uuid4().hex[:6]}',
            email='gdpr-lazy@example.com',
            password='x',
        )
        with override_settings(
            STAPEL_AUTH={'REREGISTRATION_MODEL': 'nonexistent.module.Model'}
        ):
            with self.assertWarns(UserWarning):
                AuthGDPRProvider().delete(user.id)  # must not raise

    def test_default_model_stores_hashes(self):
        import hashlib

        from stapel_gdpr.models import ReRegistrationHash

        from stapel_auth.gdpr import AuthGDPRProvider

        email = f'{uuid.uuid4().hex[:8]}@example.com'
        user = User.objects.create_user(
            username=f'gdpr2_{uuid.uuid4().hex[:6]}', email=email, password='x'
        )
        AuthGDPRProvider().delete(user.id)
        h = hashlib.sha256(email.lower().encode()).hexdigest()
        self.assertTrue(
            ReRegistrationHash.objects.filter(hash_value=h).exists()
        )


# =============================================================================
# 6. auth_settings routing for mock OTP flags
# =============================================================================


class MockOtpSettingsRoutingTests(TestCase):
    def test_stapel_auth_dict_overrides_flat_setting(self):
        from stapel_auth.otp.services import (
            EmailVerificationService,
            PhoneVerificationService,
        )

        # Flat settings in conftest say True; the STAPEL_AUTH dict must win.
        with override_settings(
            STAPEL_AUTH={'USE_MOCK_SMS_OTP': False, 'USE_MOCK_EMAIL_OTP': False}
        ):
            self.assertFalse(PhoneVerificationService().use_mock_otp)
            self.assertFalse(EmailVerificationService().use_mock_otp)

    def test_mock_code_via_stapel_auth(self):
        from stapel_auth.otp.services import EmailVerificationService

        with override_settings(STAPEL_AUTH={'MOCK_OTP_CODE': '4242'}):
            self.assertEqual(EmailVerificationService().generate_code(), '4242')

    def test_check_mock_admin_reads_auth_settings(self):
        from stapel_core.django.api.errors import StapelServiceError

        from stapel_auth.password.services import PasswordService

        admin = User.objects.create_user(
            username=f'adm_{uuid.uuid4().hex[:6]}',
            password='x',
            is_staff=True,
        )
        with self.assertRaises(StapelServiceError):
            PasswordService._check_mock_admin(admin)  # mock is on in tests
        with override_settings(
            STAPEL_AUTH={'USE_MOCK_SMS_OTP': False, 'USE_MOCK_EMAIL_OTP': False}
        ):
            PasswordService._check_mock_admin(admin)  # no raise


# =============================================================================
# 7. user.registered — signal + comm emit + schema
# =============================================================================


class UserRegisteredEventTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def test_email_registration_sends_signal_and_emit(self):
        from stapel_core.signals import user_registered

        received = []

        def receiver(sender, **kwargs):
            received.append(kwargs)

        user_registered.connect(receiver)
        self.addCleanup(user_registered.disconnect, receiver)

        email = f'reg_{uuid.uuid4().hex[:8]}@example.com'
        self.client.post(reverse('email_request'), {'email': email})
        with patch('stapel_core.comm.emit') as m_emit:
            resp = self.client.post(
                reverse('email_verify'), {'email': email, 'code': '0000'}
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['status'], 'REGISTERED')

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]['user'].email, email)

        m_emit.assert_called_once()
        args, kwargs = m_emit.call_args
        self.assertEqual(args[0], 'user.registered')
        payload = args[1]
        self.assertIsInstance(payload['user_id'], str)
        self.assertEqual(payload['email'], email)
        self.assertEqual(payload['auth_type'], 'email')

    @override_settings(URL_PREFIX='', STAPEL_AUTH={'AUTH_PASSWORD_REGISTRATION': True})
    def test_password_registration_sends_signal_and_emit(self):
        from stapel_core.signals import user_registered

        received = []

        def receiver(sender, **kwargs):
            received.append(kwargs)

        user_registered.connect(receiver)
        self.addCleanup(user_registered.disconnect, receiver)

        email = f'pwreg_{uuid.uuid4().hex[:8]}@example.com'
        with patch('stapel_core.comm.emit') as m_emit:
            resp = self.client.post(
                reverse('password_register'),
                {'email': email, 'password': 'S3cure!passw0rd'},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(received), 1)
        m_emit.assert_called_once()
        self.assertEqual(m_emit.call_args[0][0], 'user.registered')

    def test_registration_survives_emit_failure(self):
        email = f'boom_{uuid.uuid4().hex[:8]}@example.com'
        self.client.post(reverse('email_request'), {'email': email})
        with patch('stapel_core.comm.emit', side_effect=RuntimeError('broker down')):
            resp = self.client.post(
                reverse('email_verify'), {'email': email, 'code': '0000'}
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['status'], 'REGISTERED')


class EmitSchemaTests(TestCase):
    SCHEMAS_DIR = Path(__file__).resolve().parent.parent / 'schemas' / 'emits'

    def _load(self, name):
        return json.loads((self.SCHEMAS_DIR / name).read_text())

    def test_user_registered_schema_matches_real_payload(self):
        import jsonschema

        schema = self._load('user.registered.json')
        payload = {
            'user_id': str(uuid.uuid4()),
            'auth_type': 'email',
            'email': 'x@example.com',
        }
        jsonschema.validate(payload, schema)  # must not raise
        jsonschema.validate(
            {'user_id': str(uuid.uuid4()), 'auth_type': 'oauth', 'email': None},
            schema,
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(
                {'user_id': 123, 'auth_type': 'email', 'email': None}, schema
            )

    def test_session_schemas_use_string_user_id(self):
        for name in ('user.session_created.json', 'user.session_revoked.json'):
            schema = self._load(name)
            self.assertEqual(
                schema['properties']['user_id']['type'], 'string', name
            )
