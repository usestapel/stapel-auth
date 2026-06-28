"""
Unit tests for service-layer logic: _parse_ua, SecurityService, Phone/Email verification
error branches. No network calls — uses SQLite in-memory DB from conftest.py.
"""
import uuid
from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase
from django.utils import timezone


# ---------------------------------------------------------------------------
# _parse_ua — pure function, zero I/O
# ---------------------------------------------------------------------------

class ParseUATests(TestCase):
    def _ua(self, ua, **kw):
        from stapel_auth.services import _parse_ua
        return _parse_ua(ua, **kw)

    def test_empty_string(self):
        r = self._ua('')
        self.assertEqual(r['type'], 'unknown')
        self.assertEqual(r['name'], 'Unknown device')

    def test_none_treated_as_empty(self):
        from stapel_auth.services import _parse_ua
        r = _parse_ua(None)  # type: ignore[arg-type]
        self.assertEqual(r['type'], 'unknown')

    def test_python_requests_client(self):
        r = self._ua('python-requests/2.31.0')
        self.assertEqual(r['type'], 'api')

    def test_urllib_client(self):
        r = self._ua('Python-urllib/3.11')
        self.assertEqual(r['type'], 'api')

    def test_okhttp_android_app(self):
        r = self._ua('okhttp/4.11.0')
        self.assertEqual(r['type'], 'phone')
        self.assertEqual(r['name'], 'Android app')

    def test_cfnetwork_ios_app(self):
        r = self._ua('MyApp/1.0 CFNetwork/1408.0.4 Darwin/22.5.0')
        self.assertEqual(r['type'], 'phone')
        self.assertEqual(r['name'], 'iOS app')

    def test_darwin_without_mozilla_is_ios(self):
        r = self._ua('SomeApp/2.0 Darwin/21.6.0')
        self.assertEqual(r['name'], 'iOS app')

    # iPhone
    def test_iphone_with_safari(self):
        ua = ('Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) '
              'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1')
        r = self._ua(ua)
        self.assertEqual(r['type'], 'phone')
        self.assertIn('iPhone', r['name'])
        self.assertEqual(r['details'], 'iOS 16.5')

    def test_iphone_no_browser(self):
        ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15'
        r = self._ua(ua)
        self.assertEqual(r['name'], 'iPhone')

    # iPad
    def test_ipad_safari(self):
        ua = ('Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 '
              '(KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1')
        r = self._ua(ua)
        self.assertEqual(r['type'], 'tablet')
        self.assertIn('iPad', r['name'])
        self.assertEqual(r['details'], 'iPadOS 15.0')

    # Android
    def test_android_chrome_phone(self):
        ua = ('Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36')
        r = self._ua(ua)
        self.assertEqual(r['type'], 'phone')
        self.assertIn('Android', r['name'])
        self.assertIn('Chrome', r['name'])

    def test_android_tablet_no_mobile_token(self):
        ua = ('Mozilla/5.0 (Linux; Android 12; Nexus 7 Build/SQ3A) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36')
        r = self._ua(ua)
        self.assertEqual(r['type'], 'tablet')

    def test_android_client_hints_preferred(self):
        # Frozen UA (model=K) but Client Hints provide real model
        ua = ('Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36')
        r = self._ua(ua, ch_platform='Android', ch_model='Pixel 7', ch_version='114.0.5735.50')
        self.assertEqual(r['type'], 'phone')
        self.assertEqual(r['details'], 'Pixel 7')

    def test_android_client_hints_platform_only(self):
        ua = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Mobile Safari/537.36'
        r = self._ua(ua, ch_platform='Android', ch_version='13.0.0')
        self.assertEqual(r['type'], 'phone')

    # Mac
    def test_mac_safari(self):
        ua = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
              '(KHTML, like Gecko) Version/16.4 Safari/605.1.15')
        r = self._ua(ua)
        self.assertEqual(r['type'], 'desktop')
        self.assertIn('Mac', r['name'])
        self.assertIn('Safari', r['name'])
        self.assertIn('macOS', r['details'])
        self.assertIn('10.15', r['details'])

    def test_mac_chrome(self):
        ua = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/114.0.5735.133 Safari/537.36')
        r = self._ua(ua)
        self.assertIn('Chrome', r['name'])
        self.assertIn('Mac', r['name'])

    # Windows
    def test_windows_10_chrome(self):
        ua = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36')
        r = self._ua(ua)
        self.assertEqual(r['type'], 'desktop')
        self.assertIn('Windows', r['name'])
        self.assertIn('10/11', r['details'])

    def test_windows_edge(self):
        ua = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51')
        r = self._ua(ua)
        self.assertIn('Edge', r['name'])

    def test_windows_firefox(self):
        ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:109.0) Gecko/20100101 Firefox/109.0'
        r = self._ua(ua)
        self.assertIn('Firefox', r['name'])
        self.assertIn('7', r['details'])

    def test_windows_opera(self):
        ua = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 OPR/98.0.0.0')
        r = self._ua(ua)
        self.assertIn('Opera', r['name'])

    # Linux
    def test_linux_firefox(self):
        ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0'
        r = self._ua(ua)
        self.assertEqual(r['type'], 'desktop')
        self.assertIn('Linux', r['name'])
        self.assertIn('Firefox', r['name'])

    # Fallback
    def test_unknown_ua_fallback(self):
        r = self._ua('SomeObscureBrowser/1.0.0 (WidgetOS; x64)')
        self.assertEqual(r['type'], 'desktop')

    def test_parse_device_name_returns_name_field(self):
        from stapel_auth.services import _parse_device_name
        name = _parse_device_name(
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
            'AppleWebKit/537.36 Chrome/114.0.0.0 Safari/537.36'
        )
        self.assertIn('Mac', name)


# ---------------------------------------------------------------------------
# SecurityService
# ---------------------------------------------------------------------------

class SecurityServiceCheckLoginAttemptsTests(TestCase):
    def test_below_threshold_returns_false(self):
        from stapel_auth.services import SecurityService
        from stapel_auth.models import LoginAttempt
        ident = f'test_{uuid.uuid4().hex}@example.com'
        LoginAttempt.objects.create(identifier=ident, attempt_type='failed', ip_address='1.2.3.4')
        self.assertFalse(SecurityService.check_login_attempts(ident))

    def test_at_threshold_returns_true(self):
        from stapel_auth.services import SecurityService
        from stapel_auth.models import LoginAttempt
        ident = f'threshold_{uuid.uuid4().hex}@example.com'
        for _ in range(5):
            LoginAttempt.objects.create(identifier=ident, attempt_type='failed', ip_address='1.2.3.4')
        self.assertTrue(SecurityService.check_login_attempts(ident))

    def test_old_attempts_not_counted(self):
        from stapel_auth.services import SecurityService
        from stapel_auth.models import LoginAttempt
        ident = f'old_{uuid.uuid4().hex}@example.com'
        old = timezone.now() - timedelta(hours=1)
        for _ in range(10):
            a = LoginAttempt.objects.create(identifier=ident, attempt_type='failed', ip_address='1.2.3.4')
            LoginAttempt.objects.filter(pk=a.pk).update(created_at=old)
        self.assertFalse(SecurityService.check_login_attempts(ident))

    def test_successful_attempts_not_counted(self):
        from stapel_auth.services import SecurityService
        from stapel_auth.models import LoginAttempt
        ident = f'success_{uuid.uuid4().hex}@example.com'
        for _ in range(10):
            LoginAttempt.objects.create(identifier=ident, attempt_type='success', ip_address='1.2.3.4')
        self.assertFalse(SecurityService.check_login_attempts(ident))


class SecurityServiceCleanupTests(TestCase):
    def test_cleanup_expired_verifications_deletes_expired(self):
        from stapel_auth.services import SecurityService
        from stapel_auth.models import PhoneVerification
        past = timezone.now() - timedelta(hours=1)
        v = PhoneVerification.objects.create(
            phone='+10000000001',
            code='1234',
            expires_at=past,
        )
        count = SecurityService.cleanup_expired_verifications()
        self.assertGreaterEqual(count, 1)
        self.assertFalse(PhoneVerification.objects.filter(pk=v.pk).exists())

    def test_cleanup_expired_verifications_keeps_active(self):
        from stapel_auth.services import SecurityService
        from stapel_auth.models import PhoneVerification
        future = timezone.now() + timedelta(hours=1)
        v = PhoneVerification.objects.create(
            phone='+10000000002',
            code='5678',
            expires_at=future,
        )
        SecurityService.cleanup_expired_verifications()
        self.assertTrue(PhoneVerification.objects.filter(pk=v.pk).exists())

    def test_cleanup_expired_verifications_keeps_verified(self):
        from stapel_auth.services import SecurityService
        from stapel_auth.models import PhoneVerification
        past = timezone.now() - timedelta(hours=1)
        v = PhoneVerification.objects.create(
            phone='+10000000003',
            code='0000',
            expires_at=past,
            is_verified=True,
        )
        SecurityService.cleanup_expired_verifications()
        self.assertTrue(PhoneVerification.objects.filter(pk=v.pk).exists())


# ---------------------------------------------------------------------------
# PhoneVerificationService — error branches
# ---------------------------------------------------------------------------

class PhoneVerificationSendErrorTests(TestCase):
    def setUp(self):
        from stapel_auth.services import PhoneVerificationService
        self.svc = PhoneVerificationService()

    def test_device_rate_limit_returns_error(self):
        from stapel_auth.models import PhoneVerification
        device = uuid.uuid4().hex
        PhoneVerification.objects.create(
            phone='+19990000001',
            code='0000',
            device_id=device,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        result = self.svc.send_verification_code('+19990000099', device_id=device)
        self.assertEqual(result.get('error'), 'rate_limit')

    def test_blocked_phone_returns_blocked(self):
        from stapel_auth.models import PhoneVerification
        phone = '+19990000002'
        v = PhoneVerification.objects.create(
            phone=phone,
            code='0000',
            expires_at=timezone.now() + timedelta(minutes=10),
            blocked_until=timezone.now() + timedelta(minutes=10),
        )
        # Push created_at outside the 30s rate-limit window so blocked check is reached
        PhoneVerification.objects.filter(pk=v.pk).update(created_at=timezone.now() - timedelta(minutes=2))
        result = self.svc.send_verification_code(phone)
        self.assertEqual(result.get('error'), 'blocked')

    def test_notification_failure_returns_none(self):
        self.svc.use_mock_otp = False
        with patch('stapel_core.notifications.request_notification', return_value=False):
            result = self.svc.send_verification_code('+19990000003')
        self.assertIsNone(result)

    def test_exception_returns_none(self):
        with patch(
            'stapel_auth.models.PhoneVerification.objects.filter',
            side_effect=Exception('db error'),
        ):
            result = self.svc.send_verification_code('+19990000004')
        self.assertIsNone(result)


class PhoneVerificationVerifyErrorTests(TestCase):
    def setUp(self):
        from stapel_auth.services import PhoneVerificationService
        self.svc = PhoneVerificationService()

    def test_expired_retry_allowed(self):
        from stapel_auth.models import PhoneVerification
        phone = '+19990000010'
        # expired more than 5 minutes ago
        PhoneVerification.objects.create(
            phone=phone,
            code='1234',
            expires_at=timezone.now() - timedelta(minutes=10),
        )
        result = self.svc.verify_code(phone, '1234')
        self.assertEqual(result.get('error'), 'expired_retry_allowed')

    def test_exception_returns_server_error(self):
        with patch(
            'stapel_auth.models.PhoneVerification.objects.filter',
            side_effect=Exception('boom'),
        ):
            result = self.svc.verify_code('+19990000011', '0000')
        self.assertEqual(result.get('error'), 'server_error')


# ---------------------------------------------------------------------------
# EmailVerificationService — error branches
# ---------------------------------------------------------------------------

class EmailVerificationSendErrorTests(TestCase):
    def setUp(self):
        from stapel_auth.services import EmailVerificationService
        self.svc = EmailVerificationService()

    def test_device_rate_limit_returns_error(self):
        from stapel_auth.models import EmailVerification
        device = uuid.uuid4().hex
        EmailVerification.objects.create(
            email='ratetest@example.com',
            code='0000',
            device_id=device,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        result = self.svc.send_verification_code('other@example.com', device_id=device)
        self.assertEqual(result.get('error'), 'rate_limit')

    def test_blocked_email_returns_blocked(self):
        from stapel_auth.models import EmailVerification
        email = 'blocked@example.com'
        v = EmailVerification.objects.create(
            email=email,
            code='0000',
            expires_at=timezone.now() + timedelta(minutes=10),
            blocked_until=timezone.now() + timedelta(minutes=10),
        )
        # Push created_at outside the 30s rate-limit window so blocked check is reached
        EmailVerification.objects.filter(pk=v.pk).update(created_at=timezone.now() - timedelta(minutes=2))
        result = self.svc.send_verification_code(email)
        self.assertEqual(result.get('error'), 'blocked')

    def test_notification_failure_returns_none(self):
        self.svc.use_mock_otp = False
        with patch('stapel_core.notifications.request_notification', return_value=False):
            result = self.svc.send_verification_code('fail@example.com')
        self.assertIsNone(result)

    def test_exception_returns_none(self):
        with patch(
            'stapel_auth.models.EmailVerification.objects.filter',
            side_effect=Exception('db error'),
        ):
            result = self.svc.send_verification_code('exc@example.com')
        self.assertIsNone(result)


class EmailVerificationVerifyErrorTests(TestCase):
    def setUp(self):
        from stapel_auth.services import EmailVerificationService
        self.svc = EmailVerificationService()

    def test_expired_retry_allowed(self):
        from stapel_auth.models import EmailVerification
        email = 'expiredretry@example.com'
        EmailVerification.objects.create(
            email=email,
            code='1234',
            expires_at=timezone.now() - timedelta(minutes=10),
        )
        result = self.svc.verify_code(email, '1234')
        self.assertEqual(result.get('error'), 'expired_retry_allowed')

    def test_max_attempts_blocks(self):
        from stapel_auth.models import EmailVerification
        email = 'maxattempts@example.com'
        v = EmailVerification.objects.create(
            email=email,
            code='9999',
            expires_at=timezone.now() + timedelta(minutes=5),
            attempts=6,  # one more = 7, triggers block
        )
        result = self.svc.verify_code(email, '0000')
        self.assertEqual(result.get('error'), 'blocked')
        v.refresh_from_db()
        self.assertIsNotNone(v.blocked_until)

    def test_exception_returns_server_error(self):
        with patch(
            'stapel_auth.models.EmailVerification.objects.filter',
            side_effect=Exception('boom'),
        ):
            result = self.svc.verify_code('exc@example.com', '0000')
        self.assertEqual(result.get('error'), 'server_error')

    def test_no_verification_returns_invalid_code(self):
        from stapel_auth.services import EmailVerificationService
        svc = EmailVerificationService()
        result = svc.verify_code('norecord@example.com', '0000')
        self.assertEqual(result.get('error'), 'invalid_code')


# ---------------------------------------------------------------------------
# OAuthService — unsupported provider and exception branches
# ---------------------------------------------------------------------------

class OAuthServiceTests(TestCase):
    def setUp(self):
        from stapel_auth.services import OAuthService
        self.svc = OAuthService()

    def test_unsupported_provider_returns_none(self):
        result = self.svc.get_user_data('tiktok', 'fake_token')
        self.assertIsNone(result)

    def test_exception_returns_none(self):
        with patch('requests.get', side_effect=Exception('network error')):
            result = self.svc.get_user_data('google', 'fake_token')
        self.assertIsNone(result)

    def test_facebook_non_200_returns_none(self):
        mock_resp = type('R', (), {'status_code': 401})()
        with patch('requests.get', return_value=mock_resp):
            result = self.svc._get_facebook_user_data('bad_token')
        self.assertIsNone(result)

    def test_github_non_200_returns_none(self):
        mock_resp = type('R', (), {'status_code': 403})()
        with patch('requests.get', return_value=mock_resp):
            result = self.svc._get_github_user_data('bad_token')
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# TokenService — exception branches
# ---------------------------------------------------------------------------

class TokenServiceExceptionTests(TestCase):
    def test_verify_token_exception_returns_none(self):
        from stapel_auth.services import TokenService
        with patch(
            'stapel_core.django.jwt_provider.jwt_provider.validate_token',
            side_effect=Exception('decode failed'),
        ):
            result = TokenService.verify_token('bad.token.here')
        self.assertIsNone(result)

    def test_blacklist_token_exception_returns_false(self):
        from stapel_auth.services import TokenService
        with patch(
            'stapel_core.django.jwt_provider.jwt_provider.blacklist_token',
            side_effect=Exception('redis down'),
        ):
            result = TokenService.blacklist_token('any.token')
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# PasswordService — _raise_for_otp_result error branches
# ---------------------------------------------------------------------------

class PasswordServiceRaiseForOTPTests(TestCase):
    def _call(self, error):
        from stapel_auth.services import PasswordService
        from stapel_core.django.errors import IronServiceError
        with self.assertRaises(IronServiceError) as ctx:
            PasswordService._raise_for_otp_result({'error': error})
        return ctx.exception.http_status

    def test_no_verified_contact_raises_400(self):
        exc = self._call('no_verified_contact')
        self.assertEqual(exc, 400)

    def test_invalid_method_raises_400(self):
        exc = self._call('invalid_method')
        self.assertEqual(exc, 400)

    def test_user_not_found_raises_404(self):
        exc = self._call('user_not_found')
        self.assertEqual(exc, 404)

    def test_unknown_error_raises_500(self):
        exc = self._call('some_unknown_error_code')
        self.assertEqual(exc, 500)


class PasswordServiceResetVerifyUserNotFoundTests(TestCase):
    def _make_user(self, **kw):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        return User.objects.create_user(
            username=f'u_{uuid.uuid4().hex[:8]}',
            email=kw.get('email', f'{uuid.uuid4().hex}@example.com'),
            password='pass',
        )

    def test_reset_verify_email_user_not_found_raises(self):
        from stapel_auth.services import PasswordService
        from stapel_core.django.errors import IronServiceError
        with patch(
            'stapel_auth.services.EmailVerificationService.verify_code',
            return_value={'success': True},
        ):
            with self.assertRaises(IronServiceError) as ctx:
                PasswordService.reset_verify(
                    email='nobody@example.com',
                    code='0000',
                    new_password='newpass',
                )
        self.assertEqual(ctx.exception.http_status, 404)

    def test_reset_verify_phone_user_not_found_raises(self):
        from stapel_auth.services import PasswordService
        from stapel_core.django.errors import IronServiceError
        with patch(
            'stapel_auth.services.PhoneVerificationService.verify_code',
            return_value={'success': True},
        ):
            with self.assertRaises(IronServiceError) as ctx:
                PasswordService.reset_verify(
                    phone='+19990000099',
                    code='0000',
                    new_password='newpass',
                )
        self.assertEqual(ctx.exception.http_status, 404)
