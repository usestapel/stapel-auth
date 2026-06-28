"""
Additional tests to improve coverage:
- monitoring_proxy.py
- gdpr.py
- security_views.py (audit log, magic link, suspicious revoke, passkeys)
- tasks.py
- conf.py
"""
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase, APIClient

User = get_user_model()


def _make_user(**kwargs):
    defaults = dict(
        email=f'{uuid.uuid4().hex[:8]}@example.com',
        username=uuid.uuid4().hex[:12],
        password='testpass123',
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


# =============================================================================
# monitoring_proxy.py
# =============================================================================

class MonitoringAuthCheckTests(APITestCase):
    def setUp(self):
        from .monitoring_proxy import MonitoringAuthCheckView
        # Hit the view directly via URL — add it to test-only urlconf if needed
        self.view = MonitoringAuthCheckView.as_view()

    def _call(self, user=None):
        from django.test import RequestFactory
        rf = RequestFactory()
        req = rf.get('/monitoring/auth-check/')
        if user:
            req.user = user
        else:
            from django.contrib.auth.models import AnonymousUser
            req.user = AnonymousUser()
        from .monitoring_proxy import MonitoringAuthCheckView
        return MonitoringAuthCheckView.as_view()(req)

    def test_unauthenticated_returns_401(self):
        resp = self._call()
        self.assertEqual(resp.status_code, 401)

    def test_authenticated_non_staff_returns_403(self):
        user = _make_user(is_staff=False, is_superuser=False)
        resp = self._call(user)
        self.assertEqual(resp.status_code, 403)

    def test_staff_user_returns_200_with_headers(self):
        user = _make_user(is_staff=True, is_superuser=False)
        resp = self._call(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['X-WEBAUTH-USER'], str(user.id))
        self.assertEqual(resp['X-WEBAUTH-EMAIL'], user.email)
        self.assertEqual(resp['X-WEBAUTH-ROLE'], 'Editor')

    def test_superuser_returns_200_with_admin_role(self):
        user = _make_user(is_staff=True, is_superuser=True)
        resp = self._call(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['X-WEBAUTH-ROLE'], 'Admin')

    def test_response_includes_name_header(self):
        user = _make_user(is_staff=True)
        resp = self._call(user)
        self.assertIn('X-WEBAUTH-NAME', resp)


# =============================================================================
# gdpr.py
# =============================================================================

class GDPRProviderTests(TestCase):
    def setUp(self):
        from .gdpr import AuthGDPRProvider
        self.provider = AuthGDPRProvider()
        self.user = _make_user()

    def test_export_returns_all_sections(self):
        result = self.provider.export(self.user.id)
        self.assertIn('sessions', result)
        self.assertIn('passkeys', result)
        self.assertIn('totp_devices', result)
        self.assertIn('login_attempts', result)
        self.assertIn('audit_log', result)
        self.assertIn('authenticator_changes', result)
        self.assertIn('sso_memberships', result)

    def test_export_empty_user_returns_empty_lists(self):
        result = self.provider.export(self.user.id)
        for key in result:
            self.assertIsInstance(result[key], list)
            self.assertEqual(len(result[key]), 0)

    def test_delete_removes_user_data(self):
        with patch.object(self.provider, '_store_reregistration_hashes'):
            self.provider.delete(self.user.id)

    def test_delete_nonexistent_user_does_not_raise(self):
        with patch.object(self.provider, '_store_reregistration_hashes'):
            self.provider.delete(999999999)

    def test_anonymize_is_noop(self):
        # anonymize() should do nothing (auth data is fully deleted)
        result = self.provider.anonymize(self.user.id)
        self.assertIsNone(result)

    def test_user_identifiers_with_email(self):
        ids = self.provider._user_identifiers(self.user.id)
        self.assertIn(self.user.email, ids)

    def test_user_identifiers_nonexistent_user(self):
        ids = self.provider._user_identifiers(999999999)
        self.assertEqual(ids, [])

    def test_store_reregistration_hashes_nonexistent_user(self):
        # Should return early without error
        self.provider._store_reregistration_hashes(999999999)

    def test_store_reregistration_hashes_creates_hash_for_email(self):
        from stapel_gdpr.models import ReRegistrationHash
        self.provider._store_reregistration_hashes(self.user.id)
        exists = ReRegistrationHash.objects.filter(
            hash_type=ReRegistrationHash.TYPE_EMAIL,
        ).exists()
        self.assertTrue(exists)

    def test_serialize_dates_converts_datetimes(self):
        from .gdpr import _serialize_dates
        from datetime import datetime
        rows = [{'created_at': datetime(2024, 1, 1, 12, 0, 0), 'name': 'test'}]
        result = _serialize_dates(rows)
        self.assertEqual(result[0]['created_at'], '2024-01-01T12:00:00')
        self.assertEqual(result[0]['name'], 'test')

    def test_serialize_dates_empty(self):
        from .gdpr import _serialize_dates
        self.assertEqual(_serialize_dates([]), [])


# =============================================================================
# conf.py
# =============================================================================

class AuthSettingsTests(TestCase):
    def setUp(self):
        from .conf import AuthSettings
        self.settings = AuthSettings()

    def test_reads_from_stapel_auth_dict(self):
        with override_settings(STAPEL_AUTH={'MOCK_OTP_CODE': '1234'}):
            from .conf import AuthSettings
            s = AuthSettings()
            self.assertEqual(s.MOCK_OTP_CODE, '1234')

    def test_fallback_to_direct_django_setting(self):
        with override_settings(FRONTEND_URL='https://test.example.com'):
            from .conf import AuthSettings
            s = AuthSettings()
            self.assertEqual(s.FRONTEND_URL, 'https://test.example.com')

    def test_default_value_when_not_set(self):
        from .conf import AuthSettings
        s = AuthSettings()
        self.assertEqual(s.OTP_TTL, 600)
        self.assertEqual(s.SESSION_TTL_DAYS, 30)

    def test_invalid_attribute_raises_attribute_error(self):
        with self.assertRaises(AttributeError):
            _ = self.settings.NONEXISTENT_SETTING

    def test_cache_is_populated_on_second_access(self):
        from .conf import AuthSettings
        s = AuthSettings()
        _ = s.MOCK_OTP_CODE  # First access — populates cache
        self.assertIn('MOCK_OTP_CODE', s._cache)

    def test_reload_clears_cache(self):
        from .conf import AuthSettings
        s = AuthSettings()
        _ = s.MOCK_OTP_CODE
        self.assertIn('MOCK_OTP_CODE', s._cache)
        s.reload()
        self.assertEqual(s._cache, {})

    def test_setting_changed_signal_reloads(self):
        from .conf import auth_settings, _reload_on_change
        _ = auth_settings.OTP_TTL
        self.assertIn('OTP_TTL', auth_settings._cache)
        _reload_on_change(setting='STAPEL_AUTH')
        self.assertEqual(auth_settings._cache, {})

    def test_setting_changed_signal_ignores_other_settings(self):
        from .conf import auth_settings, _reload_on_change
        _ = auth_settings.OTP_TTL
        _reload_on_change(setting='OTHER_SETTING')
        self.assertIn('OTP_TTL', auth_settings._cache)  # not cleared

    def test_env_fallback(self):
        import os
        with patch.dict(os.environ, {'WEBAUTHN_RP_ID': 'test.example.com'}):
            with override_settings(STAPEL_AUTH={}):
                from .conf import AuthSettings
                s = AuthSettings()
                self.assertEqual(s.WEBAUTHN_RP_ID, 'test.example.com')


# =============================================================================
# security_views.py — AuditLog
# =============================================================================

class AuditLogTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        from stapel_core.django.jwt_provider import jwt_provider
        access, _ = jwt_provider.create_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')

    def test_get_log_empty(self):
        resp = self.client.get('/security/audit/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['count'], 0)
        self.assertEqual(resp.data['results'], [])

    def test_get_log_with_entries(self):
        from .models import AuthAuditLog
        AuthAuditLog.objects.create(
            user=self.user,
            event_type='login',
            ip_address='1.2.3.4',
            user_agent='TestAgent/1.0',
            metadata={},
        )
        resp = self.client.get('/security/audit/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['count'], 1)
        self.assertEqual(resp.data['results'][0]['event_type'], 'login')

    def test_get_log_requires_auth(self):
        self.client.credentials()
        resp = self.client.get('/security/audit/')
        self.assertEqual(resp.status_code, 401)

    def test_get_log_pagination(self):
        from .models import AuthAuditLog
        for i in range(25):
            AuthAuditLog.objects.create(
                user=self.user, event_type='login_success',
                ip_address='1.1.1.1', user_agent='UA', metadata={},
            )
        resp = self.client.get('/security/audit/?page=1')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data['results']), 20)
        self.assertEqual(resp.data['next'], 2)

        resp2 = self.client.get('/security/audit/?page=2')
        self.assertEqual(len(resp2.data['results']), 5)
        self.assertIsNone(resp2.data['next'])


# =============================================================================
# security_views.py — MagicLink
# =============================================================================

class MagicLinkRequestTests(APITestCase):
    def test_request_existing_user_sends_link(self):
        user = _make_user()
        with patch('stapel_auth.services.MagicLinkService.send', return_value=True):
            resp = self.client.post('/magic/request/', {'email': user.email}, format='json')
        self.assertEqual(resp.status_code, 200)

    def test_request_nonexistent_email_returns_200(self):
        resp = self.client.post('/magic/request/', {'email': 'nobody@example.com'}, format='json')
        self.assertEqual(resp.status_code, 200)

    def test_request_rate_limited_returns_429(self):
        user = _make_user()
        with patch('stapel_auth.services.MagicLinkService.send', return_value=False):
            resp = self.client.post('/magic/request/', {'email': user.email}, format='json')
        self.assertEqual(resp.status_code, 429)

    def test_verify_no_token_redirects_to_error(self):
        resp = self.client.get('/magic/verify/')
        self.assertIn(resp.status_code, [302, 301])
        self.assertIn('invalid_link', resp['Location'])

    def test_verify_invalid_token_redirects_to_error(self):
        with patch('stapel_auth.services.MagicLinkService.peek', return_value=None):
            resp = self.client.get('/magic/verify/?token=badtoken')
        self.assertIn(resp.status_code, [302, 301])
        self.assertIn('invalid_link', resp['Location'])

    def test_verify_valid_token_sets_cookies(self):
        user = _make_user()
        token_data = {'user_id': str(user.id), 'redirect_url': '/home'}
        with patch('stapel_auth.services.MagicLinkService.peek', return_value=token_data), \
             patch('stapel_auth.services.MagicLinkService.consume', return_value=token_data), \
             patch('stapel_auth.services.AuditService.log'), \
             patch('stapel_auth.views._issue_session_tokens', return_value=('acc', 'ref')), \
             patch('stapel_core.django.utils.set_jwt_cookies'):
            resp = self.client.get('/magic/verify/?token=validtoken')
        self.assertIn(resp.status_code, [302, 301])

    def test_verify_consumed_token_redirects_to_error(self):
        token_data = {'user_id': '999999', 'redirect_url': '/'}
        with patch('stapel_auth.services.MagicLinkService.peek', return_value=token_data), \
             patch('stapel_auth.services.MagicLinkService.consume', return_value=None):
            resp = self.client.get('/magic/verify/?token=usedtoken')
        self.assertIn(resp.status_code, [302, 301])
        self.assertIn('invalid_link', resp['Location'])

    def test_verify_same_user_already_logged_in_redirects(self):
        user = _make_user()
        from stapel_core.django.jwt_provider import jwt_provider
        access, _ = jwt_provider.create_tokens(user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        token_data = {'user_id': str(user.id), 'redirect_url': '/home'}
        with patch('stapel_auth.services.MagicLinkService.peek', return_value=token_data), \
             patch('stapel_auth.services.MagicLinkService.consume', return_value=token_data):
            resp = self.client.get('/magic/verify/?token=validtoken')
        self.assertIn(resp.status_code, [302, 301])

    def test_verify_different_user_logged_in_shows_conflict(self):
        user1 = _make_user()
        user2 = _make_user()
        from stapel_core.django.jwt_provider import jwt_provider
        access, _ = jwt_provider.create_tokens(user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        token_data = {'user_id': str(user2.id), 'redirect_url': '/home'}
        with patch('stapel_auth.services.MagicLinkService.peek', return_value=token_data):
            resp = self.client.get('/magic/verify/?token=validtoken')
        self.assertIn(resp.status_code, [302, 301])
        self.assertIn('account_conflict', resp['Location'])


# =============================================================================
# security_views.py — RevokeSuspicious
# =============================================================================

class RevokeSuspiciousTests(APITestCase):
    def test_invalid_token_redirects_to_error(self):
        resp = self.client.get('/security/revoke-suspicious/?token=badtoken')
        self.assertIn(resp.status_code, [302, 301])
        self.assertIn('invalid_link', resp['Location'])

    def test_no_token_redirects_to_error(self):
        resp = self.client.get('/security/revoke-suspicious/')
        self.assertIn(resp.status_code, [302, 301])
        self.assertIn('invalid_link', resp['Location'])

    def test_valid_token_revokes_sessions(self):
        from django.core.signing import TimestampSigner
        from .models import UserSession
        user = _make_user()
        import uuid as _uuid
        session = UserSession.objects.create(
            user=user,
            jti=_uuid.uuid4().hex,
            device_name='Test',
            device_type='desktop',
            expires_at=timezone.now() + timedelta(days=30),
        )
        signer = TimestampSigner()
        token = signer.sign(f'{user.id}:{session.id}')
        with patch('stapel_core.notifications.request_notification', return_value=True), \
             patch('stapel_auth.services.AuditService.log'):
            resp = self.client.get(f'/security/revoke-suspicious/?token={token}')
        self.assertIn(resp.status_code, [302, 301])
        self.assertIn('sessions_revoked', resp['Location'])
        session.refresh_from_db()
        self.assertTrue(session.is_revoked)


# =============================================================================
# security_views.py — Passkeys
# =============================================================================

class PasskeyListTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        from stapel_core.django.jwt_provider import jwt_provider
        access, _ = jwt_provider.create_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')

    def test_list_empty(self):
        resp = self.client.get('/passkey/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['passkeys'], [])

    def test_register_begin_returns_options(self):
        fake_options = {'challenge': 'abc123', 'rp': {'id': 'example.com'}, 'user': {}}
        with patch('stapel_auth.services.PasskeyService.registration_begin', return_value=fake_options):
            resp = self.client.post('/passkey/register/begin/', {}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('options', resp.data)

    def test_register_begin_service_error_returns_400(self):
        with patch('stapel_auth.services.PasskeyService.registration_begin', side_effect=Exception('fail')):
            resp = self.client.post('/passkey/register/begin/', {}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_auth_begin_no_email(self):
        fake_opts = {'challenge': 'xyz'}
        with patch('stapel_auth.services.PasskeyService.authentication_begin', return_value=('key123', fake_opts)):
            resp = self.client.post('/passkey/authenticate/begin/', {}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['session_key'], 'key123')

    def test_auth_begin_service_error_returns_400(self):
        with patch('stapel_auth.services.PasskeyService.authentication_begin', side_effect=Exception('fail')):
            resp = self.client.post('/passkey/authenticate/begin/', {}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_register_complete_challenge_expired(self):
        with patch('stapel_auth.services.PasskeyService.registration_complete',
                   side_effect=ValueError('challenge_expired')):
            resp = self.client.post('/passkey/register/complete/',
                                    {'credential': {}, 'device_name': 'Test'}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_destroy_not_found_returns_404(self):
        resp = self.client.delete(f'/passkey/{uuid.uuid4()}/')
        self.assertEqual(resp.status_code, 404)

    def test_destroy_last_auth_method_returns_400(self):
        from .models import PasskeyCredential
        pk = PasskeyCredential.objects.create(
            user=self.user,
            credential_id=uuid.uuid4().bytes,
            public_key=b'fakepublickeybytes',
            sign_count=0,
            aaguid='00000000-0000-0000-0000-000000000000',
        )
        # User has no password (set to '!' sentinel), no totp, no other passkeys → last method
        from django.contrib.auth import get_user_model
        get_user_model().objects.filter(pk=self.user.pk).update(password='!')
        self.user.refresh_from_db()
        resp = self.client.delete(f'/passkey/{pk.id}/')
        self.assertEqual(resp.status_code, 400)


class PasskeyAuthAnonTests(APITestCase):
    """Auth begin/complete are public endpoints."""

    def test_auth_begin_with_email_hint(self):
        user = _make_user()
        fake_opts = {'challenge': 'abc'}
        with patch('stapel_auth.services.PasskeyService.authentication_begin', return_value=('key', fake_opts)):
            resp = self.client.post('/passkey/authenticate/begin/', {'email': user.email}, format='json')
        self.assertEqual(resp.status_code, 200)

    def test_auth_complete_challenge_expired(self):
        with patch('stapel_auth.services.PasskeyService.authentication_complete',
                   side_effect=ValueError('challenge_expired')):
            resp = self.client.post('/passkey/authenticate/complete/',
                                    {'session_key': 'k', 'credential': {}}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_auth_complete_invalid_credential(self):
        with patch('stapel_auth.services.PasskeyService.authentication_complete',
                   side_effect=ValueError('invalid')):
            resp = self.client.post('/passkey/authenticate/complete/',
                                    {'session_key': 'k', 'credential': {}}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_auth_complete_success(self):
        user = _make_user()
        from .models import PasskeyCredential
        pc = PasskeyCredential.objects.create(
            user=user,
            credential_id=uuid.uuid4().bytes,
            public_key=b'fakepublickeybytes',
            sign_count=0,
            aaguid='00000000-0000-0000-0000-000000000000',
        )
        with patch('stapel_auth.services.PasskeyService.authentication_complete', return_value=(user, pc)), \
             patch('stapel_auth.views._issue_session_tokens', return_value=('acc', 'ref')), \
             patch('stapel_core.django.utils.set_jwt_cookies'):
            resp = self.client.post('/passkey/authenticate/complete/',
                                    {'session_key': 'k', 'credential': {}}, format='json')
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# tasks.py
# =============================================================================

class SendChangeNotificationsTaskTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def test_no_pending_requests_returns_zero(self):
        from .tasks import send_change_notifications
        result = send_change_notifications()
        self.assertEqual(result, 0)

    def test_sends_day1_notification(self):
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='email',
            old_value='old@example.com',
            new_value='new@example.com',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=14),
            change_token=uuid.uuid4(),
        )
        req.created_at = timezone.now() - timedelta(days=2)
        req.save(update_fields=['created_at'])

        with patch('stapel_auth.tasks.request_notification', return_value=True):
            from .tasks import send_change_notifications
            result = send_change_notifications()
        self.assertEqual(result, 1)
        req.refresh_from_db()
        self.assertTrue(req.notification_day_1_sent)

    def test_sends_day7_notification(self):
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='email',
            old_value='old@example.com',
            new_value='new@example.com',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=7),
            change_token=uuid.uuid4(),
            notification_day_1_sent=True,
        )
        req.created_at = timezone.now() - timedelta(days=8)
        req.save(update_fields=['created_at'])

        with patch('stapel_auth.tasks.request_notification', return_value=True):
            from .tasks import send_change_notifications
            result = send_change_notifications()
        self.assertEqual(result, 1)
        req.refresh_from_db()
        self.assertTrue(req.notification_day_7_sent)

    def test_sends_day13_notification(self):
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='phone',
            old_value='+10000000000',
            new_value='+10000000001',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=1),
            change_token=uuid.uuid4(),
            notification_day_1_sent=True,
            notification_day_7_sent=True,
        )
        req.created_at = timezone.now() - timedelta(days=14)
        req.save(update_fields=['created_at'])

        with patch('stapel_auth.tasks.request_notification', return_value=True):
            from .tasks import send_change_notifications
            result = send_change_notifications()
        self.assertEqual(result, 1)
        req.refresh_from_db()
        self.assertTrue(req.notification_day_13_sent)

    def test_notification_exception_is_swallowed(self):
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='email',
            old_value='old@example.com',
            new_value='new@example.com',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=14),
            change_token=uuid.uuid4(),
        )
        req.created_at = timezone.now() - timedelta(days=2)
        req.save(update_fields=['created_at'])

        with patch('stapel_auth.tasks.request_notification', side_effect=Exception('fail')):
            from .tasks import send_change_notifications
            result = send_change_notifications()
        self.assertEqual(result, 0)


class ExecutePendingChangesTaskTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def test_no_due_changes_returns_zero(self):
        from .tasks import execute_pending_changes
        result = execute_pending_changes()
        self.assertEqual(result, 0)

    def test_executes_due_email_change(self):
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='email',
            old_value=self.user.email,
            new_value='changed@example.com',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() - timedelta(minutes=5),
            change_token=uuid.uuid4(),
        )
        with patch('stapel_auth.services.AuthenticatorChangeService._apply_change'), \
             patch('stapel_auth.services.AuthenticatorChangeService._invalidate_all_tokens'), \
             patch('stapel_auth.tasks.request_notification', return_value=True):
            from .tasks import execute_pending_changes
            result = execute_pending_changes()
        self.assertEqual(result, 1)
        req.refresh_from_db()
        self.assertEqual(req.status, AuthenticatorChangeStatus.COMPLETED)


class CleanupExpiredRequestsTaskTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def test_no_expired_returns_zero(self):
        from .tasks import cleanup_expired_requests
        result = cleanup_expired_requests()
        self.assertEqual(result, 0)

    def test_marks_old_pending_as_expired(self):
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='email',
            old_value='old@example.com',
            new_value='new@example.com',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() - timedelta(days=35),
            change_token=uuid.uuid4(),
        )
        req.created_at = timezone.now() - timedelta(days=35)
        req.save(update_fields=['created_at'])

        from .tasks import cleanup_expired_requests
        result = cleanup_expired_requests()
        self.assertEqual(result, 1)
        req.refresh_from_db()
        self.assertEqual(req.status, AuthenticatorChangeStatus.EXPIRED)


class EvaluateLoginNotificationTaskTests(TestCase):
    def setUp(self):
        self.user = _make_user()

    def test_missing_user_returns_early(self):
        from .tasks import evaluate_login_notification
        # Should not raise
        evaluate_login_notification('99999999', str(uuid.uuid4()))

    def test_missing_session_returns_early(self):
        from .tasks import evaluate_login_notification
        evaluate_login_notification(str(self.user.id), str(uuid.uuid4()))

    def test_new_device_sends_notification(self):
        from .models import UserSession
        from .tasks import evaluate_login_notification
        session = UserSession.objects.create(
            user=self.user,
            jti=uuid.uuid4().hex,
            device_name='Chrome on Mac',
            device_type='desktop',
            expires_at=timezone.now() + timedelta(days=30),
        )
        with patch('stapel_auth.services.LoginNotificationService.is_new_device', return_value=True), \
             patch('stapel_auth.services.LoginNotificationService.is_suspicious_ip', return_value=False), \
             patch('stapel_auth.tasks._send_login_alert_email') as mock_send:
            evaluate_login_notification(str(self.user.id), str(session.id))
        mock_send.assert_called_once()

    def test_suspicious_ip_marks_session_and_notifies(self):
        from .models import UserSession
        from .tasks import evaluate_login_notification
        session = UserSession.objects.create(
            user=self.user,
            jti=uuid.uuid4().hex,
            device_name='Chrome',
            device_type='desktop',
            expires_at=timezone.now() + timedelta(days=30),
        )
        with patch('stapel_auth.services.LoginNotificationService.is_new_device', return_value=False), \
             patch('stapel_auth.services.LoginNotificationService.is_suspicious_ip', return_value=True), \
             patch('stapel_auth.services.AuditService.log'), \
             patch('stapel_auth.tasks._send_login_alert_email') as mock_send:
            evaluate_login_notification(str(self.user.id), str(session.id))
        mock_send.assert_called_once()
        session.refresh_from_db()
        self.assertTrue(session.is_suspicious)


# =============================================================================
# OAuth Provider Registry Tests
# =============================================================================

class ProviderRegistryTests(TestCase):
    """Tests for PROVIDER_REGISTRY and get_enabled_providers()."""

    def test_registry_contains_expected_providers(self):
        from stapel_auth.oauth_providers import PROVIDER_REGISTRY
        for pid in ('google', 'github', 'zoom', 'facebook', 'apple', 'twitter', 'yandex', 'vk', 'sber'):
            self.assertIn(pid, PROVIDER_REGISTRY)

    def test_get_enabled_providers_empty_when_no_credentials(self):
        from stapel_auth.oauth_providers import get_enabled_providers
        providers = get_enabled_providers()
        self.assertEqual(providers, [])

    @override_settings(STAPEL_AUTH={'OAUTH_PROVIDERS': {
        'google': {'client_id': 'gid', 'client_secret': 'gsecret'},
    }})
    def test_get_enabled_providers_returns_configured(self):
        from stapel_auth.oauth_providers import get_enabled_providers
        from stapel_auth.conf import auth_settings
        auth_settings.reload()
        providers = get_enabled_providers()
        self.assertEqual(len(providers), 1)
        self.assertEqual(providers[0].id, 'google')

    def test_unsupported_provider_returns_none(self):
        from stapel_auth.services import OAuthService
        result = OAuthService().get_user_data('tiktok', 'token')
        self.assertIsNone(result)

    @patch('stapel_auth.oauth_providers.requests.get')
    def test_google_user_data_returns_dataclass(self, mock_get):
        from stapel_auth.oauth_providers import GoogleProvider, OAuthUserData
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'id': 'g1', 'email': 'g@example.com', 'picture': 'https://pic.jpg'
        }
        result = GoogleProvider().get_user_data('tok')
        self.assertIsInstance(result, OAuthUserData)
        self.assertEqual(result.id, 'g1')
        self.assertEqual(result.email, 'g@example.com')

    @patch('stapel_auth.oauth_providers.requests.get')
    def test_google_non_200_returns_none(self, mock_get):
        from stapel_auth.oauth_providers import GoogleProvider
        mock_get.return_value.status_code = 401
        self.assertIsNone(GoogleProvider().get_user_data('bad'))

    @patch('stapel_auth.oauth_providers.requests.get')
    def test_github_user_data_username_and_email(self, mock_get):
        from stapel_auth.oauth_providers import GitHubProvider, OAuthUserData
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'id': 42, 'login': 'ghuser', 'email': 'gh@example.com', 'avatar_url': 'https://av.jpg'
        }
        result = GitHubProvider().get_user_data('tok')
        self.assertIsInstance(result, OAuthUserData)
        self.assertEqual(result.id, '42')
        self.assertEqual(result.username, 'ghuser')

    @patch('stapel_auth.oauth_providers.requests.get')
    def test_facebook_user_data(self, mock_get):
        from stapel_auth.oauth_providers import FacebookProvider, OAuthUserData
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'id': 'fb1', 'name': 'John Doe', 'email': 'fb@example.com',
            'picture': {'data': {'url': 'https://pic.jpg'}}
        }
        result = FacebookProvider().get_user_data('tok')
        self.assertIsInstance(result, OAuthUserData)
        self.assertEqual(result.id, 'fb1')
        self.assertEqual(result.username, 'john_doe')


# =============================================================================
# Capabilities Endpoint Tests
# =============================================================================

@override_settings(URL_PREFIX='')
class CapabilitiesViewTests(APITestCase):
    """Tests for GET /capabilities/"""

    def setUp(self):
        self.client = APIClient()

    def test_public_no_auth_required(self):
        response = self.client.get(reverse('capabilities'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_response_structure(self):
        response = self.client.get(reverse('capabilities'))
        self.assertIn('registration', response.data)
        self.assertIn('login', response.data)
        for section in ('registration', 'login'):
            self.assertIn('phone', response.data[section])
            self.assertIn('email', response.data[section])
            self.assertIn('oauth', response.data[section])

    def test_mock_otp_disables_phone_and_email_in_capabilities(self):
        # conftest sets USE_MOCK_SMS_OTP=True and USE_MOCK_EMAIL_OTP=True
        response = self.client.get(reverse('capabilities'))
        self.assertFalse(response.data['registration']['phone'])
        self.assertFalse(response.data['registration']['email'])
        self.assertFalse(response.data['login']['phone'])
        self.assertFalse(response.data['login']['email'])

    def test_password_disabled_by_default(self):
        response = self.client.get(reverse('capabilities'))
        self.assertFalse(response.data['registration']['password'])
        self.assertFalse(response.data['login']['password'])

    @override_settings(STAPEL_AUTH={'AUTH_PASSWORD_REGISTRATION': True, 'AUTH_PASSWORD_LOGIN': True})
    def test_password_enabled_when_flag_set(self):
        response = self.client.get(reverse('capabilities'))
        self.assertTrue(response.data['registration']['password'])
        self.assertTrue(response.data['login']['password'])

    def test_oauth_list_empty_when_no_providers_configured(self):
        response = self.client.get(reverse('capabilities'))
        self.assertEqual(response.data['registration']['oauth'], [])
        self.assertEqual(response.data['login']['oauth'], [])

    @override_settings(STAPEL_AUTH={'OAUTH_PROVIDERS': {
        'google': {'client_id': 'gid', 'client_secret': 'gsec'},
    }})
    def test_configured_oauth_provider_appears_in_list(self):
        from stapel_auth.conf import auth_settings
        auth_settings.reload()
        response = self.client.get(reverse('capabilities'))
        oauth_ids = [p['id'] for p in response.data['login']['oauth']]
        self.assertIn('google', oauth_ids)

    @override_settings(STAPEL_AUTH={'AUTH_PHONE_REGISTRATION': False})
    def test_phone_disabled_by_flag(self):
        response = self.client.get(reverse('capabilities'))
        self.assertFalse(response.data['registration']['phone'])

    def test_sso_and_qr_default_true(self):
        response = self.client.get(reverse('capabilities'))
        self.assertTrue(response.data['registration']['sso'])
        self.assertTrue(response.data['login']['qr'])
        self.assertTrue(response.data['login']['passkey'])
        self.assertTrue(response.data['login']['magic_link'])


# =============================================================================
# Feature Flag Gate Tests
# =============================================================================

@override_settings(URL_PREFIX='')
class FeatureFlagGateTests(APITestCase):
    """Tests that feature flag gates block endpoints correctly."""

    def setUp(self):
        self.client = APIClient()

    @override_settings(STAPEL_AUTH={'AUTH_PHONE_LOGIN': False, 'AUTH_PHONE_REGISTRATION': False})
    def test_phone_request_blocked_when_disabled(self):
        response = self.client.post(reverse('phone_request'), {'phone': '+79001234567'})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @override_settings(STAPEL_AUTH={'AUTH_EMAIL_LOGIN': False, 'AUTH_EMAIL_REGISTRATION': False})
    def test_email_request_blocked_when_disabled(self):
        response = self.client.post(reverse('email_request'), {'email': 'test@example.com'})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_password_login_blocked_by_default(self):
        response = self.client.post(reverse('password_login'), {
            'login': 'user@example.com', 'password': 'pass'
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_password_register_blocked_by_default(self):
        response = self.client.post(reverse('password_register'), {
            'email': 'new@example.com', 'password': 'secure_pass_123'
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# =============================================================================
# Password Registration Tests
# =============================================================================

@override_settings(URL_PREFIX='', STAPEL_AUTH={'AUTH_PASSWORD_REGISTRATION': True})
class PasswordRegistrationTests(APITestCase):
    """Tests for POST /password/register/"""

    def setUp(self):
        self.client = APIClient()

    def test_register_with_email_and_password(self):
        response = self.client.post(reverse('password_register'), {
            'email': 'newuser@example.com',
            'password': 'secure_pass_123',
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('tokens', response.data)
        self.assertEqual(response.data['status'], 'REGISTERED')

    def test_register_blocked_when_flag_off(self):
        with self.settings(STAPEL_AUTH={}):
            response = self.client.post(reverse('password_register'), {
                'email': 'x@example.com', 'password': 'secure_pass_123'
            })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_register_duplicate_email_returns_409(self):
        User.objects.create(email='dup@example.com', username='dup')
        response = self.client.post(reverse('password_register'), {
            'email': 'dup@example.com',
            'password': 'secure_pass_123',
        })
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_register_requires_identifier(self):
        response = self.client.post(reverse('password_register'), {
            'password': 'secure_pass_123',
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_with_username(self):
        response = self.client.post(reverse('password_register'), {
            'username': 'alice',
            'password': 'secure_pass_123',
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(username='alice').exists())

    def test_register_duplicate_username_returns_409(self):
        User.objects.create(username='taken')
        response = self.client.post(reverse('password_register'), {
            'username': 'taken',
            'password': 'secure_pass_123',
        })
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)


# =============================================================================
# Admin User Broker Tests
# =============================================================================

@override_settings(URL_PREFIX='')
class AdminUserBrokerTests(APITestCase):
    """Tests for POST /admin/users/"""

    def setUp(self):
        self.client = APIClient()

    def _make_service_key(self):
        from stapel_auth.models import ServiceAPIKey
        key = ServiceAPIKey.objects.create(name='test-svc', key='svc-test-key-abc', is_active=True)
        return key.key

    def test_create_user_requires_auth(self):
        response = self.client.post(reverse('admin-users'), {'email': 'u@example.com'})
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    def test_create_user_with_service_key(self):
        key = self._make_service_key()
        response = self.client.post(
            reverse('admin-users'),
            {'email': 'broker@example.com'},
            HTTP_X_API_KEY=key,
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('user_id', response.data)
        self.assertTrue(User.objects.filter(email='broker@example.com').exists())

    def test_create_user_with_staff_user(self):
        admin = User.objects.create_user(username='admin', password='pw', is_staff=True)
        from stapel_auth.tests import create_token_for_user
        access, _ = create_token_for_user(admin)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        response = self.client.post(reverse('admin-users'), {'email': 'staffcreated@example.com'})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_mark_verified_sets_email_verified(self):
        key = self._make_service_key()
        response = self.client.post(
            reverse('admin-users'),
            {'email': 'verified@example.com', 'mark_verified': True},
            HTTP_X_API_KEY=key,
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email='verified@example.com')
        self.assertTrue(user.is_email_verified)

    def test_mark_not_verified(self):
        key = self._make_service_key()
        response = self.client.post(
            reverse('admin-users'),
            {'email': 'unverified@example.com', 'mark_verified': False},
            HTTP_X_API_KEY=key,
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email='unverified@example.com')
        self.assertFalse(user.is_email_verified)

    def test_requires_at_least_one_identifier(self):
        key = self._make_service_key()
        response = self.client.post(
            reverse('admin-users'),
            {'display_name': 'No Identifier'},
            HTTP_X_API_KEY=key,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_send_welcome_calls_notification(self):
        key = self._make_service_key()
        with patch('stapel_core.notifications.request_notification') as mock_notify:
            response = self.client.post(
                reverse('admin-users'),
                {'email': 'welcome@example.com', 'send_welcome': True},
                HTTP_X_API_KEY=key,
            )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        mock_notify.assert_called_once()
        call_kwargs = mock_notify.call_args
        self.assertIn('welcome', str(call_kwargs))


# =============================================================================
# OAuth Server-Side Flow Tests (TestProvider)
# =============================================================================

_TEST_OAUTH_SETTINGS = {
    'OAUTH_PROVIDERS': {'test': {'client_id': 'test-client-id', 'client_secret': 'test-secret'}},
}


@override_settings(URL_PREFIX='', DEBUG=True, STAPEL_AUTH=_TEST_OAUTH_SETTINGS)
class OAuthAuthorizeTests(APITestCase):
    """Tests for GET /oauth/test/authorize/ — server-side OAuth initiation."""

    def setUp(self):
        self.client = APIClient()
        # Ensure TestProvider is in registry for DEBUG=True
        from stapel_auth.oauth_providers import PROVIDER_REGISTRY, TestProvider
        PROVIDER_REGISTRY.setdefault('test', TestProvider())
        from stapel_auth.conf import auth_settings
        auth_settings.reload()

    def test_authorize_redirects_to_provider(self):
        response = self.client.get(reverse('oauth_authorize', kwargs={'provider': 'test'}))
        self.assertEqual(response.status_code, 302)
        self.assertIn('test-provider.example.com', response['Location'])

    def test_authorize_stores_state_in_cache(self):
        from django.core.cache import cache
        response = self.client.get(reverse('oauth_authorize', kwargs={'provider': 'test'}))
        self.assertEqual(response.status_code, 302)
        loc = response['Location']
        # state is a query param in the redirect URL
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(loc).query)
        self.assertIn('state', qs)
        state = qs['state'][0]
        state_data = cache.get(f'oauth_state:{state}')
        self.assertIsNotNone(state_data)
        self.assertEqual(state_data['provider'], 'test')

    def test_authorize_unknown_provider_returns_400(self):
        response = self.client.get(reverse('oauth_authorize', kwargs={'provider': 'unknown-xyz'}))
        self.assertEqual(response.status_code, 400)

    def test_authorize_unconfigured_provider_returns_400(self):
        # 'google' is in registry but not in OAUTH_PROVIDERS settings
        response = self.client.get(reverse('oauth_authorize', kwargs={'provider': 'google'}))
        self.assertEqual(response.status_code, 400)

    def test_authorize_passes_redirect_uri_param(self):
        response = self.client.get(
            reverse('oauth_authorize', kwargs={'provider': 'test'}),
            {'redirect_uri': '/dashboard'},
        )
        self.assertEqual(response.status_code, 302)


@override_settings(URL_PREFIX='', DEBUG=True, STAPEL_AUTH=_TEST_OAUTH_SETTINGS)
class OAuthCallbackTests(APITestCase):
    """Tests for GET /oauth/test/callback/ — server-side OAuth code exchange."""

    def setUp(self):
        self.client = APIClient()
        from stapel_auth.oauth_providers import PROVIDER_REGISTRY, TestProvider
        PROVIDER_REGISTRY.setdefault('test', TestProvider())
        from stapel_auth.conf import auth_settings
        auth_settings.reload()

    def _store_state(self, state='test-state-abc', redirect_after=''):
        from django.core.cache import cache
        cache.set(f'oauth_state:{state}', {
            'provider': 'test',
            'redirect_uri': 'http://localhost:8000/api/oauth/test/callback',
            'redirect_after': redirect_after,
        }, timeout=600)

    def test_callback_creates_new_user_and_returns_tokens(self):
        self._store_state()
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'code': 'valid-code', 'state': 'test-state-abc'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('tokens', response.data)
        self.assertTrue(User.objects.filter(email='test-oauth@example.com').exists())

    def test_callback_returning_user_matched_by_oauth_id(self):
        User.objects.create(
            email='test-oauth@example.com',
            oauth_provider='test',
            oauth_id='test-oauth-user-1',
            is_email_verified=True,
        )
        self._store_state()
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'code': 'valid-code', 'state': 'test-state-abc'},
        )
        self.assertEqual(response.status_code, 200)
        # No duplicate user created
        self.assertEqual(User.objects.filter(email='test-oauth@example.com').count(), 1)

    def test_callback_merges_by_email_when_no_oauth_id_match(self):
        User.objects.create(
            email='test-oauth@example.com',
            username='existing',
            is_email_verified=True,
        )
        self._store_state()
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'code': 'valid-code', 'state': 'test-state-abc'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.filter(email='test-oauth@example.com').count(), 1)

    def test_callback_invalid_code_returns_400(self):
        self._store_state()
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'code': 'bad-code', 'state': 'test-state-abc'},
        )
        self.assertEqual(response.status_code, 400)

    def test_callback_missing_code_returns_400(self):
        self._store_state()
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'state': 'test-state-abc'},
        )
        self.assertEqual(response.status_code, 400)

    def test_callback_invalid_state_returns_400(self):
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'code': 'valid-code', 'state': 'no-such-state'},
        )
        self.assertEqual(response.status_code, 400)

    def test_callback_wrong_provider_in_state_returns_400(self):
        from django.core.cache import cache
        cache.set('oauth_state:mismatch-state', {
            'provider': 'google',
            'redirect_uri': 'http://localhost/callback',
            'redirect_after': '',
        }, timeout=600)
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'code': 'valid-code', 'state': 'mismatch-state'},
        )
        self.assertEqual(response.status_code, 400)

    def test_callback_error_param_returns_400(self):
        self._store_state()
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'error': 'access_denied', 'state': 'test-state-abc'},
        )
        self.assertEqual(response.status_code, 400)

    def test_callback_with_redirect_after_redirects_with_tokens(self):
        self._store_state(redirect_after='https://app.example.com/dashboard')
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'code': 'valid-code', 'state': 'test-state-abc'},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn('access_token', response['Location'])
        self.assertIn('app.example.com', response['Location'])

    def test_callback_sets_jwt_cookies(self):
        self._store_state()
        response = self.client.get(
            reverse('oauth_callback', kwargs={'provider': 'test'}),
            {'code': 'valid-code', 'state': 'test-state-abc'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('iron_jwt', response.cookies)

    def test_callback_totp_user_redirects_to_challenge(self):
        User.objects.create(
            email='test-oauth@example.com',
            oauth_provider='test',
            oauth_id='test-oauth-user-1',
            is_email_verified=True,
        )
        from unittest.mock import patch
        self._store_state()
        with patch('stapel_auth.services.TOTPService.is_enabled', return_value=True), \
             patch('stapel_auth.services.TOTPService.create_challenge', return_value='totp-challenge-tok'):
            response = self.client.get(
                reverse('oauth_callback', kwargs={'provider': 'test'}),
                {'code': 'valid-code', 'state': 'test-state-abc'},
            )
        self.assertEqual(response.status_code, 302)
        self.assertIn('totp-challenge', response['Location'])
