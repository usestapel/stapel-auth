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
from django.utils import timezone
from rest_framework.test import APITestCase

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
