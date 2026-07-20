"""Coverage for the TOTP anti-takeover hardening (security fix, 2026-07).

Brings TOTP up to the same standard the phone/email authenticator change
flow already has (``otp.services.AuthenticatorChangeService`` /
``AuthenticatorChangeRequest``):

  1. Instant replace: ``TOTPService.setup()`` now requires proof of the
     CURRENT device (code or backup code) once one is already active —
     closing a gap where a stolen session could silently re-enroll with
     zero proof (setup() previously deactivated the active device
     unconditionally).
  2. Delayed (anti-takeover) mode for a LOST device: ``AuthenticatorChange
     Service.initiate_delayed_totp`` reuses the exact same
     ``AuthenticatorChangeRequest`` model, ``DELAYED_PERIOD_DAYS`` cooldown,
     and Celery beat tasks (``send_change_notifications`` /
     ``execute_pending_changes``) as phone/email — the only difference is
     what gets applied at the end (a TOTP disable, not a contact swap).
  3. Every TOTP change (instant or delayed) notifies the user's verified
     contact (``mfa.services.notify_totp_change``).
  4. No verified contact -> delayed mode fails cleanly (support case).

Service-layer tests use real pyotp (as test_mfa_services_coverage.py does);
view-layer tests mock the service layer (as test_mfa_views_coverage.py
does) to isolate view branch coverage from crypto.
"""
import uuid
from datetime import timedelta
from unittest.mock import patch

import pyotp
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from stapel_core.django.jwt.provider import jwt_provider

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
# mfa.services.TOTPService.setup — proof-gated replace
# =============================================================================

class TOTPSetupProofGateTests(TestCase):
    def setUp(self):
        from stapel_auth.models import TOTPDevice

        self.user = _make_user()
        self.secret = pyotp.random_base32()
        self.device = TOTPDevice.objects.create(
            user=self.user, secret=self.secret, is_active=True, backup_codes=[],
        )

    def test_first_enrollment_needs_no_proof(self):
        from stapel_auth.mfa.services import TOTPService
        from stapel_auth.models import TOTPDevice

        other = _make_user()
        result = TOTPService.setup(other)
        self.assertIn('secret', result)
        self.assertFalse(TOTPDevice.objects.get(user=other).is_active)

    def test_replace_without_proof_raises(self):
        from stapel_auth.mfa.services import TOTPService

        with self.assertRaises(ValueError) as ctx:
            TOTPService.setup(self.user)
        self.assertEqual(str(ctx.exception), 'proof_required')
        # The active device must be untouched — no silent strip.
        self.device.refresh_from_db()
        self.assertTrue(self.device.is_active)
        self.assertEqual(self.device.secret, self.secret)

    def test_replace_with_wrong_code_raises(self):
        from stapel_auth.mfa.services import TOTPService

        with self.assertRaises(ValueError):
            TOTPService.setup(self.user, code='000000')
        self.device.refresh_from_db()
        self.assertTrue(self.device.is_active)

    def test_replace_with_valid_code_succeeds(self):
        from stapel_auth.mfa.services import TOTPService

        code = pyotp.TOTP(self.secret).now()
        result = TOTPService.setup(self.user, code=code)
        self.assertIn('secret', result)
        self.assertNotEqual(result['secret'], self.secret)
        self.device.refresh_from_db()
        self.assertFalse(self.device.is_active)
        self.assertEqual(self.device.secret, result['secret'])

    def test_replace_with_valid_backup_code_succeeds(self):
        from stapel_auth.mfa.services import TOTPService
        import hashlib

        plain = 'ABCD-1234'
        self.device.backup_codes = [hashlib.sha256(plain.replace('-', '').encode()).hexdigest()]
        self.device.save(update_fields=['backup_codes'])

        result = TOTPService.setup(self.user, backup_code=plain)
        self.assertIn('secret', result)


# =============================================================================
# mfa.services.notify_totp_change
# =============================================================================

class NotifyTotpChangeTests(TestCase):
    def test_sends_to_verified_email(self):
        user = _make_user(is_email_verified=True)
        with patch('stapel_core.notifications.request_notification', return_value=True) as mock_notify:
            from stapel_auth.mfa.services import notify_totp_change
            notify_totp_change(user, 'totp_disabled')
        mock_notify.assert_called_once()
        self.assertEqual(mock_notify.call_args.kwargs['email'], user.email)
        self.assertIsNone(mock_notify.call_args.kwargs['phone'])
        self.assertEqual(mock_notify.call_args.kwargs['notification_type'], 'totp_disabled')

    def test_falls_back_to_verified_phone_when_email_unverified(self):
        user = _make_user(phone='+14155552671', is_phone_verified=True)
        with patch('stapel_core.notifications.request_notification', return_value=True) as mock_notify:
            from stapel_auth.mfa.services import notify_totp_change
            notify_totp_change(user, 'totp_disabled')
        mock_notify.assert_called_once()
        self.assertEqual(mock_notify.call_args.kwargs['phone'], user.phone)
        self.assertIsNone(mock_notify.call_args.kwargs['email'])

    def test_noop_without_any_verified_contact(self):
        user = _make_user()
        User.objects.filter(pk=user.pk).update(is_email_verified=False)
        with patch('stapel_core.notifications.request_notification', return_value=True) as mock_notify:
            from stapel_auth.mfa.services import notify_totp_change
            notify_totp_change(user, 'totp_disabled')
        mock_notify.assert_not_called()

    def test_exception_is_swallowed(self):
        user = _make_user(is_email_verified=True)
        with patch('stapel_core.notifications.request_notification', side_effect=Exception('boom')):
            from stapel_auth.mfa.services import notify_totp_change
            notify_totp_change(user, 'totp_disabled')  # must not raise


# =============================================================================
# otp.services.AuthenticatorChangeService.initiate_delayed_totp
# =============================================================================

class InitiateDelayedTotpTests(TestCase):
    def setUp(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        self.svc = AuthenticatorChangeService()

    def _with_device(self, user):
        from stapel_auth.models import TOTPDevice

        TOTPDevice.objects.create(user=user, secret=pyotp.random_base32(), is_active=True, backup_codes=[])

    def test_not_enabled_when_no_active_device(self):
        user = _make_user(is_email_verified=True)
        result = self.svc.initiate_delayed_totp(user)
        self.assertEqual(result.get('error'), 'not_enabled')

    def test_no_verified_contact_errors_cleanly(self):
        user = _make_user()  # email unset as verified
        User.objects.filter(pk=user.pk).update(is_email_verified=False)
        self._with_device(user)
        result = self.svc.initiate_delayed_totp(user)
        self.assertEqual(result.get('error'), 'no_verified_contact')

    def test_success_with_verified_email(self):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        user = _make_user(is_email_verified=True)
        self._with_device(user)
        result = self.svc.initiate_delayed_totp(user, device_id='dev-1')
        self.assertTrue(result.get('success'))
        req = AuthenticatorChangeRequest.objects.get(id=result['change_request_id'])
        self.assertEqual(req.change_type, 'totp')
        self.assertEqual(req.status, AuthenticatorChangeStatus.PENDING)
        self.assertEqual(req.old_value, '')
        self.assertTrue(req.new_value.startswith('totp:'))
        self.assertEqual(req.device_id, 'dev-1')

    def test_success_with_verified_phone_only(self):
        user = _make_user(phone='+14155552671', is_phone_verified=True)
        User.objects.filter(pk=user.pk).update(is_email_verified=False)
        self._with_device(user)
        result = self.svc.initiate_delayed_totp(user)
        self.assertTrue(result.get('success'))

    def test_cancels_existing_pending_before_creating_new(self):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        user = _make_user(is_email_verified=True)
        self._with_device(user)
        first = self.svc.initiate_delayed_totp(user)
        second = self.svc.initiate_delayed_totp(user)
        self.assertTrue(first.get('success'))
        self.assertTrue(second.get('success'))
        first_req = AuthenticatorChangeRequest.objects.get(id=first['change_request_id'])
        self.assertEqual(first_req.status, AuthenticatorChangeStatus.CANCELLED)


class GetPendingStatusTotpTests(TestCase):
    def test_masks_new_value_as_authenticator_app(self):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user()
        AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type='totp',
            old_value='',
            new_value=f'totp:{uuid.uuid4().hex}',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        status = AuthenticatorChangeService().get_pending_status(user, 'totp')
        self.assertEqual(status['new_value_masked'], 'authenticator app')
        self.assertEqual(status['type'], 'totp')

    def test_none_when_no_pending(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user()
        self.assertIsNone(AuthenticatorChangeService().get_pending_status(user, 'totp'))


class CancelPendingTotpTests(TestCase):
    def test_success(self):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user()
        req = AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type='totp',
            old_value='',
            new_value=f'totp:{uuid.uuid4().hex}',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        result = AuthenticatorChangeService().cancel_pending(user, 'totp', str(req.id))
        self.assertTrue(result.get('success'))
        req.refresh_from_db()
        self.assertEqual(req.status, AuthenticatorChangeStatus.CANCELLED)

    def test_not_found(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user()
        result = AuthenticatorChangeService().cancel_pending(user, 'totp', str(uuid.uuid4()))
        self.assertEqual(result.get('error'), 'not_found')


# =============================================================================
# tasks.py — delayed TOTP lifecycle (day-1 notify, execute-after-window)
# =============================================================================

class TotpDelayedTaskLifecycleTests(TestCase):
    def setUp(self):
        self.user = _make_user(is_email_verified=True)

    def test_send_change_notifications_day1_notifies_verified_email(self):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='totp',
            old_value='',
            new_value=f'totp:{uuid.uuid4().hex}',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=12),
        )
        req.created_at = timezone.now() - timedelta(days=2)
        req.save(update_fields=['created_at'])

        with patch('stapel_auth.tasks.request_notification', return_value=True) as mock_notify:
            from stapel_auth.tasks import send_change_notifications
            result = send_change_notifications()

        self.assertEqual(result, 1)
        req.refresh_from_db()
        self.assertTrue(req.notification_day_1_sent)
        mock_notify.assert_called_once()
        kwargs = mock_notify.call_args.kwargs
        self.assertEqual(kwargs['email'], self.user.email)
        self.assertEqual(kwargs['variables']['masked_new_value'], 'authenticator app')
        self.assertEqual(kwargs['variables']['change_type'], 'totp')

    def test_execute_pending_changes_disables_device_and_completes(self):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus, TOTPDevice

        TOTPDevice.objects.create(
            user=self.user, secret=pyotp.random_base32(), is_active=True, backup_codes=[],
        )
        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='totp',
            old_value='',
            new_value=f'totp:{uuid.uuid4().hex}',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() - timedelta(minutes=5),
        )

        with patch('stapel_auth.tasks.request_notification', return_value=True) as mock_notify:
            from stapel_auth.tasks import execute_pending_changes
            result = execute_pending_changes()

        self.assertEqual(result, 1)
        req.refresh_from_db()
        self.assertEqual(req.status, AuthenticatorChangeStatus.COMPLETED)
        self.assertFalse(TOTPDevice.objects.filter(user=self.user, is_active=True).exists())
        # Single completion notification (not the old+new pair phone/email gets).
        mock_notify.assert_called_once()
        self.assertEqual(mock_notify.call_args.kwargs['email'], self.user.email)

    def test_not_yet_due_is_not_executed(self):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus, TOTPDevice

        TOTPDevice.objects.create(
            user=self.user, secret=pyotp.random_base32(), is_active=True, backup_codes=[],
        )
        AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='totp',
            old_value='',
            new_value=f'totp:{uuid.uuid4().hex}',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=13),
        )

        from stapel_auth.tasks import execute_pending_changes
        result = execute_pending_changes()

        self.assertEqual(result, 0)
        self.assertTrue(TOTPDevice.objects.filter(user=self.user, is_active=True).exists())


# =============================================================================
# View layer — mfa.views.TOTPViewSet
# =============================================================================

class _AuthedMixin:
    def setUp(self):
        self.user = _make_user()
        access, _ = jwt_provider.create_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')


class TOTPSetupProofGateViewTests(_AuthedMixin, APITestCase):
    def test_replace_without_proof_returns_400(self):
        with patch(
            'stapel_auth.mfa.services.TOTPService.setup',
            side_effect=ValueError('proof_required'),
        ):
            resp = self.client.post(reverse('totp_setup'), {}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_replace_with_proof_returns_200(self):
        with patch(
            'stapel_auth.mfa.services.TOTPService.setup',
            return_value={'secret': 'NEWSECRET', 'qr_uri': 'otpauth://x'},
        ) as mock_setup:
            resp = self.client.post(
                reverse('totp_setup'), {'code': '123456'}, format='json',
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['secret'], 'NEWSECRET')
        mock_setup.assert_called_once_with(self.user, code='123456', backup_code=None)


class TOTPConfirmSetupNotifyTests(_AuthedMixin, APITestCase):
    def test_confirm_success_logs_audit_and_notifies(self):
        with patch(
            'stapel_auth.mfa.services.TOTPService.confirm',
            return_value=['AAAA-BBBB'],
        ), patch(
            'stapel_auth.mfa.services.notify_totp_change',
        ) as mock_notify, patch(
            'stapel_auth.sessions.services.AuditService.log',
        ) as mock_audit:
            resp = self.client.post(
                reverse('totp_setup_confirm'), {'code': '123456'}, format='json',
            )
        self.assertEqual(resp.status_code, 200)
        mock_notify.assert_called_once_with(self.user, 'totp_enabled')
        mock_audit.assert_called_once()
        self.assertEqual(mock_audit.call_args.args[0], 'totp_enabled')


class TOTPDisableNotifyTests(_AuthedMixin, APITestCase):
    def test_disable_notifies_contact(self):
        with patch(
            'stapel_auth.mfa.services.TOTPService.disable', return_value=True,
        ), patch('stapel_auth.sessions.services.AuditService.log'), patch(
            'stapel_auth.mfa.services.notify_totp_change',
        ) as mock_notify:
            resp = self.client.post(
                reverse('totp_disable'), {'method': 'totp', 'code': '123456'}, format='json',
            )
        self.assertEqual(resp.status_code, 200)
        mock_notify.assert_called_once_with(self.user, 'totp_disabled')


class TOTPDelayedInitiateViewTests(_AuthedMixin, APITestCase):
    def test_not_enabled_returns_400(self):
        resp = self.client.post(reverse('totp_delayed_initiate'), {}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_no_verified_contact_returns_400(self):
        with patch(
            'stapel_auth.otp.services.AuthenticatorChangeService.initiate_delayed_totp',
            return_value={'error': 'no_verified_contact', 'message': 'x'},
        ):
            resp = self.client.post(reverse('totp_delayed_initiate'), {}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_success_returns_201(self):
        with patch(
            'stapel_auth.otp.services.AuthenticatorChangeService.initiate_delayed_totp',
            return_value={
                'success': True,
                'change_request_id': str(uuid.uuid4()),
                'scheduled_at': timezone.now().isoformat(),
            },
        ):
            resp = self.client.post(
                reverse('totp_delayed_initiate'), {'device_id': 'dev-1'}, format='json',
            )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data['status'], 'PENDING')
        self.assertEqual(resp.data['new_value_masked'], 'authenticator app')


class TOTPDelayedStatusViewTests(_AuthedMixin, APITestCase):
    def test_no_pending_change(self):
        resp = self.client.get(reverse('totp_delayed_status'))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data['has_pending_change'])

    def test_pending_change_present(self):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='totp',
            old_value='',
            new_value=f'totp:{uuid.uuid4().hex}',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        resp = self.client.get(reverse('totp_delayed_status'))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['has_pending_change'])
        self.assertEqual(resp.data['new_value_masked'], 'authenticator app')


class TOTPDelayedCancelViewTests(_AuthedMixin, APITestCase):
    def test_not_found_returns_404(self):
        resp = self.client.post(
            reverse('totp_delayed_cancel'), {'change_request_id': str(uuid.uuid4())}, format='json',
        )
        self.assertEqual(resp.status_code, 404)

    def test_success(self):
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        req = AuthenticatorChangeRequest.objects.create(
            user=self.user,
            change_type='totp',
            old_value='',
            new_value=f'totp:{uuid.uuid4().hex}',
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=14),
        )
        resp = self.client.post(
            reverse('totp_delayed_cancel'), {'change_request_id': str(req.id)}, format='json',
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['status'], 'CANCELLED')
        req.refresh_from_db()
        self.assertEqual(req.status, AuthenticatorChangeStatus.CANCELLED)


# =============================================================================
# End-to-end: full delayed lifecycle (initiate -> notify -> cancel window ->
# apply), simulating the beat tasks directly (no Celery broker in tests).
# =============================================================================

class TotpDelayedFullLifecycleTests(TestCase):
    def test_initiate_then_cancel_prevents_execution(self):
        from stapel_auth.models import TOTPDevice
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user(is_email_verified=True)
        TOTPDevice.objects.create(user=user, secret=pyotp.random_base32(), is_active=True, backup_codes=[])

        svc = AuthenticatorChangeService()
        initiated = svc.initiate_delayed_totp(user)
        self.assertTrue(initiated['success'])

        cancelled = svc.cancel_pending(user, 'totp', initiated['change_request_id'])
        self.assertTrue(cancelled['success'])

        # Force the (now-cancelled) request's scheduled_at into the past and
        # run the apply task — a cancelled request must never execute.
        from stapel_auth.models import AuthenticatorChangeRequest
        AuthenticatorChangeRequest.objects.filter(id=initiated['change_request_id']).update(
            scheduled_at=timezone.now() - timedelta(minutes=1),
        )
        from stapel_auth.tasks import execute_pending_changes
        executed = execute_pending_changes()
        self.assertEqual(executed, 0)
        self.assertTrue(TOTPDevice.objects.filter(user=user, is_active=True).exists())

    def test_initiate_then_window_elapses_applies_disable(self):
        from stapel_auth.models import TOTPDevice, AuthenticatorChangeRequest, AuthenticatorChangeStatus
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user(is_email_verified=True)
        TOTPDevice.objects.create(user=user, secret=pyotp.random_base32(), is_active=True, backup_codes=[])

        svc = AuthenticatorChangeService()
        initiated = svc.initiate_delayed_totp(user)

        # Simulate the DELAYED_PERIOD_DAYS cooldown having elapsed.
        AuthenticatorChangeRequest.objects.filter(id=initiated['change_request_id']).update(
            scheduled_at=timezone.now() - timedelta(minutes=1),
        )

        with patch('stapel_auth.tasks.request_notification', return_value=True):
            from stapel_auth.tasks import execute_pending_changes
            executed = execute_pending_changes()

        self.assertEqual(executed, 1)
        self.assertFalse(TOTPDevice.objects.filter(user=user, is_active=True).exists())
        req = AuthenticatorChangeRequest.objects.get(id=initiated['change_request_id'])
        self.assertEqual(req.status, AuthenticatorChangeStatus.COMPLETED)
