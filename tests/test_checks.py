"""Tests for stapel_auth.checks — the mock-OTP-in-production system check.

Owner-caught regression: oauth/services.py used to read the mock OTP flags
as ``not USE_MOCK_*`` and treated a mock provider as a disabled channel —
the exact opposite of what a mock is for (channel works, delivery goes to
logs). The fix stops gating ``enabled`` on the mock flags at all; production
safety for "mock left on by accident" is this system check instead of
hiding the tab.
"""
from django.test import TestCase, override_settings

from stapel_auth.checks import (
    E001_MOCK_OTP_IN_PRODUCTION,
    check_mock_otp_disabled_in_production,
)


class MockOtpProdguardCheckTests(TestCase):
    @override_settings(DEBUG=True, STAPEL_AUTH={'USE_MOCK_SMS_OTP': True, 'USE_MOCK_EMAIL_OTP': True})
    def test_debug_true_never_flags_mock(self):
        # DEBUG=True is dev/test — mock is expected there, not a misconfiguration.
        self.assertEqual(check_mock_otp_disabled_in_production(), [])

    @override_settings(DEBUG=False, STAPEL_AUTH={'USE_MOCK_SMS_OTP': False, 'USE_MOCK_EMAIL_OTP': False})
    def test_debug_false_clean_with_real_providers(self):
        self.assertEqual(check_mock_otp_disabled_in_production(), [])

    @override_settings(DEBUG=False, STAPEL_AUTH={'USE_MOCK_SMS_OTP': True, 'USE_MOCK_EMAIL_OTP': False})
    def test_debug_false_flags_mock_sms_only(self):
        errors = check_mock_otp_disabled_in_production()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].id, E001_MOCK_OTP_IN_PRODUCTION)
        self.assertIn('USE_MOCK_SMS_OTP', errors[0].msg)

    @override_settings(DEBUG=False, STAPEL_AUTH={'USE_MOCK_SMS_OTP': False, 'USE_MOCK_EMAIL_OTP': True})
    def test_debug_false_flags_mock_email_only(self):
        errors = check_mock_otp_disabled_in_production()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].id, E001_MOCK_OTP_IN_PRODUCTION)
        self.assertIn('USE_MOCK_EMAIL_OTP', errors[0].msg)

    @override_settings(DEBUG=False, STAPEL_AUTH={'USE_MOCK_SMS_OTP': True, 'USE_MOCK_EMAIL_OTP': True})
    def test_debug_false_flags_both(self):
        errors = check_mock_otp_disabled_in_production()
        self.assertEqual(len(errors), 2)
        self.assertEqual({e.id for e in errors}, {E001_MOCK_OTP_IN_PRODUCTION})

    def test_registered_under_stapel_auth_tag(self):
        from django.core.checks.registry import registry
        self.assertIn(check_mock_otp_disabled_in_production, registry.registered_checks)
        self.assertEqual(check_mock_otp_disabled_in_production.tags, ('stapel_auth',))
