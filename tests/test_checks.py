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
    E003_FRONTEND_URL_NOT_SET,
    check_frontend_url_set_in_production,
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


class FrontendUrlProdguardCheckTests(TestCase):
    """Regression: a plain `warnings.warn` in apps.py used to be the only
    guard here — easy to miss (Python warnings routinely never reach a
    container's visible log stream), and a host's own legacy flat
    `FRONTEND_URL` Django setting carrying a dev-friendly default (e.g.
    http://localhost:3000) silently satisfied it anyway, so real users' auth
    redirects (SSO/magic-link/QR/OTP-challenge) landed on a developer's
    laptop instead of failing loudly."""

    @override_settings(DEBUG=True, STAPEL_AUTH={})
    def test_debug_true_never_flags_unset(self):
        self.assertEqual(check_frontend_url_set_in_production(), [])

    @override_settings(DEBUG=False, STAPEL_AUTH={'FRONTEND_URL': 'https://app.example.com'})
    def test_debug_false_clean_when_set(self):
        self.assertEqual(check_frontend_url_set_in_production(), [])

    @override_settings(DEBUG=False, FRONTEND_URL=None, STAPEL_AUTH={})
    def test_debug_false_flags_unset(self):
        # Both the STAPEL_AUTH dict AND the legacy flat Django setting must
        # be cleared — AppSettings' resolution order (STAPEL_AUTH dict →
        # flat setting → env → default) means conftest's own flat
        # FRONTEND_URL would otherwise silently satisfy the check, exactly
        # the shadowing failure mode this check exists to catch.
        errors = check_frontend_url_set_in_production()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].id, E003_FRONTEND_URL_NOT_SET)
        self.assertIn('FRONTEND_URL', errors[0].msg)

    @override_settings(DEBUG=False, FRONTEND_URL=None, STAPEL_AUTH={'FRONTEND_URL': ''})
    def test_debug_false_flags_blank(self):
        errors = check_frontend_url_set_in_production()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].id, E003_FRONTEND_URL_NOT_SET)

    def test_registered_under_stapel_auth_tag(self):
        from django.core.checks.registry import registry
        self.assertIn(check_frontend_url_set_in_production, registry.registered_checks)
        self.assertEqual(check_frontend_url_set_in_production.tags, ('stapel_auth',))


class TestMockOtpOnAPublicHost:
    """E001 keys off DEBUG=False — which a stand on dev settings never
    trips. The ironmemo stand therefore served a fixed OTP code for ANY
    address on the public internet, months after real providers were wired.
    E004 keys off REACHABILITY instead."""

    def _run(self, settings, hosts, **auth):
        settings.ALLOWED_HOSTS = hosts
        settings.STAPEL_AUTH = {**getattr(settings, "STAPEL_AUTH", {}), **auth}
        from stapel_auth.checks import check_mock_otp_not_on_a_public_host

        return check_mock_otp_not_on_a_public_host()

    def test_errors_on_a_public_hostname(self, settings):
        errors = self._run(settings, ["app.example.com"], USE_MOCK_EMAIL_OTP=True)
        assert [e.id for e in errors] == ["stapel_auth.E004"]
        assert "sign in as anyone" in errors[0].msg

    def test_wildcard_allowed_hosts_counts_as_public(self, settings):
        errors = self._run(settings, ["*"], USE_MOCK_SMS_OTP=True)
        assert [e.id for e in errors] == ["stapel_auth.E004"]

    def test_quiet_on_a_developer_machine(self, settings):
        assert self._run(
            settings, ["localhost", "127.0.0.1", "testserver"],
            USE_MOCK_EMAIL_OTP=True, USE_MOCK_SMS_OTP=True,
        ) == []

    def test_quiet_when_mock_otp_is_off(self, settings):
        assert self._run(
            settings, ["app.example.com"],
            USE_MOCK_EMAIL_OTP=False, USE_MOCK_SMS_OTP=False,
        ) == []

    def test_fires_regardless_of_debug(self, settings):
        settings.DEBUG = True  # exactly the stand's configuration
        errors = self._run(settings, ["app.example.com"], USE_MOCK_EMAIL_OTP=True)
        assert [e.id for e in errors] == ["stapel_auth.E004"]
