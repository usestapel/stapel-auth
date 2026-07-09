"""Config-axis gating tests (capability-config.md §1/§5).

A1 — AUTH_ANONYMOUS: anonymous auth is its own axis with its own URL factory,
independent of the email/phone method gates. Historically the /anonymous/ URL
lived inside the otp factory: switching email+phone off silently 404'd
anonymous auth while GET /capabilities/ kept claiming it was on.

A2 — AUTH_TOTP: the TOTP endpoints in get_mfa_urls are gated the same way the
passkey endpoints are, and the capability payload reflects the setting.
"""
import sys
import types

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase


def _build_urlconf(name: str) -> str:
    """Materialize a urlconf module from the flag-consulting factories.

    Built at call time (inside an active override_settings) so the factories
    see the overridden STAPEL_AUTH — the way a host assembles a gated URLconf.
    """
    from stapel_auth import urls as auth_urls

    mod = types.ModuleType(name)
    mod.urlpatterns = [
        *auth_urls.get_sessions_urls(),
        *auth_urls.get_otp_urls(),
        *auth_urls.get_anonymous_urls(),
        *auth_urls.get_mfa_urls(),
    ]
    sys.modules[name] = mod
    return name


class AnonymousAxisFactoryTests(TestCase):
    """A1 — the AUTH_ANONYMOUS axis gates its own URL factory."""

    def test_on_by_default(self):
        from stapel_auth import urls as auth_urls

        names = [p.name for p in auth_urls.get_anonymous_urls()]
        self.assertEqual(names, ['anonymous'])

    @override_settings(STAPEL_AUTH={'AUTH_ANONYMOUS': False})
    def test_off_yields_no_urls(self):
        from stapel_auth import urls as auth_urls

        self.assertEqual(auth_urls.get_anonymous_urls(), [])

    @override_settings(STAPEL_AUTH={
        'AUTH_EMAIL_LOGIN': False, 'AUTH_EMAIL_REGISTRATION': False,
        'AUTH_PHONE_LOGIN': False, 'AUTH_PHONE_REGISTRATION': False,
    })
    def test_independent_of_email_phone_gates(self):
        """The original bug: email+phone off must NOT take anonymous down."""
        from stapel_auth import urls as auth_urls

        self.assertEqual(auth_urls.get_otp_urls(), [])
        names = [p.name for p in auth_urls.get_anonymous_urls()]
        self.assertEqual(names, ['anonymous'])


class AnonymousAxisEndpointTests(APITestCase):
    """A1 — end-to-end over factory-assembled urlconfs."""

    def setUp(self):
        self.client = APIClient()

    def test_disabled_endpoint_404s(self):
        with override_settings(STAPEL_AUTH={'AUTH_ANONYMOUS': False}):
            urlconf = _build_urlconf('tests._urlconf_anonymous_off')
            with override_settings(ROOT_URLCONF=urlconf):
                response = self.client.post('/anonymous/', {})
                self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_disabled_view_403s_on_always_on_mount(self):
        # include('stapel_auth.urls') keeps every path mounted; the
        # per-request gate inside the view is the enforcement there.
        with override_settings(STAPEL_AUTH={'AUTH_ANONYMOUS': False}):
            response = self.client.post(reverse('anonymous'), {})
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_email_phone_off_anonymous_still_works(self):
        """Regression test for the original bug (capability-config.md §5-A1)."""
        flags = {
            'AUTH_EMAIL_LOGIN': False, 'AUTH_EMAIL_REGISTRATION': False,
            'AUTH_PHONE_LOGIN': False, 'AUTH_PHONE_REGISTRATION': False,
        }
        with override_settings(STAPEL_AUTH=flags):
            urlconf = _build_urlconf('tests._urlconf_otp_off')
            with override_settings(ROOT_URLCONF=urlconf):
                response = self.client.post('/anonymous/', {})
                self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                # ... while the otp endpoints are genuinely gone.
                self.assertEqual(
                    self.client.post('/email/request/', {}).status_code,
                    status.HTTP_404_NOT_FOUND,
                )


@override_settings(URL_PREFIX='')
class AnonymousAxisCapabilitiesTests(APITestCase):
    """A1 — GET /capabilities/ reads the setting instead of hardcoding True."""

    def test_default_reports_anonymous_on(self):
        response = self.client.get(reverse('capabilities'))
        self.assertTrue(response.data['registration']['anonymous'])

    @override_settings(STAPEL_AUTH={'AUTH_ANONYMOUS': False})
    def test_disabled_reports_anonymous_off(self):
        response = self.client.get(reverse('capabilities'))
        self.assertFalse(response.data['registration']['anonymous'])

    @override_settings(STAPEL_AUTH={
        'AUTH_EMAIL_LOGIN': False, 'AUTH_EMAIL_REGISTRATION': False,
        'AUTH_PHONE_LOGIN': False, 'AUTH_PHONE_REGISTRATION': False,
    })
    def test_email_phone_off_capabilities_still_truthful(self):
        # Capabilities said "anonymous on" before the fix too — but the URL
        # was gone. Now both stay on together.
        response = self.client.get(reverse('capabilities'))
        self.assertTrue(response.data['registration']['anonymous'])


class TOTPAxisFactoryTests(TestCase):
    """A2 — AUTH_TOTP gates the totp block of get_mfa_urls, passkey-style."""

    def _names(self):
        from stapel_auth import urls as auth_urls

        return {p.name for p in auth_urls.get_mfa_urls()}

    def test_on_by_default(self):
        names = self._names()
        self.assertIn('totp_setup', names)
        self.assertIn('totp_step_up', names)
        self.assertIn('passkey_list', names)

    @override_settings(STAPEL_AUTH={'AUTH_TOTP': False})
    def test_off_drops_totp_keeps_passkey(self):
        names = self._names()
        self.assertNotIn('totp_setup', names)
        self.assertNotIn('totp_challenge_verify', names)
        self.assertNotIn('totp_step_up', names)
        self.assertIn('passkey_list', names)

    @override_settings(STAPEL_AUTH={'AUTH_TOTP': False, 'AUTH_PASSKEY_LOGIN': False})
    def test_both_off_yields_no_mfa_urls(self):
        from stapel_auth import urls as auth_urls

        self.assertEqual(auth_urls.get_mfa_urls(), [])


class TOTPAxisEndpointTests(APITestCase):
    """A2 — end-to-end: disabled TOTP endpoints 404 on a factory urlconf."""

    def test_disabled_endpoint_404s(self):
        with override_settings(STAPEL_AUTH={'AUTH_TOTP': False}):
            urlconf = _build_urlconf('tests._urlconf_totp_off')
            with override_settings(ROOT_URLCONF=urlconf):
                response = self.client.post('/totp/setup/', {})
                self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


@override_settings(URL_PREFIX='')
class TOTPAxisCapabilitiesTests(APITestCase):
    """A2 — GET /capabilities/ exposes the mfa section."""

    def test_default_reports_totp_on(self):
        response = self.client.get(reverse('capabilities'))
        self.assertTrue(response.data['mfa']['totp'])
        self.assertTrue(response.data['mfa']['passkey'])

    @override_settings(STAPEL_AUTH={'AUTH_TOTP': False})
    def test_disabled_reports_totp_off(self):
        response = self.client.get(reverse('capabilities'))
        self.assertFalse(response.data['mfa']['totp'])
        self.assertTrue(response.data['mfa']['passkey'])
