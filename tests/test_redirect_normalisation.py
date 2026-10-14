"""Redirect targets are judged as the browser will read them.

Browsers delete tabs and newlines anywhere inside a URL and treat a backslash
as a slash, so ``/\\t/evil.test`` and ``/\\\\evil.test`` both navigate to
``//evil.test`` — a scheme-relative URL on somebody else's host.
"""
from django.test import SimpleTestCase, override_settings
from rest_framework.test import APITestCase

from stapel_auth.hosts import safe_relative_path, safe_return_target
from stapel_auth.otp.views import _sanitize_redirect_after

_FRONTEND = {"FRONTEND_URL": "https://app.example.com"}

_EVIL = [
    "/\t/evil.test",
    "/\n/evil.test",
    "/\r\n/evil.test",
    "\t//evil.test",
    "/\\evil.test",
    "\\\\evil.test",
    "/path\\..\\..//evil.test",
    "//evil.test",
    " //evil.test",
    "/\x00/evil.test",
    "https://app.example.com@evil.test/",
    "https://user:pw@app.example.com/x",
    "javascript:alert(1)",
    "java\tscript:alert(1)",
    "https:\\\\evil.test",
    "https://evil.test/",
]


@override_settings(STAPEL_AUTH=_FRONTEND)
class RedirectNormalisationTests(SimpleTestCase):
    def setUp(self):
        from stapel_auth.conf import auth_settings

        auth_settings.reload()

    def test_every_browser_normalised_escape_is_refused(self):
        for value in _EVIL:
            with self.subTest(value=value):
                self.assertEqual(safe_return_target(value), "")
                self.assertEqual(_sanitize_redirect_after(value), "")
                self.assertEqual(safe_relative_path(value), "")

    def test_ordinary_targets_still_pass(self):
        self.assertEqual(safe_return_target("/dashboard?x=1"), "/dashboard?x=1")
        self.assertEqual(
            safe_return_target("https://app.example.com/x"), "https://app.example.com/x"
        )
        # Stripped the way the browser strips it, then accepted.
        self.assertEqual(safe_return_target("/dash\tboard"), "/dashboard")


@override_settings(URL_PREFIX="", STAPEL_AUTH={**_FRONTEND, "AUTH_QR_LOGIN": True})
class RedirectSerializerTests(APITestCase):
    def setUp(self):
        from stapel_auth.conf import auth_settings

        auth_settings.reload()

    def test_magic_link_refuses_a_tab_smuggled_redirect(self):
        from stapel_auth.magic_link.serializers import MagicLinkRequestBodySerializer

        ser = MagicLinkRequestBodySerializer(
            data={"email": "a@example.com", "redirect_url": "/\t/evil.test"}
        )
        self.assertFalse(ser.is_valid())
        self.assertIn("redirect_url", ser.errors)

    def test_qr_refuses_a_tab_smuggled_redirect(self):
        from stapel_auth.qr.serializers import QRGenerateSerializer

        good = QRGenerateSerializer(data={"type": "login_request", "redirect_url": "/home"})
        self.assertTrue(good.is_valid(), good.errors)
        ser = QRGenerateSerializer(
            data={"type": "login_request", "redirect_url": "/\t/evil.test"}
        )
        self.assertFalse(ser.is_valid())
        self.assertIn("redirect_url", ser.errors)
