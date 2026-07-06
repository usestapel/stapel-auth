"""Mount-prefix safety for URLs stapel-auth hands back to clients (auth-tails).

The arch-monolith-mounting class of bug: a value built from a *root-relative*
literal (``/auth/api/qr/.../scan/``, ``/totp-challenge``) is wrong the moment
the auth URLconf is ``include()``d under a prefix. Both must be *derived* — the
scan URL via ``reverse()`` (follows the include prefix), the frontend redirect
via ``FRONTEND_URL`` (the SPA origin, not the backend mount). These tests pin
the anonymous→generate→scan chain under a prefix, mirroring
``example-monolith``'s ``test_mounting``.
"""
import sys
import types

from django.test import TestCase, override_settings
from django.urls import include, path, reverse
from rest_framework.test import APIClient

# Whole auth URLconf mounted under a non-root prefix, the stapel-studio shape.
# Mounted flat via ``include("stapel_auth.urls")`` (no namespace) exactly as
# hosts wire it (MODULE.md), so the production bare ``reverse("qr_scan")`` in
# QRAuthViewSet resolves under the prefix.
_PREFIXED_URLCONF = "_stapel_auth_mounting_test_urls"
_mod = types.ModuleType(_PREFIXED_URLCONF)
_mod.urlpatterns = [path("svc/auth/", include("stapel_auth.urls"))]
sys.modules[_PREFIXED_URLCONF] = _mod


class QRScanUrlMountTests(TestCase):
    """QR scan_url must carry whatever prefix the URLconf is mounted under."""

    def test_scan_url_at_root_uses_reverse_not_hardcoded_prefix(self):
        client = APIClient()
        resp = client.post(reverse("qr_generate"), {"type": "login_request"})
        self.assertEqual(resp.status_code, 201, resp.content)
        key = resp.data["key"]
        # reverse() at root yields /qr/<key>/scan/ — NOT the old /auth/api/ literal.
        self.assertEqual(
            resp.data["scan_url"], f"http://testserver/qr/{key}/scan/"
        )

    @override_settings(ROOT_URLCONF=_PREFIXED_URLCONF)
    def test_scan_url_carries_mount_prefix(self):
        client = APIClient()
        resp = client.post(reverse("qr_generate"), {"type": "login_request"})
        self.assertEqual(resp.status_code, 201, resp.content)
        key = resp.data["key"]
        self.assertEqual(
            resp.data["scan_url"], f"http://testserver/svc/auth/qr/{key}/scan/"
        )
        # and the advertised URL actually resolves inside the deployment
        self.assertTrue(resp.data["scan_url"].endswith(f"/svc/auth/qr/{key}/scan/"))
