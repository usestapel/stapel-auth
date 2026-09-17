"""``GET jwt/status/`` — the read-only sibling AUTH-02 left retired.

A fleet host's own ``core/urls.py`` retired (audit tag AUTH-02, 2026-08-24)
the whole unversioned ``api/jwt/{refresh,status}`` mount because the *refresh*
half re-minted a token pair with no tracked-session requirement and no
``load_user_by_uid`` trust decision. ``JWTStatusView`` never re-mints
anything — it decodes and reports the caller's OWN cookie-borne tokens — so
it carries none of that risk and is restored here, under the v1 canon, as
its own gate.

Reference consumer: stapel-core's admin session-timeout widget
(``static/admin/js/jwt_session.js``), which used to hardcode the pre-v1
``/auth/api/jwt/status/`` literal — now permanently 404 — instead of the
mounted, versioned path this test pins.
"""
from django.test import TestCase

from stapel_auth.urls import GATE_REGISTRY, get_jwt_status_urls


class JwtStatusUrlGateTests(TestCase):
    """The route is mounted, always on, at the v1-canon path."""

    def test_the_route_is_registered_always_on(self):
        entry = GATE_REGISTRY["jwt_status"]
        self.assertEqual(entry.flags, ())
        self.assertEqual([p.name for p in entry.patterns], ["jwt_status"])

    def test_a_host_assembling_its_own_urlconf_gets_the_route(self):
        names = [p.name for p in get_jwt_status_urls()]
        self.assertIn("jwt_status", names)

    def test_the_mounted_path_is_the_v1_canon_shape(self):
        resp = self.client.get("/auth/api/v1/jwt/status/")
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertFalse(resp.json()["authenticated"])

    def test_the_pre_v1_literal_the_widget_used_to_hardcode_is_gone(self):
        """The exact path AUTH-02 retired must stay 404 — this restores the
        capability under v1, not the old unversioned literal."""
        resp = self.client.get("/auth/api/jwt/status/")
        self.assertEqual(resp.status_code, 404)
