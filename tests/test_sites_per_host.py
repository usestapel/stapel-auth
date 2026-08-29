"""One build, two hosts: every link and redirect follows the host in the URL bar.

The registry lives in ``stapel_core.sites``; what this module owns is the
consequences — the mounted bootstrap route, the ``return_to`` allowlist, and
every place that used to reach for the single ``FRONTEND_URL`` while holding a
request.

Hostnames here are deliberately the RFC 2606 reserved names (``example.com`` /
``example.org``, plus ``attacker.test``): a real customer domain in a test file
is an exposure, and the pre-push lint says so.
"""
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_auth.hosts import allowed_return_origins, frontend_url_for
from stapel_auth.magic_link.services import MagicLinkService
from stapel_auth.otp.views import _sanitize_redirect_after

User = get_user_model()

#: Two brands on two registrable domains, one of them carrying a ``www`` alias
#: — the shape the fleet actually deploys.
SITES = {
    "sites": [
        {
            "host": "example.com",
            "aliases": ["www.example.com"],
            "primary": True,
            "locale": "en",
            "brand": {
                "key": "acme",
                "name": "Acme",
                "title": "Acme — classifieds",
                "theme": "acme",
                "legal": {"support_email": "hello@example.com"},
            },
            "seo": {"index": True},
        },
        {
            "host": "example.org",
            "primary": False,
            "locale": "en",
            "brand": {
                "key": "nord",
                "name": "Nord",
                "title": "Nord — classifieds",
                "theme": "nord",
                "legal": {"support_email": "hello@example.org"},
            },
            "seo": {"index": True},
        },
    ]
}


def _make_user(**kwargs):
    defaults = dict(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


# =============================================================================
# (a) The bootstrap the storefront reads before its first paint
# =============================================================================


@override_settings(STAPEL_SITES=SITES)
class SiteBootstrapMountTests(APITestCase):
    """``GET /auth/api/v1/site/`` — mounted here, addressed the same everywhere."""

    def test_route_is_mounted_under_the_auth_v1_prefix(self):
        # The storefront hardcodes one relative URL; this is the pin that it
        # resolves in a deployment that mounts auth the way the fleet does.
        self.assertEqual(reverse("site-bootstrap"), "/auth/api/v1/site/")

    def test_second_host_gets_its_own_brand(self):
        resp = self.client.get(reverse("site-bootstrap"), HTTP_HOST="example.org")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["host"], "example.org")
        self.assertTrue(resp.data["matched"])
        self.assertFalse(resp.data["primary"])
        self.assertEqual(resp.data["brand"]["key"], "nord")

    def test_alias_resolves_to_its_site(self):
        resp = self.client.get(reverse("site-bootstrap"), HTTP_HOST="www.example.com")
        self.assertEqual(resp.data["brand"]["key"], "acme")
        self.assertTrue(resp.data["matched"])

    def test_unknown_host_falls_back_to_the_primary_and_says_so(self):
        # A probe, an IP, a health check: the deployment has a default face,
        # and a blank page would be the alternative.
        resp = self.client.get(reverse("site-bootstrap"), HTTP_HOST="attacker.test")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data["matched"])
        self.assertEqual(resp.data["brand"]["key"], "acme")

    def test_public_and_cacheable(self):
        # No cookie, no session, no account — and the answer depends only on
        # the Host header, so a crawl must not become a request per page view.
        resp = self.client.get(reverse("site-bootstrap"), HTTP_HOST="example.org")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Cache-Control"], "public, max-age=300")
        self.assertNotIn("Set-Cookie", resp)


# =============================================================================
# (b) The return_to allowlist
# =============================================================================


@override_settings(STAPEL_SITES=SITES)
class SanitizeRedirectAfterTests(TestCase):
    """Parsed-origin membership, never a prefix test."""

    def test_registered_second_host_is_accepted(self):
        self.assertEqual(
            _sanitize_redirect_after("https://example.org/x"),
            "https://example.org/x",
        )

    def test_alias_origin_is_accepted(self):
        self.assertEqual(
            _sanitize_redirect_after("https://www.example.com/x"),
            "https://www.example.com/x",
        )

    def test_suffix_lookalike_is_rejected(self):
        # startswith("https://example.org") is true and the site is somebody
        # else's — this is the whole reason the check parses.
        self.assertEqual(_sanitize_redirect_after("https://example.org.attacker.test/"), "")

    def test_mentioning_a_registered_host_in_the_query_is_rejected(self):
        self.assertEqual(
            _sanitize_redirect_after("https://attacker.test/?u=example.org"), ""
        )

    def test_right_host_over_the_wrong_scheme_is_rejected(self):
        self.assertEqual(_sanitize_redirect_after("http://example.org/"), "")

    def test_relative_path_still_accepted(self):
        self.assertEqual(_sanitize_redirect_after("/relative"), "/relative")

    def test_protocol_relative_still_rejected(self):
        self.assertEqual(_sanitize_redirect_after("//attacker.test"), "")

    def test_frontend_url_origin_survives_for_local_dev(self):
        # FRONTEND_URL is http://localhost:3000 in this harness. Its own scheme
        # is the one non-https exception, and it applies to that origin only.
        self.assertEqual(
            _sanitize_redirect_after("http://localhost:3000/ok"),
            "http://localhost:3000/ok",
        )

    def test_allowlist_is_the_frontend_url_plus_the_registry(self):
        self.assertEqual(
            allowed_return_origins(),
            frozenset(
                {
                    "http://localhost:3000",
                    "https://example.com",
                    "https://www.example.com",
                    "https://example.org",
                }
            ),
        )


class SanitizeWithoutRegistryTests(TestCase):
    """The single-host deployment: nothing changes."""

    def test_only_the_frontend_url_origin_is_allowed(self):
        self.assertEqual(
            _sanitize_redirect_after("http://localhost:3000/ok"),
            "http://localhost:3000/ok",
        )
        self.assertEqual(_sanitize_redirect_after("https://example.org/x"), "")


# =============================================================================
# frontend_url_for
# =============================================================================


@override_settings(STAPEL_SITES=SITES)
class FrontendUrlForTests(TestCase):
    def setUp(self):
        self.rf = RequestFactory()

    def test_registered_host(self):
        self.assertEqual(
            frontend_url_for(self.rf.get("/", HTTP_HOST="example.org")),
            "https://example.org",
        )

    def test_alias_resolves_to_its_sites_canonical_host(self):
        # An alias matches, but the link is minted for the site's canonical
        # host: `www.` 301s to the apex and the session cookie is host-only,
        # so one brand must have exactly one cookie jurisdiction.
        self.assertEqual(
            frontend_url_for(self.rf.get("/", HTTP_HOST="www.example.com")),
            "https://example.com",
        )

    def test_unregistered_host_keeps_the_frontend_url(self):
        # Deliberately NOT the primary: this value goes into an email, and a
        # link is only safe to mint for a host the registry recognises.
        self.assertEqual(
            frontend_url_for(self.rf.get("/", HTTP_HOST="attacker.test")),
            "http://localhost:3000",
        )

    def test_no_request_keeps_the_frontend_url(self):
        self.assertEqual(frontend_url_for(None), "http://localhost:3000")


# =============================================================================
# (c) A minted email link follows the host the request arrived on
# =============================================================================


class MagicLinkPerHostTests(TestCase):
    """The link in the mail is the link back to the brand they asked from."""

    def setUp(self):
        cache.clear()
        self.user = _make_user()
        self.rf = RequestFactory()

    def tearDown(self):
        cache.clear()

    def _sent_link(self, host):
        with patch("stapel_core.notifications.request_notification") as notify:
            sent = MagicLinkService.send(
                self.user, request=self.rf.post("/", HTTP_HOST=host), redirect_url="/"
            )
        self.assertTrue(sent)
        return notify.call_args.kwargs["variables"]["link"]

    @override_settings(STAPEL_SITES=SITES)
    def test_link_is_minted_for_the_second_brand(self):
        link = self._sent_link("example.org")
        self.assertTrue(
            link.startswith("https://example.org/auth/api/v1/magic/verify/"), link
        )

    @override_settings(STAPEL_SITES=SITES)
    def test_unregistered_host_falls_back_to_frontend_url(self):
        link = self._sent_link("attacker.test")
        self.assertTrue(
            link.startswith("http://localhost:3000/auth/api/v1/magic/verify/"), link
        )


@override_settings(STAPEL_SITES=SITES)
class MagicLinkVerifyRedirectTests(APITestCase):
    """And so does the redirect the link itself performs."""

    def setUp(self):
        cache.clear()
        self.user = _make_user()

    def tearDown(self):
        cache.clear()

    def test_invalid_token_lands_on_the_host_it_was_opened_on(self):
        resp = self.client.get(
            reverse("magic_verify") + "?token=nope", HTTP_HOST="example.org"
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(
            resp["Location"], "https://example.org/login?error=invalid_link"
        )

    def test_invalid_token_on_an_unregistered_host_keeps_frontend_url(self):
        resp = self.client.get(
            reverse("magic_verify") + "?token=nope", HTTP_HOST="attacker.test"
        )
        self.assertEqual(
            resp["Location"], "http://localhost:3000/login?error=invalid_link"
        )


# =============================================================================
# (d) The worker is told which host, it does not guess
# =============================================================================


@override_settings(STAPEL_SITES=SITES)
class LoginAlertBaseUrlTests(TestCase):
    """A Celery worker has no Host header — so the view resolves it and sends it."""

    def setUp(self):
        cache.clear()
        self.user = _make_user()
        self.rf = RequestFactory()

    def _enqueued_kwargs(self, request):
        from datetime import timedelta

        from django.utils import timezone

        from stapel_auth.models import UserSession
        from stapel_auth.sessions.services import LoginNotificationService

        session = UserSession.objects.create(
            user=self.user,
            jti=uuid.uuid4().hex,
            device_name="Test device",
            expires_at=timezone.now() + timedelta(days=30),
        )
        with patch("stapel_auth.tasks.evaluate_login_notification.delay") as delay:
            LoginNotificationService.check_and_notify(
                self.user, session, request=request
            )
        return delay.call_args

    def test_task_receives_the_hosts_base_url_as_an_argument(self):
        call = self._enqueued_kwargs(self.rf.post("/", HTTP_HOST="example.org"))
        self.assertEqual(call.kwargs["frontend_url"], "https://example.org")

    def test_unregistered_host_hands_the_worker_the_primary(self):
        call = self._enqueued_kwargs(self.rf.post("/", HTTP_HOST="attacker.test"))
        self.assertEqual(call.kwargs["frontend_url"], "http://localhost:3000")

    def test_worker_with_no_base_url_falls_back_to_the_setting(self):
        # The no-request path (beat, a signal): FRONTEND_URL is the primary
        # site, by design — there is no host to follow.
        from stapel_auth import tasks

        with override_settings(
            STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": True},
        ), patch("stapel_core.notifications.request_notification") as notify:
            session = type("S", (), {"user_id": self.user.id, "id": uuid.uuid4(),
                                     "device_name": "d", "ip_address": ""})()
            tasks._send_login_alert_email(self.user, session, False)
        self.assertEqual(
            notify.call_args.kwargs["variables"]["secure_url"],
            "http://localhost:3000/security/sessions",
        )

    def test_worker_uses_the_base_url_it_was_given(self):
        from stapel_auth import tasks

        with override_settings(
            STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": True},
        ), patch("stapel_core.notifications.request_notification") as notify:
            session = type("S", (), {"user_id": self.user.id, "id": uuid.uuid4(),
                                     "device_name": "d", "ip_address": ""})()
            tasks._send_login_alert_email(
                self.user, session, False, frontend_url="https://example.org"
            )
        self.assertEqual(
            notify.call_args.kwargs["variables"]["secure_url"],
            "https://example.org/security/sessions",
        )


# =============================================================================
# The settings-shaped values that stay fleet-wide
# =============================================================================


@override_settings(STAPEL_SITES=SITES)
class FleetWideValuesTests(TestCase):
    def test_jwt_issuer_is_not_per_host(self):
        # A token minted on one brand must verify on the other: same accounts,
        # same secret, same issuer. Per-host issuers would split the fleet.
        from django.conf import settings

        self.assertEqual(settings.JWT_ISSUER, "stapel-auth")
