"""The client IP is what the SERVER observed, not what the caller claimed.

Audit F6, confirmed in production. Every IP-keyed decision this module makes —
the ``ANONYMOUS_RATE_LIMIT_PER_HOUR`` guest-mint budget, the progressive OTP
lockout, the ``LoginAttempt``/``AuthAuditLog``/``UserSession`` rows the user's
own security screen shows — used to be keyed on a hand-rolled read of
``X-Forwarded-For``, taking its LEFTMOST element. Behind the standard nginx
recipe ``proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`` the
proxy *appends*, so that element is whatever the client typed: rotating one
header handed an attacker a fresh rate-limit budget, a clean lockout counter
and a forged address in the audit trail.

The rule now: one seam, ``stapel_core.netintel.client_ip``, which trusts
``REMOTE_ADDR`` and nothing else until the deployment names a proxy-set
header in ``STAPEL_NETINTEL["TRUSTED_PROXY_HEADER"]``. Untrusted headers are
not consulted at all, so there is nothing to forge; a declared header is
honoured, so a correctly configured proxy still sees the real client.
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

User = get_user_model()

#: A deployment that declares a header its edge OVERWRITES on every request.
TRUSTS_REAL_IP = {"TRUSTED_PROXY_HEADER": "HTTP_X_REAL_IP"}


class ClaimedHeadersAreNotTheClientIpTests(TestCase):
    """The view seam and the sessions seam agree, and both ignore claims."""

    def _auth_view(self):
        from stapel_auth.otp.views import AuthViewSet

        return AuthViewSet()

    def _sessions_ip(self, request):
        from stapel_auth.sessions import services

        return services._get_client_ip(request)

    def test_forwarded_for_is_ignored_when_nothing_is_declared(self):
        """The regression test: this returned "1.2.3.4" before the fix."""
        req = RequestFactory().get(
            "/", HTTP_X_FORWARDED_FOR="1.2.3.4, 5.6.7.8", REMOTE_ADDR="10.0.0.1"
        )
        self.assertEqual(self._auth_view().get_client_ip(req), "10.0.0.1")
        self.assertEqual(self._sessions_ip(req), "10.0.0.1")

    def test_real_ip_header_is_ignored_when_nothing_is_declared(self):
        req = RequestFactory().get(
            "/", HTTP_X_REAL_IP="198.51.100.7", REMOTE_ADDR="10.0.0.1"
        )
        self.assertEqual(self._auth_view().get_client_ip(req), "10.0.0.1")
        self.assertEqual(self._sessions_ip(req), "10.0.0.1")

    def test_a_private_remote_addr_is_still_the_answer(self):
        """Behind an undeclared proxy the honest answer is the proxy itself.

        The old sessions helper skipped private-looking candidates precisely
        so it would reach past the proxy — and that is what made it read
        caller-supplied text. Over-restricting is the safe wrong answer;
        ``stapel_auth.W005`` is how the deployment learns to fix it.
        """
        req = RequestFactory().get(
            "/", HTTP_X_FORWARDED_FOR="203.0.113.9", REMOTE_ADDR="172.18.0.5"
        )
        self.assertEqual(self._sessions_ip(req), "172.18.0.5")
        self.assertEqual(self._auth_view().get_client_ip(req), "172.18.0.5")

    @override_settings(STAPEL_NETINTEL=TRUSTS_REAL_IP)
    def test_a_declared_header_is_honoured(self):
        req = RequestFactory().get(
            "/", HTTP_X_REAL_IP="198.51.100.7", REMOTE_ADDR="172.18.0.5"
        )
        self.assertEqual(self._auth_view().get_client_ip(req), "198.51.100.7")
        self.assertEqual(self._sessions_ip(req), "198.51.100.7")

    @override_settings(STAPEL_NETINTEL=TRUSTS_REAL_IP)
    def test_a_declared_header_does_not_bless_the_others(self):
        req = RequestFactory().get(
            "/",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
            HTTP_X_REAL_IP="198.51.100.7",
            REMOTE_ADDR="172.18.0.5",
        )
        self.assertEqual(self._auth_view().get_client_ip(req), "198.51.100.7")

    @override_settings(STAPEL_NETINTEL=TRUSTS_REAL_IP)
    def test_a_declared_header_that_is_absent_falls_back(self):
        req = RequestFactory().get("/", REMOTE_ADDR="172.18.0.5")
        self.assertEqual(self._auth_view().get_client_ip(req), "172.18.0.5")

    def test_no_request_is_no_ip(self):
        self.assertIsNone(self._sessions_ip(None))


@override_settings(URL_PREFIX="", STAPEL_AUTH={"ANONYMOUS_RATE_LIMIT_PER_HOUR": 3})
class TheMintBudgetCannotBeRotatedAwayTests(APITestCase):
    """End to end: the exploit the consumer's nginx made available.

    Two hops behind ``$proxy_add_x_forwarded_for``, so the caller's own
    ``X-Forwarded-For`` survives as the leftmost element and the old code
    read it as the client. One caller, one budget — a new header value used
    to buy a new one.
    """

    def setUp(self):
        cache.clear()

    def _mint(self, **extra):
        # A fresh client each time: keeping cookies would hand back the
        # anonymous JWT and the view would reuse the session instead of
        # minting, which spends no budget by design.
        return self.client_class().post(
            reverse("anonymous"), {}, format="json", REMOTE_ADDR="10.0.0.7", **extra
        )

    def test_rotating_forwarded_for_does_not_buy_a_new_budget(self):
        for _ in range(3):
            self.assertEqual(self._mint().status_code, 201)
        refused = self._mint(HTTP_X_FORWARDED_FOR="1.2.3.4")
        self.assertEqual(refused.status_code, 429, refused.content)
        again = self._mint(HTTP_X_FORWARDED_FOR="5.6.7.8")
        self.assertEqual(again.status_code, 429, again.content)

    @override_settings(STAPEL_NETINTEL=TRUSTS_REAL_IP)
    def test_a_declared_header_still_separates_real_clients(self):
        """The proxy-set header is the whole point of declaring one."""
        for _ in range(3):
            self.assertEqual(
                self._mint(HTTP_X_REAL_IP="203.0.113.10").status_code, 201
            )
        self.assertEqual(self._mint(HTTP_X_REAL_IP="203.0.113.10").status_code, 429)
        self.assertEqual(self._mint(HTTP_X_REAL_IP="203.0.113.11").status_code, 201)


class ProxyTrustChecksTests(TestCase):
    """W005/W006 — the deployment has to say what it is behind."""

    def _w005(self):
        from stapel_auth.checks import check_proxy_trust_declared

        return check_proxy_trust_declared()

    def _w006(self):
        from stapel_auth.checks import check_trusted_proxy_header_is_overwritten

        return check_trusted_proxy_header_is_overwritten()

    @override_settings(SECURE_PROXY_SSL_HEADER=None, USE_X_FORWARDED_HOST=False)
    def test_no_proxy_declared_is_quiet(self):
        # Nothing says there is a proxy, so REMOTE_ADDR is simply right.
        self.assertEqual(self._w005(), [])

    @override_settings(
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
        STAPEL_NETINTEL={},
    )
    def test_behind_a_proxy_without_a_declared_header_warns(self):
        from stapel_auth.checks import W005_PROXY_TRUST_UNDECLARED

        warnings = self._w005()
        self.assertEqual(len(warnings), 1, warnings)
        self.assertEqual(warnings[0].id, W005_PROXY_TRUST_UNDECLARED)
        self.assertIn("SECURE_PROXY_SSL_HEADER", warnings[0].msg)

    @override_settings(USE_X_FORWARDED_HOST=True, STAPEL_NETINTEL={})
    def test_use_x_forwarded_host_counts_as_behind_a_proxy(self):
        self.assertEqual(len(self._w005()), 1)

    @override_settings(
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
        STAPEL_NETINTEL=TRUSTS_REAL_IP,
    )
    def test_declaring_the_header_clears_w005(self):
        self.assertEqual(self._w005(), [])

    @override_settings(STAPEL_NETINTEL={})
    def test_no_trusted_header_is_quiet_for_w006(self):
        self.assertEqual(self._w006(), [])

    @override_settings(STAPEL_NETINTEL=TRUSTS_REAL_IP)
    def test_an_overwritten_header_is_quiet_for_w006(self):
        self.assertEqual(self._w006(), [])

    @override_settings(STAPEL_NETINTEL={"TRUSTED_PROXY_HEADER": "HTTP_X_FORWARDED_FOR"})
    def test_trusting_an_appending_header_warns(self):
        """Pointing the setting at X-Forwarded-For re-opens F6 one layer down."""
        from stapel_auth.checks import W006_APPENDING_PROXY_HEADER_TRUSTED

        warnings = self._w006()
        self.assertEqual(len(warnings), 1, warnings)
        self.assertEqual(warnings[0].id, W006_APPENDING_PROXY_HEADER_TRUSTED)
        self.assertIn("X-Real-IP", warnings[0].hint)

    def test_both_are_registered_under_the_stapel_auth_tag(self):
        from django.core.checks import registry

        registered = {
            getattr(fn, "__name__", "") for fn in registry.registry.get_checks()
        }
        self.assertIn("check_proxy_trust_declared", registered)
        self.assertIn("check_trusted_proxy_header_is_overwritten", registered)
