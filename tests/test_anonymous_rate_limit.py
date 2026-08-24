"""Guest minting is capped — the faucet has a tap now.

``POST /anonymous/`` is unauthenticated by design (`AUTH_ANONYMOUS`, on by
default) and every call created a real ``User`` row plus a JWT, with a
caller-supplied ``device_id`` as the only dedup: no captcha, no throttle, no
counter. Anyone could hold the faucet open and grow the user and session
tables at request speed.

The cap spends budget only where the cost is — creating a row. A guest that
reuses its session (by ``device_id``, or by presenting the anonymous JWT it
already holds) pays nothing, which is what the normal flow does.
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

User = get_user_model()


@override_settings(URL_PREFIX="", STAPEL_AUTH={"ANONYMOUS_RATE_LIMIT_PER_HOUR": 3})
class AnonymousMintingIsCappedTests(APITestCase):
    def setUp(self):
        cache.clear()

    def _mint(self, device_id=None, ip="10.0.0.7"):
        # A FRESH client every time: keeping the cookie jar would hand the
        # anonymous JWT back on the next call and the view would reuse that
        # session instead of minting — which is the legitimate flow, not the
        # abuse this cap is about.
        body = {"device_id": device_id} if device_id else {}
        return self.client_class().post(
            reverse("anonymous"), body, format="json", REMOTE_ADDR=ip
        )

    def test_the_budget_runs_out(self):
        before = User.objects.count()
        for _ in range(3):
            self.assertEqual(self._mint().status_code, 201)
        refused = self._mint()
        self.assertEqual(refused.status_code, 429, refused.content)
        self.assertEqual(
            User.objects.count() - before, 3, "a refused mint still created a row"
        )

    def test_the_budget_is_per_client(self):
        for _ in range(3):
            self.assertEqual(self._mint(ip="10.0.0.7").status_code, 201)
        self.assertEqual(self._mint(ip="10.0.0.7").status_code, 429)
        # A different client has its own budget — one abuser cannot lock the
        # guest surface for everybody.
        self.assertEqual(self._mint(ip="10.0.0.8").status_code, 201)

    def test_the_forwarded_client_counts_only_where_it_is_declared(self):
        """Behind a proxy the budget follows the DECLARED client-IP header.

        It used to follow ``X-Forwarded-For`` unconditionally, which meant a
        caller could buy a fresh budget by editing a header (audit F6). See
        tests/test_client_ip_trust.py for that exploit in full.
        """
        def mint(ip):
            return self.client_class().post(
                reverse("anonymous"), {}, format="json", HTTP_X_REAL_IP=ip
            )

        with override_settings(STAPEL_NETINTEL={"TRUSTED_PROXY_HEADER": "HTTP_X_REAL_IP"}):
            for _ in range(3):
                self.assertEqual(mint("1.2.3.4").status_code, 201)
            self.assertEqual(mint("1.2.3.4").status_code, 429)
            self.assertEqual(mint("1.2.3.5").status_code, 201)

    def test_reusing_a_device_id_is_free(self):
        """The legitimate flow must not be the thing that runs out of budget.

        Cookie-less on purpose: the device_id dedup is the path a client that
        cannot keep cookies takes, and it must not spend budget either.
        """
        first = self._mint(device_id="device-abc")
        self.assertEqual(first.status_code, 201)
        for _ in range(10):
            again = self._mint(device_id="device-abc")
            self.assertEqual(again.status_code, 201, again.content)
        self.assertEqual(
            User.objects.filter(is_anonymous=True).count(),
            1,
            "device dedup stopped working",
        )

    @override_settings(URL_PREFIX="", STAPEL_AUTH={"ANONYMOUS_RATE_LIMIT_PER_HOUR": 0})
    def test_zero_disables_the_cap(self):
        for _ in range(6):
            self.assertEqual(self._mint().status_code, 201)

    @override_settings(
        URL_PREFIX="",
        STAPEL_AUTH={"AUTH_ANONYMOUS": False, "ANONYMOUS_RATE_LIMIT_PER_HOUR": 3},
    )
    def test_the_feature_gate_still_wins(self):
        self.assertEqual(self._mint().status_code, 403)


@override_settings(URL_PREFIX="")
class DefaultCapIsOnTests(APITestCase):
    """Stock defaults must carry a cap, not merely offer one."""

    def setUp(self):
        cache.clear()

    def test_the_shipped_default_is_a_finite_budget(self):
        from stapel_auth.conf import auth_settings

        self.assertGreater(auth_settings.ANONYMOUS_RATE_LIMIT_PER_HOUR, 0)

    def test_a_burst_on_stock_defaults_is_eventually_refused(self):
        from stapel_auth.conf import auth_settings

        def mint():
            return self.client_class().post(
                reverse("anonymous"), {}, format="json", REMOTE_ADDR="10.9.9.9"
            )

        for _ in range(auth_settings.ANONYMOUS_RATE_LIMIT_PER_HOUR):
            self.assertEqual(mint().status_code, 201)
        refused = mint()
        self.assertEqual(refused.status_code, 429, refused.content)
