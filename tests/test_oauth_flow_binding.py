"""The OAuth / OIDC redirect flow is bound to the browser that started it.

Server-side state proves only that somebody started a flow. Without a
browser binding, an attacker starts one, stops at the callback with their
own code, and has a victim's browser follow that URL: the victim is signed in
to the attacker's account, and a guest in the victim's browser is merged into
it (login CSRF).
"""
import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient, APITestCase

User = get_user_model()

_SSO_OVERRIDE = {
    "FRONTEND_URL": "https://app.example.com",
    "BACKEND_URL": "https://app.example.com",
}


def _make_org():
    from stapel_auth.models import Organization

    return Organization.objects.create(
        name="Acme Corp", slug="acmecorp", domain="acmecorp.com", sso_enforced=False
    )


def _make_oidc_config(org):
    from stapel_auth.models import SSOConfig

    return SSOConfig.objects.create(
        org=org,
        protocol=SSOConfig.PROTOCOL_OIDC,
        is_active=True,
        oidc_client_id="client_id_123",
        oidc_client_secret="secret_xyz",
        oidc_discovery_url="https://idp.acmecorp.com/.well-known/openid-configuration",
    )

_SETTINGS = {
    "OAUTH_PROVIDERS": {
        "test": {"client_id": "test-client-id", "client_secret": "test-secret"}
    },
}


@override_settings(URL_PREFIX="", DEBUG=True, STAPEL_AUTH=_SETTINGS)
class OAuthFlowBindingTests(APITestCase):
    def setUp(self):
        cache.clear()
        from stapel_auth.conf import auth_settings
        from stapel_auth.oauth_providers import PROVIDER_REGISTRY, TestProvider

        PROVIDER_REGISTRY.setdefault("test", TestProvider())
        auth_settings.reload()
        self.victim = APIClient()
        self.attacker = APIClient()

    def _start(self, client):
        resp = client.get(reverse("oauth_authorize", kwargs={"provider": "test"}))
        self.assertEqual(resp.status_code, 302)
        return resp, parse_qs(urlparse(resp["Location"]).query)["state"][0]

    def _callback(self, client, state):
        return client.get(
            reverse("oauth_callback", kwargs={"provider": "test"}),
            {"code": "valid-code", "state": state},
        )

    def test_authorize_sets_a_hardened_binding_cookie(self):
        resp, state = self._start(self.victim)
        cookie = resp.cookies["stapel_flow_oauth"]
        self.assertTrue(cookie["httponly"])
        self.assertTrue(cookie["secure"])
        self.assertEqual(cookie["samesite"], "Lax")
        # The cache keeps a digest, never the cookie's value.
        parked = cache.get(f"oauth_state:{state}")
        self.assertTrue(parked["binding"])
        self.assertNotEqual(parked["binding"], cookie.value)

    def test_the_browser_that_started_the_flow_completes_it(self):
        _, state = self._start(self.victim)
        resp = self._callback(self.victim, state)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("tokens", resp.data)
        # Spent: the binding cookie is expired on the way out.
        self.assertEqual(resp.cookies["stapel_flow_oauth"]["max-age"], 0)

    def test_a_state_replayed_into_another_browser_is_refused(self):
        """The attacker starts the flow; the victim's browser follows the
        callback URL. Nobody is signed in, no account is created."""
        _, state = self._start(self.attacker)
        resp = self._callback(self.victim, state)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data["localizable_error"], "error.400.oauth_failed")
        self.assertFalse(User.objects.filter(email="test-oauth@example.com").exists())
        self.assertNotIn("stapel_jwt", resp.cookies)

    def test_a_victim_guest_is_not_merged_into_the_attacker_account(self):
        attacker_account = User.objects.create(
            email="test-oauth@example.com",
            oauth_provider="test",
            oauth_id="test-oauth-user-1",
            is_email_verified=True,
        )
        guest = User.create_anonymous_user()
        self.victim.force_authenticate(user=guest)
        _, state = self._start(self.attacker)
        resp = self._callback(self.victim, state)
        self.assertEqual(resp.status_code, 400)
        guest.refresh_from_db()
        self.assertTrue(guest.is_anonymous)
        self.assertTrue(User.objects.filter(pk=guest.pk).exists())
        attacker_account.refresh_from_db()

    def test_a_wrong_cookie_value_is_refused(self):
        _, state = self._start(self.victim)
        self.victim.cookies["stapel_flow_oauth"] = "not-the-nonce"
        resp = self._callback(self.victim, state)
        self.assertEqual(resp.status_code, 400)

    def test_a_state_parked_without_a_binding_is_refused(self):
        cache.set(
            "oauth_state:legacy",
            {"provider": "test", "redirect_uri": "http://x/cb", "redirect_after": ""},
            600,
        )
        self.victim.cookies["stapel_flow_oauth"] = "anything"
        resp = self._callback(self.victim, "legacy")
        self.assertEqual(resp.status_code, 400)


@override_settings(**_SSO_OVERRIDE)
class OIDCFlowBindingTests(APITestCase):
    def setUp(self):
        cache.clear()
        _make_oidc_config(_make_org())
        self.url = reverse("sso_oidc_callback", kwargs={"slug": "acmecorp"})

    def test_an_unbound_state_is_refused_before_the_code_exchange(self):
        from stapel_auth.sso_service import OIDCService

        cache.set(
            "oidc_state:s1",
            json.dumps({"state": "s1", "nonce": "n", "verifier": "v", "binding": "x"}),
            600,
        )
        with patch.object(OIDCService, "exchange_code") as exchange:
            resp = self.client.get(self.url, {"code": "c", "state": "s1"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=sso_invalid_response", resp["Location"])
        exchange.assert_not_called()
