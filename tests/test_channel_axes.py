"""Login vs registration axes of a channel, as the capabilities report them.

Under a scaffolded ``public`` model with explicit kinds, ``GET /capabilities/``
reported ``registration.sso=true`` next to ``login.sso=false``. By the code's
own rule a channel is open while its login OR its registration axis is on,
and a new account additionally needs the registration axis; the scaffold
switched only the login axis off. Both values were the flags verbatim — the
combination is the defect, and it is now loud (``stapel_auth.W015``).

SSO was the one channel with no per-request door at all: with BOTH axes off,
``stapel_auth.urls`` (every factory mounted ``enabled=True``) still started
an SSO login. It now closes like email, phone and OAuth.
"""
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_auth.models import Organization, SSOConfig

_BOTH_OFF = {"AUTH_SSO_LOGIN": False, "AUTH_SSO_REGISTRATION": False}
_REG_ONLY = {"AUTH_SSO_LOGIN": False, "AUTH_SSO_REGISTRATION": True}


def _org():
    org = Organization.objects.create(name="Acme", slug="acme", domain="acme.example")
    SSOConfig.objects.create(
        org=org, protocol=SSOConfig.PROTOCOL_SAML, is_active=True,
        saml_entity_id="https://idp.acme.example", saml_sso_url="https://idp.acme.example/sso",
        saml_x509_cert="MIID...",
    )
    return org


@override_settings(URL_PREFIX="", FRONTEND_URL="https://app.example")
class SsoDoor(APITestCase):
    def setUp(self):
        _org()

    def _login(self):
        return self.client.get(reverse("sso_login", kwargs={"slug": "acme"}))

    def test_open_by_default(self):
        self.assertEqual(self._login().status_code, 302)

    def test_both_axes_off_closes_every_entry(self):
        with override_settings(STAPEL_AUTH=_BOTH_OFF):
            self.assertEqual(self._login().status_code, 403)
            acs = self.client.post(reverse("sso_saml_acs", kwargs={"slug": "acme"}), {"SAMLResponse": "x"})
            self.assertEqual(acs.status_code, 302)
            self.assertIn("error=sso_disabled", acs["Location"])
            cb = self.client.get(reverse("sso_oidc_callback", kwargs={"slug": "acme"}))
            self.assertIn("error=sso_disabled", cb["Location"])
            lookup = self.client.get(reverse("sso_lookup"), {"domain": "acme.example"})
            self.assertEqual(lookup.status_code, 200)
            self.assertIsNone(lookup.json()["org_slug"])

    def test_registration_axis_alone_keeps_the_door_open(self):
        """The same rule as email/phone/OAuth: either axis opens the channel."""
        with override_settings(STAPEL_AUTH=_REG_ONLY):
            self.assertEqual(self._login().status_code, 302)


class RegistrationWithoutLoginCheck(SimpleTestCase):
    def _w015(self):
        from stapel_auth.checks import check_registration_without_login

        return check_registration_without_login()

    def test_defaults_are_quiet(self):
        self.assertEqual(self._w015(), [])

    @override_settings(STAPEL_AUTH=_REG_ONLY)
    def test_the_scaffolded_public_pair_is_reported(self):
        warnings = self._w015()
        self.assertEqual([w.id for w in warnings], ["stapel_auth.W015"])
        self.assertIn("AUTH_SSO_REGISTRATION", warnings[0].hint)

    @override_settings(STAPEL_AUTH=_BOTH_OFF)
    def test_a_fully_closed_channel_is_quiet(self):
        self.assertEqual(self._w015(), [])


@override_settings(URL_PREFIX="", STAPEL_AUTH={**_REG_ONLY, "AUTH_ANONYMOUS": True})
class CapabilitiesReportTheAxes(APITestCase):
    def test_values_are_the_axes(self):
        data = self.client.get(reverse("capabilities")).json()
        self.assertIs(data["login"]["sso"], False)
        self.assertIs(data["registration"]["sso"], True)
        # Guest sessions are minted while AUTH_ANONYMOUS is on — correct.
        self.assertIs(data["registration"]["anonymous"], True)
        self.assertEqual(self.client.post(reverse("anonymous"), {}, format="json").status_code, 201)
