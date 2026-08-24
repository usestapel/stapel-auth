"""`POST /oauth/login/` is a door, and a bare access token is not a key to it.

Audit F-OAUTH. The endpoint is unauthenticated, mounted by default
(`AUTH_OAUTH_LOGIN`), and took an access token straight from the request body:

    POST /oauth/login/  {"provider": "google", "access_token": "ya29..."}

It then asked the provider "who owns this token?" and issued OUR session for
whoever came back. But an OAuth access token is a bearer credential scoped to
the **client** it was minted for, not a statement about who the holder is to
us — so a token minted for somebody else's app against the victim's Google
account resolved to the victim here. Any app the victim ever signed into could
mint one. That is a login takeover, and it was live in production.

The fix pins the audience: a caller-supplied token is accepted only when the
provider can prove it was minted for one of THIS deployment's OAuth clients.
Providers that cannot prove it refuse. The authorization-code flow
(`/authorize/` -> `/callback/`) is untouched — that token comes from our own
`client_secret` exchange.
"""
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from stapel_auth.oauth.services import OAuthService
from stapel_auth.oauth_providers import (
    FacebookProvider,
    GitHubProvider,
    GoogleProvider,
    TestProvider,
    ZoomProvider,
    accepted_audiences,
)

User = get_user_model()

OURS = "ours.apps.googleusercontent.com"
OUR_IOS = "ours-ios.apps.googleusercontent.com"
ATTACKER = "attacker-app.apps.googleusercontent.com"


def _settings(*, audiences=None, providers=None, **extra):
    conf = {
        "OAUTH_PROVIDERS": providers
        if providers is not None
        else {"google": {"client_id": OURS, "client_secret": "s3cret"}},
        **extra,
    }
    if audiences is not None:
        conf["OAUTH_ACCEPTED_AUDIENCES"] = audiences
    return conf


def _tokeninfo(aud, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = {"aud": aud, "scope": "openid email"}
    return response


class GoogleAudienceTests(TestCase):
    """Google reports the owning client for any token, so a list is honoured."""

    @override_settings(STAPEL_AUTH=_settings(audiences={"google": [OURS]}))
    def test_our_own_client_verifies(self):
        config = OAuthService().client_config("google")
        with patch(
            "stapel_auth.oauth_providers.requests.get", return_value=_tokeninfo(OURS)
        ):
            self.assertTrue(GoogleProvider().verify_audience("tok", config))

    @override_settings(STAPEL_AUTH=_settings(audiences={"google": [OURS]}))
    def test_a_token_for_another_app_does_not(self):
        """The takeover, at the provider level."""
        config = OAuthService().client_config("google")
        with patch(
            "stapel_auth.oauth_providers.requests.get",
            return_value=_tokeninfo(ATTACKER),
        ):
            self.assertFalse(GoogleProvider().verify_audience("tok", config))

    @override_settings(STAPEL_AUTH=_settings(audiences={"google": [OURS, OUR_IOS]}))
    def test_the_mobile_client_verifies_too(self):
        """Google issues a separate client ID per platform — hence a list."""
        config = OAuthService().client_config("google")
        for audience in (OURS, OUR_IOS):
            with patch(
                "stapel_auth.oauth_providers.requests.get",
                return_value=_tokeninfo(audience),
            ):
                self.assertTrue(
                    GoogleProvider().verify_audience("tok", config), audience
                )

    @override_settings(STAPEL_AUTH=_settings(audiences={"google": [OURS]}))
    def test_a_tokeninfo_outage_refuses(self):
        config = OAuthService().client_config("google")
        with patch(
            "stapel_auth.oauth_providers.requests.get",
            return_value=_tokeninfo(OURS, status_code=500),
        ):
            self.assertFalse(GoogleProvider().verify_audience("tok", config))

    @override_settings(STAPEL_AUTH=_settings(audiences={"google": [OURS]}))
    def test_a_response_without_an_audience_refuses(self):
        config = OAuthService().client_config("google")
        with patch(
            "stapel_auth.oauth_providers.requests.get", return_value=_tokeninfo(None)
        ):
            self.assertFalse(GoogleProvider().verify_audience("tok", config))


class GitHubAudienceTests(TestCase):
    """GitHub answers only "is this token mine", so only our own id verifies."""

    def _config(self):
        return OAuthService().client_config("github")

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"github": {"client_id": "Iv1.ours", "client_secret": "s"}},
            audiences={"github": ["Iv1.ours"]},
        )
    )
    def test_a_token_for_our_app_verifies(self):
        response = MagicMock(status_code=200)
        with patch(
            "stapel_auth.oauth_providers.requests.post", return_value=response
        ) as post:
            self.assertTrue(GitHubProvider().verify_audience("tok", self._config()))
        self.assertIn("applications/Iv1.ours/token", post.call_args.args[0])
        self.assertEqual(post.call_args.kwargs["auth"], ("Iv1.ours", "s"))
        self.assertEqual(post.call_args.kwargs["json"], {"access_token": "tok"})

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"github": {"client_id": "Iv1.ours", "client_secret": "s"}},
            audiences={"github": ["Iv1.ours"]},
        )
    )
    def test_a_token_for_another_app_gets_404_and_refuses(self):
        with patch(
            "stapel_auth.oauth_providers.requests.post",
            return_value=MagicMock(status_code=404),
        ):
            self.assertFalse(GitHubProvider().verify_audience("tok", self._config()))

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"github": {"client_id": "Iv1.ours", "client_secret": "s"}},
            audiences={"github": ["Iv1.somebody-else"]},
        )
    )
    def test_an_audience_we_hold_no_secret_for_refuses_without_a_call(self):
        """Not verifiable is not the same as verified — and never silently so."""
        with patch("stapel_auth.oauth_providers.requests.post") as post:
            self.assertFalse(GitHubProvider().verify_audience("tok", self._config()))
        post.assert_not_called()

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"github": {"client_id": "Iv1.ours", "client_secret": ""}},
            audiences={"github": ["Iv1.ours"]},
        )
    )
    def test_no_secret_means_no_proof(self):
        self.assertFalse(GitHubProvider().verify_audience("tok", self._config()))


class FacebookAudienceTests(TestCase):
    def _config(self):
        return OAuthService().client_config("facebook")

    def _debug(self, app_id, is_valid=True):
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {"app_id": app_id, "is_valid": is_valid}}
        return response

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"facebook": {"client_id": "111", "client_secret": "sec"}},
            audiences={"facebook": ["111"]},
        )
    )
    def test_our_app_verifies_and_uses_an_app_access_token(self):
        with patch(
            "stapel_auth.oauth_providers.requests.get", return_value=self._debug("111")
        ) as get:
            self.assertTrue(FacebookProvider().verify_audience("tok", self._config()))
        self.assertEqual(get.call_args.kwargs["params"]["access_token"], "111|sec")
        self.assertEqual(get.call_args.kwargs["params"]["input_token"], "tok")

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"facebook": {"client_id": "111", "client_secret": "sec"}},
            audiences={"facebook": ["111"]},
        )
    )
    def test_a_valid_token_for_another_app_refuses(self):
        """`is_valid: true` is not "belongs to us" — app_id is the audience."""
        with patch(
            "stapel_auth.oauth_providers.requests.get",
            return_value=self._debug("999", is_valid=True),
        ):
            self.assertFalse(FacebookProvider().verify_audience("tok", self._config()))

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"facebook": {"client_id": "111", "client_secret": "sec"}},
            audiences={"facebook": ["111"]},
        )
    )
    def test_an_invalid_token_refuses(self):
        with patch(
            "stapel_auth.oauth_providers.requests.get",
            return_value=self._debug("111", is_valid=False),
        ):
            self.assertFalse(FacebookProvider().verify_audience("tok", self._config()))


class ProvidersThatCannotVerifyTests(TestCase):
    """Refusing is a bucket, and it has to look like one."""

    def test_zoom_declares_that_it_cannot(self):
        """Zoom publishes no introspection endpoint — checked 2026-08-24."""
        self.assertFalse(ZoomProvider().verifies_audience)

    def test_the_unimplemented_providers_declare_it_too(self):
        from stapel_auth.oauth_providers import (
            AppleProvider,
            SberProvider,
            TwitterProvider,
            VKProvider,
            YandexProvider,
        )

        for cls in (
            AppleProvider,
            TwitterProvider,
            YandexProvider,
            VKProvider,
            SberProvider,
        ):
            self.assertFalse(cls().verifies_audience, cls.__name__)

    def test_the_verifying_ones_declare_it(self):
        for cls in (GoogleProvider, GitHubProvider, FacebookProvider):
            self.assertTrue(cls().verifies_audience, cls.__name__)


@override_settings(URL_PREFIX="")
class TheServiceRefusesUnattributableTokensTests(TestCase):
    """The one boundary both caller-supplied-token paths cross."""

    @override_settings(STAPEL_AUTH=_settings(audiences={"google": [OURS]}))
    def test_a_token_for_another_app_never_reaches_the_profile_call(self):
        """The regression test: this returned the victim's profile before."""
        with patch(
            "stapel_auth.oauth_providers.requests.get",
            return_value=_tokeninfo(ATTACKER),
        ), patch.object(GoogleProvider, "get_user_data") as profile:
            result = OAuthService().get_user_data("google", "stolen-token")
        self.assertIsNone(result)
        profile.assert_not_called()

    @override_settings(STAPEL_AUTH=_settings(audiences={"google": [OURS]}))
    def test_our_own_token_resolves(self):
        from stapel_core.oauth import OAuthUserData

        with patch(
            "stapel_auth.oauth_providers.requests.get", return_value=_tokeninfo(OURS)
        ), patch.object(
            GoogleProvider,
            "get_user_data",
            return_value=OAuthUserData(
                id="1", email="u@example.com", username="u", avatar=None
            ),
        ):
            result = OAuthService().get_user_data("google", "our-token")
        self.assertIsNotNone(result)
        self.assertEqual(result.email, "u@example.com")

    @override_settings(STAPEL_AUTH=_settings(audiences={"zoom": ["z"]},
                                             providers={"zoom": {"client_id": "z",
                                                                 "client_secret": "s"}}))
    def test_an_unverifiable_provider_is_refused(self):
        with patch.object(ZoomProvider, "get_user_data") as profile:
            result = OAuthService().get_user_data("zoom", "any-token")
        self.assertIsNone(result)
        profile.assert_not_called()

    @override_settings(STAPEL_AUTH=_settings(providers={"google": {"client_id": "",
                                                                  "client_secret": ""}}))
    def test_nothing_to_pin_to_is_refused(self):
        with patch.object(GoogleProvider, "get_user_data") as profile:
            result = OAuthService().get_user_data("google", "any-token")
        self.assertIsNone(result)
        profile.assert_not_called()

    @override_settings(STAPEL_AUTH=_settings(audiences={"google": [OURS]}))
    def test_our_own_exchanged_token_skips_the_check(self):
        """The callback's token came from our client_secret exchange."""
        from stapel_core.oauth import OAuthUserData

        with patch("stapel_auth.oauth_providers.requests.get") as tokeninfo, patch.object(
            GoogleProvider,
            "get_user_data",
            return_value=OAuthUserData(id="1", email=None, username=None, avatar=None),
        ):
            result = OAuthService().get_user_data(
                "google", "exchanged", token_is_ours=True
            )
        self.assertIsNotNone(result)
        tokeninfo.assert_not_called()

    @override_settings(STAPEL_AUTH=_settings(audiences={"google": [OURS]}))
    def test_the_audiences_resolve_from_the_declaration(self):
        self.assertEqual(accepted_audiences("google"), (OURS,))

    @override_settings(STAPEL_AUTH=_settings())
    def test_the_audiences_fall_back_to_the_client_id(self):
        self.assertEqual(accepted_audiences("google"), (OURS,))

    @override_settings(STAPEL_AUTH=_settings(providers={}))
    def test_nothing_configured_is_no_audience(self):
        self.assertEqual(accepted_audiences("google"), ())


@override_settings(URL_PREFIX="", DEBUG=True)
class TheLoginEndpointRefusesTests(APITestCase):
    """End to end through the door itself, with the deterministic provider."""

    def _post(self, token):
        return self.client.post(
            reverse("oauth_login"),
            {"provider": "test", "access_token": token},
            format="json",
        )

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"test": {"client_id": TestProvider.AUDIENCE,
                                "client_secret": "s"}},
            audiences={"test": [TestProvider.AUDIENCE]},
        )
    )
    def test_a_token_minted_for_us_logs_in(self):
        response = self._post(TestProvider.TOKEN_OK)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"test": {"client_id": TestProvider.AUDIENCE,
                                "client_secret": "s"}},
            audiences={"test": ["some-other-client"]},
        )
    )
    def test_a_token_minted_for_another_client_is_refused(self):
        """The takeover, end to end: 400, and no account appears."""
        before = User.objects.count()
        response = self._post(TestProvider.TOKEN_OK)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), before)


class AudiencePinningChecksTests(TestCase):
    """W007 / E008 / W009 / W010."""

    def _run(self):
        from stapel_auth.checks import check_oauth_audience_pinning

        return check_oauth_audience_pinning()

    def _ids(self):
        return {issue.id for issue in self._run()}

    @override_settings(STAPEL_AUTH=_settings(AUTH_OAUTH_LOGIN=False))
    def test_the_door_being_shut_silences_everything(self):
        self.assertEqual(self._run(), [])

    @override_settings(
        STAPEL_AUTH=_settings(audiences={"google": [OURS, OUR_IOS]})
    )
    def test_a_declared_list_is_quiet(self):
        from stapel_auth.checks import (
            E008_OAUTH_NOTHING_TO_PIN,
            W007_OAUTH_AUDIENCES_NOT_DECLARED,
        )

        ids = self._ids()
        self.assertNotIn(W007_OAUTH_AUDIENCES_NOT_DECLARED, ids)
        self.assertNotIn(E008_OAUTH_NOTHING_TO_PIN, ids)

    @override_settings(STAPEL_AUTH=_settings())
    def test_an_inherited_audience_warns(self):
        from stapel_auth.checks import W007_OAUTH_AUDIENCES_NOT_DECLARED

        self.assertIn(W007_OAUTH_AUDIENCES_NOT_DECLARED, self._ids())

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"google": {"client_id": "", "client_secret": ""}}
        )
    )
    def test_nothing_to_pin_to_is_an_error(self):
        from stapel_auth.checks import E008_OAUTH_NOTHING_TO_PIN

        self.assertIn(E008_OAUTH_NOTHING_TO_PIN, self._ids())

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"zoom": {"client_id": "z", "client_secret": "s"}}
        )
    )
    def test_an_unverifiable_provider_warns(self):
        from stapel_auth.checks import W009_OAUTH_PROVIDER_CANNOT_VERIFY

        issues = self._run()
        self.assertEqual({i.id for i in issues}, {W009_OAUTH_PROVIDER_CANNOT_VERIFY})
        self.assertIn("authorization-code flow", issues[0].msg)

    @override_settings(
        STAPEL_AUTH=_settings(
            providers={"github": {"client_id": "Iv1.ours", "client_secret": "s"}},
            audiences={"github": ["Iv1.ours", "Iv1.another"]},
        )
    )
    def test_audiences_github_cannot_check_are_named(self):
        from stapel_auth.checks import W010_OAUTH_AUDIENCES_NOT_HONOURED

        issues = [i for i in self._run() if i.id == W010_OAUTH_AUDIENCES_NOT_HONOURED]
        self.assertEqual(len(issues), 1, self._run())
        self.assertIn("Iv1.another", issues[0].msg)
        self.assertIn("REFUSED", issues[0].msg)

    def test_it_is_registered_under_the_stapel_auth_tag(self):
        from django.core.checks import registry

        names = {getattr(fn, "__name__", "") for fn in registry.registry.get_checks()}
        self.assertIn("check_oauth_audience_pinning", names)
