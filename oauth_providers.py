"""Built-in OAuth provider implementations for stapel-auth.

Base classes and registry live in ``stapel_core.oauth``.
Custom providers can be registered from any app without modifying this file:

    from stapel_core.oauth import register_provider
    from my_app.providers import MyProvider
    register_provider(MyProvider())
"""
import logging

import requests

from stapel_core.oauth import OAuthProvider, OAuthUserData

logger = logging.getLogger(__name__)

#: Dated REST API version GitHub wants on the token-check endpoint.
GITHUB_API_VERSION = "2026-03-10"


# Expose the global registry dict — tests can inspect/mutate it
from stapel_core.oauth import _registry as PROVIDER_REGISTRY  # noqa: F401



class GoogleProvider(OAuthProvider):
    id = "google"
    display_name = "Google"
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://oauth2.googleapis.com/token"
    scope = "openid email profile"
    extra_params = {"access_type": "offline"}

    #: Google reports a token's owning client for ANY valid access token, so
    #: an accepted-audiences LIST is fully honoured here.
    verifies_audience = True
    tokeninfo_url = "https://oauth2.googleapis.com/tokeninfo"

    def verify_audience(self, access_token, config) -> bool:
        """`aud` from Google's tokeninfo must be one of the accepted clients.

        `aud` is documented as "the OAuth client that this token is for" —
        the field to compare. (`azp`, "the client that requested it", can
        legitimately differ under Google's cross-client identity within one
        project; the token is still *for* `aud`.)

        Google publishes distinct client IDs per platform, so a project with
        a web app and a native app has several legitimate audiences — which
        is exactly why the pin is a list.
        """
        response = requests.get(
            self.tokeninfo_url, params={"access_token": access_token}, timeout=10
        )
        if response.status_code != 200:
            # 400 for an invalid/expired token; anything else is an outage.
            # Both are "not proven", and not proven means refuse.
            return False
        audience = str((response.json() or {}).get("aud") or "")
        return bool(audience) and audience in config.accepted_audiences

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if response.status_code != 200:
            return None
        data = response.json()
        email = data.get("email", "")
        return OAuthUserData(
            id=str(data.get("id", "")),
            email=email or None,
            username=email.split("@")[0] or None,
            avatar=data.get("picture"),
            email_verified=bool(data.get("verified_email")),
        )


class GitHubProvider(OAuthProvider):
    id = "github"
    display_name = "GitHub"
    auth_url = "https://github.com/login/oauth/authorize"
    token_url = "https://github.com/login/oauth/access_token"
    scope = "read:user user:email"
    extra_params = {}

    verifies_audience = True
    #: GitHub answers "is this token for the app whose secret I hold", never
    #: "which app is this token for" — the check authenticates AS the app.
    #: So only the configured `client_id` can be verified; any OTHER accepted
    #: audience would need that app's own secret, which the deployment has
    #: not given us. `checks.W010` says so rather than letting the extra
    #: entries look honoured.
    verifies_only_own_client = True

    def verify_audience(self, access_token, config) -> bool:
        if not config.client_id or not config.client_secret:
            return False
        if config.client_id not in config.accepted_audiences:
            # We can only ask about our own app, and our own app is not on
            # the accept list — nothing here can produce a proof.
            return False
        response = requests.post(
            f"https://api.github.com/applications/{config.client_id}/token",
            auth=(config.client_id, config.client_secret),
            json={"access_token": access_token},
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
            timeout=10,
        )
        # 200 = this token belongs to this app. 404 = it does not (GitHub
        # collapses "unknown token" and "not yours" into one answer, which
        # is all we need).
        return response.status_code == 200

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        headers = {"Authorization": f"token {access_token}"}
        response = requests.get("https://api.github.com/user", headers=headers, timeout=10)
        if response.status_code != 200:
            return None
        data = response.json()
        email = data.get("email")
        email_verified = False
        emails = []
        try:
            emails_resp = requests.get("https://api.github.com/user/emails", headers=headers, timeout=10)
            if emails_resp.status_code == 200:
                raw_emails = emails_resp.json()
                if isinstance(raw_emails, list):
                    emails = [e for e in raw_emails if isinstance(e, dict)]
        except Exception:
            # Verification status unknown -> treat as unverified (fail-safe)
            emails = []
        if email:
            # Public profile email: verified only if GitHub lists it verified
            email_verified = any(
                e.get("email") == email and e.get("verified") for e in emails
            )
        else:
            primary = next(
                (e for e in emails if e.get("primary") and e.get("verified")), None
            )
            if primary:
                email, email_verified = primary["email"], True
            elif emails:
                email = emails[0].get("email")
                email_verified = bool(emails[0].get("verified"))
        return OAuthUserData(
            id=str(data.get("id", "")),
            email=email,
            username=data.get("login"),
            avatar=data.get("avatar_url"),
            email_verified=email_verified,
        )


class ZoomProvider(OAuthProvider):
    id = "zoom"
    display_name = "Zoom"
    auth_url = "https://zoom.us/oauth/authorize"
    token_url = "https://zoom.us/oauth/token"
    scope = "user:read:user"
    extra_params = {}

    # Zoom publishes NO token-introspection endpoint (checked 2026-08-24:
    # /oauth/token and /oauth/revoke answer 400 to an empty request, i.e.
    # they route; /oauth/introspect answers 404, i.e. it does not exist).
    # Zoom access tokens are JWT-shaped but Zoom publishes no verification
    # keys or claim schema for third parties, and calling /v2/users/me with
    # a token proves the token is live, never which client minted it.
    #
    # So a caller-supplied Zoom token cannot be attributed, and this stays
    # False: `POST /oauth/login/` refuses Zoom rather than pretending. The
    # authorization-code flow (/authorize/ -> /callback/) is unaffected —
    # that token comes from our own exchange. `checks.W009` tells the
    # deployment which door closed.
    verifies_audience = False

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        response = requests.get(
            "https://api.zoom.us/v2/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if response.status_code != 200:
            return None
        data = response.json()
        first = data.get("first_name", "")
        last = data.get("last_name", "")
        username = f"{first}_{last}".strip("_").lower().replace(" ", "_") or data.get("id")
        return OAuthUserData(
            id=str(data.get("id", "")),
            email=data.get("email"),
            username=username,
            avatar=data.get("pic_url"),
        )


class FacebookProvider(OAuthProvider):
    id = "facebook"
    display_name = "Facebook"
    auth_url = "https://www.facebook.com/v18.0/dialog/oauth"
    token_url = "https://graph.facebook.com/v18.0/oauth/access_token"
    scope = "email,public_profile"
    extra_params = {}

    #: debug_token names the owning app for any token, so a LIST is honoured.
    verifies_audience = True
    debug_token_url = "https://graph.facebook.com/debug_token"

    def verify_audience(self, access_token, config) -> bool:
        """`data.app_id` from debug_token must be one of the accepted clients.

        `data.is_valid` alone is NOT the check: debug_token happily reports
        `is_valid: true` with somebody else's `app_id` for a token that is
        perfectly valid and simply not ours. The app id is the audience.

        The inspecting credential is an app access token, which Meta
        documents as the literal `{app-id}|{app-secret}` pair — server-side
        only, which is where this runs.
        """
        if not config.client_id or not config.client_secret:
            return False
        response = requests.get(
            self.debug_token_url,
            params={
                "input_token": access_token,
                "access_token": f"{config.client_id}|{config.client_secret}",
            },
            timeout=10,
        )
        if response.status_code != 200:
            return False
        data = ((response.json() or {}).get("data")) or {}
        if not data.get("is_valid"):
            return False
        app_id = str(data.get("app_id") or "")
        return bool(app_id) and app_id in config.accepted_audiences

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        response = requests.get(
            f"https://graph.facebook.com/me?fields=id,email,name,picture&access_token={access_token}",
            timeout=10,
        )
        if response.status_code != 200:
            return None
        data = response.json()
        name = data.get("name", "")
        return OAuthUserData(
            id=str(data.get("id", "")),
            email=data.get("email"),
            username=name.lower().replace(" ", "_") or None,
            avatar=((data.get("picture") or {}).get("data") or {}).get("url"),
        )


class AppleProvider(OAuthProvider):
    id = "apple"
    display_name = "Apple"
    auth_url = "https://appleid.apple.com/auth/authorize"
    token_url = "https://appleid.apple.com/auth/token"
    scope = "name email"
    extra_params = {"response_mode": "form_post"}

    # No profile call and therefore no audience mechanism: this provider
    # cannot log anyone in through either door. `verifies_audience` stays
    # False so the token-body endpoint refuses it explicitly rather than
    # reaching an unimplemented profile fetch.
    verifies_audience = False

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        raise NotImplementedError("Apple provider is not yet implemented")


class TwitterProvider(OAuthProvider):
    id = "twitter"
    display_name = "Twitter"
    auth_url = "https://twitter.com/i/oauth2/authorize"
    token_url = "https://api.twitter.com/2/oauth2/token"
    scope = "tweet.read users.read offline.access"
    extra_params = {"code_challenge_method": "S256"}

    # No profile call and therefore no audience mechanism: this provider
    # cannot log anyone in through either door. `verifies_audience` stays
    # False so the token-body endpoint refuses it explicitly rather than
    # reaching an unimplemented profile fetch.
    verifies_audience = False

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        raise NotImplementedError("Twitter provider is not yet implemented")


class YandexProvider(OAuthProvider):
    id = "yandex"
    display_name = "Яндекс"
    auth_url = "https://oauth.yandex.ru/authorize"
    token_url = "https://oauth.yandex.ru/token"
    scope = "login:email login:info login:avatar"
    extra_params = {}

    # No profile call and therefore no audience mechanism: this provider
    # cannot log anyone in through either door. `verifies_audience` stays
    # False so the token-body endpoint refuses it explicitly rather than
    # reaching an unimplemented profile fetch.
    verifies_audience = False

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        raise NotImplementedError("Yandex provider is not yet implemented")


class VKProvider(OAuthProvider):
    id = "vk"
    display_name = "ВКонтакте"
    auth_url = "https://id.vk.com/authorize"
    token_url = "https://id.vk.com/oauth2/auth"
    scope = "email"
    extra_params = {}

    # No profile call and therefore no audience mechanism: this provider
    # cannot log anyone in through either door. `verifies_audience` stays
    # False so the token-body endpoint refuses it explicitly rather than
    # reaching an unimplemented profile fetch.
    verifies_audience = False

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        raise NotImplementedError("VK provider is not yet implemented")


class SberProvider(OAuthProvider):
    id = "sber"
    display_name = "Сбер ID"
    auth_url = "https://online.sberbank.ru/CSAFront/oidc/authorize.do"
    token_url = "https://online.sberbank.ru/CSAFront/api/service/oidc/v3/token"
    scope = "openid"
    extra_params = {}

    # No profile call and therefore no audience mechanism: this provider
    # cannot log anyone in through either door. `verifies_audience` stays
    # False so the token-body endpoint refuses it explicitly rather than
    # reaching an unimplemented profile fetch.
    verifies_audience = False

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        raise NotImplementedError("Sber provider is not yet implemented")


class TestProvider(OAuthProvider):
    """Deterministic provider for tests — never makes real HTTP calls.

    Token semantics:
        TEST_TOKEN_OK   → returns a fixed OAuthUserData (simulates success)
        anything else   → returns None (simulates provider failure)

    Code semantics:
        "valid-code"    → exchanges to TEST_TOKEN_OK
        anything else   → returns None (simulates exchange failure)
    """

    id = "test"
    display_name = "Test"
    auth_url = "https://test-provider.example.com/authorize"
    token_url = "https://test-provider.example.com/token"
    scope = "openid email"
    extra_params = {}

    #: Deterministic stand-in for a real introspection endpoint: the fixed
    #: token below is "minted for" AUDIENCE, and nothing else is.
    verifies_audience = True
    AUDIENCE = "test-client-id"

    TOKEN_OK = "test-token-ok"
    FIXED_USER = OAuthUserData(
        id="test-oauth-user-1",
        email="test-oauth@example.com",
        username="testoauthuser",
        avatar=None,
        email_verified=True,
    )

    def exchange_code(self, client_id, client_secret, code, redirect_uri):
        if code == "valid-code":
            return self.TOKEN_OK
        return None

    def verify_audience(self, access_token, config) -> bool:
        return (
            access_token == self.TOKEN_OK
            and self.AUDIENCE in config.accepted_audiences
        )

    def get_user_data(self, access_token: str, config=None) -> OAuthUserData | None:
        if access_token == self.TOKEN_OK:
            return self.FIXED_USER
        return None


def accepted_audiences(provider_id: str) -> tuple:
    """OAuth client IDs a caller-supplied token for *provider_id* may carry.

    ``STAPEL_AUTH['OAUTH_ACCEPTED_AUDIENCES'][provider_id]`` when declared;
    otherwise the provider's own ``client_id``, which is the only audience
    that can be inferred. Empty when neither is configured — nothing to pin
    to, so the token-body login path refuses (see ``checks.E008``).
    """
    from .conf import auth_settings

    declared = (auth_settings.OAUTH_ACCEPTED_AUDIENCES or {}).get(provider_id)
    if declared:
        return tuple(str(a) for a in declared if a)
    config = (auth_settings.OAUTH_PROVIDERS or {}).get(provider_id)
    client_id = str(getattr(config, "client_id", "") or "")
    return (client_id,) if client_id else ()


def audiences_are_declared(provider_id: str) -> bool:
    """Whether the deployment PINNED the audiences rather than inheriting one."""
    from .conf import auth_settings

    return bool((auth_settings.OAUTH_ACCEPTED_AUDIENCES or {}).get(provider_id))


def get_enabled_providers() -> list[OAuthProvider]:
    """Return registered providers that have credentials configured in auth_settings."""
    from stapel_core.oauth import get_all_providers
    from .conf import auth_settings
    configs = auth_settings.OAUTH_PROVIDERS
    return [
        p for p in get_all_providers()
        if p.id in configs and configs[p.id].client_id and configs[p.id].client_secret
    ]
