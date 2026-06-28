"""OAuth provider plugin registry.

Each provider implements OAuthProvider and registers itself in PROVIDER_REGISTRY.
Enabled providers are those that have client_id + client_secret in auth_settings.OAUTH_PROVIDERS.
"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)


@dataclass
class OAuthUserData:
    """Normalized user profile from any OAuth provider.

    Attributes:
        id: Provider-specific user ID. Example: 12345
        email: User email if available. Example: user@example.com
        username: Suggested username. Example: johndoe
        avatar: Avatar URL. Example: https://example.com/avatar.jpg
    """
    id: str
    email: str | None
    username: str | None
    avatar: str | None


class OAuthProvider(ABC):
    """Abstract base for OAuth providers."""

    id: str
    display_name: str
    auth_url: str
    token_url: str
    scope: str
    extra_params: dict

    @abstractmethod
    def get_user_data(self, access_token: str) -> OAuthUserData | None:
        """Fetch and normalize user profile using the given access token."""
        ...

    def get_authorization_url(self, client_id: str, redirect_uri: str, state: str) -> str:
        """Build the provider authorization URL."""
        from urllib.parse import urlencode
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": self.scope,
            "state": state,
            "response_type": "code",
            **self.extra_params,
        }
        return self.auth_url + "?" + urlencode(params)

    def exchange_code(self, client_id: str, client_secret: str, code: str, redirect_uri: str) -> str | None:
        """Exchange authorization code for access token. Returns token string or None."""
        response = requests.post(
            self.token_url,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
        if response.status_code != 200:
            return None
        return response.json().get("access_token")


class GoogleProvider(OAuthProvider):
    id = "google"
    display_name = "Google"
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://oauth2.googleapis.com/token"
    scope = "openid email profile"
    extra_params = {"access_type": "offline"}

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
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
        )


class GitHubProvider(OAuthProvider):
    id = "github"
    display_name = "GitHub"
    auth_url = "https://github.com/login/oauth/authorize"
    token_url = "https://github.com/login/oauth/access_token"
    scope = "read:user user:email"
    extra_params = {}

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
        headers = {"Authorization": f"token {access_token}"}
        response = requests.get("https://api.github.com/user", headers=headers, timeout=10)
        if response.status_code != 200:
            return None
        data = response.json()
        email = data.get("email")
        # GitHub does not return private emails via /user — fetch from /user/emails
        if not email:
            emails_resp = requests.get("https://api.github.com/user/emails", headers=headers, timeout=10)
            if emails_resp.status_code == 200:
                emails = emails_resp.json()
                email = next(
                    (e["email"] for e in emails if e.get("primary") and e.get("verified")),
                    emails[0]["email"] if emails else None,
                )
        return OAuthUserData(
            id=str(data.get("id", "")),
            email=email,
            username=data.get("login"),
            avatar=data.get("avatar_url"),
        )


class ZoomProvider(OAuthProvider):
    id = "zoom"
    display_name = "Zoom"
    auth_url = "https://zoom.us/oauth/authorize"
    token_url = "https://zoom.us/oauth/token"
    scope = "user:read:user"
    extra_params = {}

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
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

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
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

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
        raise NotImplementedError("Apple provider is not yet implemented")


class TwitterProvider(OAuthProvider):
    id = "twitter"
    display_name = "Twitter"
    auth_url = "https://twitter.com/i/oauth2/authorize"
    token_url = "https://api.twitter.com/2/oauth2/token"
    scope = "tweet.read users.read offline.access"
    extra_params = {"code_challenge_method": "S256"}

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
        raise NotImplementedError("Twitter provider is not yet implemented")


class YandexProvider(OAuthProvider):
    id = "yandex"
    display_name = "Яндекс"
    auth_url = "https://oauth.yandex.ru/authorize"
    token_url = "https://oauth.yandex.ru/token"
    scope = "login:email login:info login:avatar"
    extra_params = {}

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
        raise NotImplementedError("Yandex provider is not yet implemented")


class VKProvider(OAuthProvider):
    id = "vk"
    display_name = "ВКонтакте"
    auth_url = "https://id.vk.com/authorize"
    token_url = "https://id.vk.com/oauth2/auth"
    scope = "email"
    extra_params = {}

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
        raise NotImplementedError("VK provider is not yet implemented")


class SberProvider(OAuthProvider):
    id = "sber"
    display_name = "Сбер ID"
    auth_url = "https://online.sberbank.ru/CSAFront/oidc/authorize.do"
    token_url = "https://online.sberbank.ru/CSAFront/api/service/oidc/v3/token"
    scope = "openid"
    extra_params = {}

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
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

    TOKEN_OK = "test-token-ok"
    FIXED_USER = OAuthUserData(
        id="test-oauth-user-1",
        email="test-oauth@example.com",
        username="testoauthuser",
        avatar=None,
    )

    def exchange_code(self, client_id, client_secret, code, redirect_uri):
        if code == "valid-code":
            return self.TOKEN_OK
        return None

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
        if access_token == self.TOKEN_OK:
            return self.FIXED_USER
        return None


PROVIDER_REGISTRY: dict[str, OAuthProvider] = {
    "google": GoogleProvider(),
    "github": GitHubProvider(),
    "zoom": ZoomProvider(),
    "facebook": FacebookProvider(),
    "apple": AppleProvider(),
    "twitter": TwitterProvider(),
    "yandex": YandexProvider(),
    "vk": VKProvider(),
    "sber": SberProvider(),
}

# TestProvider is only available when DEBUG=True (dev/test environments only).
try:
    from django.conf import settings as _django_settings
    if getattr(_django_settings, "DEBUG", False):
        PROVIDER_REGISTRY["test"] = TestProvider()
except Exception:
    pass


def get_enabled_providers() -> list[OAuthProvider]:
    """Return providers that have client_id and client_secret configured."""
    from .conf import auth_settings
    configs = auth_settings.OAUTH_PROVIDERS
    return [
        p for pid, p in PROVIDER_REGISTRY.items()
        if pid in configs and configs[pid].client_id and configs[pid].client_secret
    ]
