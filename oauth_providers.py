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


# Expose the global registry dict — tests can inspect/mutate it
from stapel_core.oauth import _registry as PROVIDER_REGISTRY  # noqa: F401



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
            email_verified=bool(data.get("verified_email")),
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
        email_verified=True,
    )

    def exchange_code(self, client_id, client_secret, code, redirect_uri):
        if code == "valid-code":
            return self.TOKEN_OK
        return None

    def get_user_data(self, access_token: str) -> OAuthUserData | None:
        if access_token == self.TOKEN_OK:
            return self.FIXED_USER
        return None


def get_enabled_providers() -> list[OAuthProvider]:
    """Return registered providers that have credentials configured in auth_settings."""
    from stapel_core.oauth import get_all_providers
    from .conf import auth_settings
    configs = auth_settings.OAUTH_PROVIDERS
    return [
        p for p in get_all_providers()
        if p.id in configs and configs[p.id].client_id and configs[p.id].client_secret
    ]
