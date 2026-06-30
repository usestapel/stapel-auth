"""Data Transfer Objects for OAuth and authentication capabilities."""
from dataclasses import dataclass
from typing import List


@dataclass
class OAuthProviderInfo:
    """OAuth provider available for authentication.

    Attributes:
        id: Provider identifier. Example: google
        name: Display name. Example: Google
    """
    id: str
    name: str


@dataclass
class RegistrationCapabilities:
    """Available registration methods for this deployment.

    Attributes:
        phone: Phone OTP registration enabled. Example: true
        email: Email OTP registration enabled. Example: true
        password: Password registration enabled. Example: false
        oauth: Enabled OAuth providers. Example: []
        sso: SSO/SAML JIT provisioning enabled. Example: true
        anonymous: Anonymous registration enabled. Example: true
    """
    phone: bool
    email: bool
    password: bool
    oauth: List[OAuthProviderInfo]
    sso: bool
    anonymous: bool


@dataclass
class LoginCapabilities:
    """Available login methods for this deployment.

    Attributes:
        phone: Phone OTP login enabled. Example: true
        email: Email OTP login enabled. Example: true
        password: Password login enabled. Example: false
        oauth: Enabled OAuth providers. Example: []
        sso: SSO login enabled. Example: true
        qr: QR code login enabled. Example: true
        passkey: Passkey/WebAuthn login enabled. Example: true
        magic_link: Magic link login enabled. Example: true
    """
    phone: bool
    email: bool
    password: bool
    oauth: List[OAuthProviderInfo]
    sso: bool
    qr: bool
    passkey: bool
    magic_link: bool


@dataclass
class AuthCapabilities:
    """Auth method availability for this deployment.

    Attributes:
        registration: Available registration methods.
        login: Available login methods.
    """
    registration: RegistrationCapabilities
    login: LoginCapabilities
