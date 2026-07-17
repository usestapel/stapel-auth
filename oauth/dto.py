"""Data Transfer Objects for OAuth and authentication capabilities."""
from dataclasses import dataclass
from typing import List, Optional


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
class LinkedOAuthAccountDTO:
    """One OAuth provider account connected to the current user.

    ``primary`` distinguishes the account a user originally registered/logged
    in with (``User.oauth_provider``/``oauth_id`` — immutable through this
    endpoint) from a secondary link the user attached later from their
    security settings page (an actual ``LinkedOAuthAccount`` row, removable
    via DELETE /oauth/links/{provider}/).

    Attributes:
        provider: Provider identifier. Example: google
        email: Email reported by the provider, if any. Example: user@example.com
        display_name: Provider display name/username, if any. Example: Jane Doe
        linked_at: When this account was linked. Example: 2026-07-16T12:00:00Z
        primary: Whether this is the account the user originally registered/
            logged in with (not unlinkable here). Example: false
    """
    provider: str
    email: Optional[str]
    display_name: str
    linked_at: Optional[str]
    primary: bool


@dataclass
class OAuthLinksResponse:
    """All OAuth accounts connected to the current user.

    Attributes:
        links: Connected provider accounts (primary first, then secondary
            links ordered most-recently-linked first).
    """
    links: List["LinkedOAuthAccountDTO"]


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
        email_mock: Email OTP delivery is mocked in this environment (the
            code is written to logs instead of actually sent) — purely
            informational, does not affect ``email`` above: a mocked channel
            is still enabled, just not really delivering. Lets a host
            frontend show a "dev mode" badge. Example: false
        phone_mock: Same as ``email_mock``, for phone/SMS OTP delivery.
            Example: false
    """
    phone: bool
    email: bool
    password: bool
    oauth: List[OAuthProviderInfo]
    sso: bool
    anonymous: bool
    email_mock: bool = False
    phone_mock: bool = False


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
        email_mock: Email OTP delivery is mocked in this environment (the
            code is written to logs instead of actually sent) — purely
            informational, does not affect ``email`` above: a mocked channel
            is still enabled, just not really delivering. Lets a host
            frontend show a "dev mode" badge. Example: false
        phone_mock: Same as ``email_mock``, for phone/SMS OTP delivery.
            Example: false
    """
    phone: bool
    email: bool
    password: bool
    oauth: List[OAuthProviderInfo]
    sso: bool
    qr: bool
    passkey: bool
    magic_link: bool
    email_mock: bool = False
    phone_mock: bool = False


@dataclass
class MFACapabilities:
    """Available multi-factor methods for this deployment.

    Attributes:
        totp: TOTP (authenticator app) MFA enabled. Example: true
        passkey: Passkey/WebAuthn enabled (also a login method). Example: true
    """
    totp: bool
    passkey: bool


@dataclass
class AuthMethodInfo:
    """Per-method display descriptor for the sign-in panel (owner directive:
    placement is configured on the backend the same way availability is).

    ``placement`` is configured per-method via ``AUTH_<METHOD>_PLACEMENT``
    (conf.py); ``order`` and ``interaction`` are derived server-side so the
    frontend never has to guess: ``interaction`` follows the client rule
    "main -> inline in the tab; overflow/bottom -> modal, except oauth/sso
    which always redirect to the provider".

    Attributes:
        id: Method identifier — one of email, phone, password, passkey, qr,
            magic_link, sso, oauth. Example: email
        enabled: Whether this method is currently available (mirrors the
            corresponding AUTH_*_LOGIN gate / oauth provider count). Example: true
        placement: Where the client renders this method's trigger. One of
            main (inline in the primary tab strip), overflow (behind the
            "more"/three-dot menu) or bottom (bottom row of secondary
            buttons). Example: main
        order: Sort order among methods sharing the same placement (lower
            first). Example: 0
        interaction: How the client should present the method once
            triggered. One of inline (render in place), modal (open a
            dialog) or redirect (navigate away, e.g. to an OAuth/SSO
            provider). Example: inline
        icon_svg: Inline SVG glyph for this method (24x24, currentColor) — a
            host frontend may render its own icon and ignore this field.
            Example: <svg>...</svg>
        mock: Whether this method's OTP delivery is mocked in this
            environment (code goes to logs, not a real email/SMS) rather
            than the channel being disabled — ``enabled`` already reflects
            true availability; this is additional transparency so a host
            frontend can show a "dev mode" badge next to email/phone. Always
            false for methods without an OTP delivery leg (password,
            passkey, qr, magic_link, sso, oauth). Example: false
    """
    id: str
    enabled: bool
    placement: str
    order: int
    interaction: str
    icon_svg: str
    mock: bool = False


@dataclass
class OtpMeta:
    """Server-authoritative OTP parameters — the frontend must read these
    instead of guessing (e.g. hardcoding a 6-box code input when the backend
    actually issues 4-digit codes).

    Every value here is sourced from the exact same constant/setting that
    the backend validates against (otp/services.py.OTP_CODE_LENGTH,
    mfa/services.py.TOTPService.CODE_LENGTH, AUTH_OTP_TTL, AUTH_OTP_RESEND_COOLDOWN)
    — a guard test asserts the DB/serializer field widths agree with the
    same constants, so this can't silently drift from what the server
    actually accepts.

    Attributes:
        email_code_length: Digits in an email OTP code. Example: 4
        phone_code_length: Digits in a phone/SMS OTP code. Example: 4
        totp_code_length: Digits in a TOTP authenticator-app code. Example: 6
        ttl_seconds: Seconds an OTP code stays valid after being sent. Example: 600
        resend_cooldown_seconds: Seconds the client must wait before requesting
            a new OTP code. Example: 30
    """
    email_code_length: int
    phone_code_length: int
    totp_code_length: int
    ttl_seconds: int
    resend_cooldown_seconds: int


@dataclass
class AuthCapabilities:
    """Auth method availability for this deployment.

    Attributes:
        registration: Available registration methods.
        login: Available login methods.
        mfa: Available multi-factor methods.
        methods: Per-method placement/interaction/icon descriptors for every
            login method (email, phone, password, passkey, qr, magic_link,
            sso, oauth) — the shape the sign-in panel is built from.
        otp: Server-authoritative OTP parameters (code lengths, ttl, resend
            cooldown) — see OtpMeta.
    """
    registration: RegistrationCapabilities
    login: LoginCapabilities
    mfa: MFACapabilities
    methods: List["AuthMethodInfo"]
    otp: "OtpMeta"
