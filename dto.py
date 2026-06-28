"""Data Transfer Objects for authentication API."""
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, List


class AuthStatus(str, Enum):
    """
    Authentication status enum for verify endpoints.

    Members:
        REGISTERED: New account created or anonymous completed registration.
        LOGGED_IN: Existing user logged in.
        MERGED: Anonymous user merged into existing account.
        REJECTED: Invalid code, expired code, or validation error.
        MODIFIED: Authenticated user added or changed email/phone.
    """
    REJECTED = 'REJECTED'
    REGISTERED = 'REGISTERED'
    LOGGED_IN = 'LOGGED_IN'
    MERGED = 'MERGED'
    MODIFIED = 'MODIFIED'


@dataclass
class TokenPairResponse:
    """
    JWT token pair for authentication.

    Attributes:
        refresh: JWT refresh token. Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        access: JWT access token. Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    """
    refresh: str
    access: str


@dataclass
class AuthResponse:
    """
    Authentication response with user data and tokens.

    Attributes:
        status: Authentication outcome. Example: LOGGED_IN
        user: Authenticated user object.
        tokens: JWT token pair.
    """
    status: AuthStatus
    user: Any
    tokens: TokenPairResponse


@dataclass
class TokenVerifyResponse:
    """
    Token verification response.

    Attributes:
        valid: Whether the token is valid. Example: true
        user: User associated with the token.
    """
    valid: bool
    user: Any


@dataclass
class OtpSentResponse:
    """
    OTP has been sent to the target.

    Attributes:
        message: Confirmation message. Example: Verification code sent
        target: Masked email or phone where OTP was sent. Example: u***@example.com
    """
    message: str
    target: str


@dataclass
class LogoutResponse:
    """
    Logout confirmation.

    Attributes:
        message: Logout confirmation message. Example: Successfully logged out
    """
    message: str


@dataclass
class InstantRequestOldResponse:
    """
    OTP sent to current authenticator for instant change.

    Attributes:
        message: Confirmation message. Example: Verification code sent
        masked_target: Masked current email or phone. Example: u***@example.com
    """
    message: str
    masked_target: str


@dataclass
class InstantVerifyOldResponse:
    """
    Current authenticator verified, change token issued.

    Attributes:
        status: Always OLD_VERIFIED. Example: OLD_VERIFIED
        change_token: Token to authorize the change, pass to verify-new. Example: ctk_abc123
        expires_at: ISO 8601 expiration time for the change token. Example: 2025-01-15T12:00:00Z
    """
    status: str
    change_token: str
    expires_at: str


@dataclass
class InstantRequestNewResponse:
    """
    OTP sent to new authenticator.

    Attributes:
        message: Confirmation message. Example: Verification code sent to new address
    """
    message: str


@dataclass
class DelayedInitiateResponse:
    """
    Delayed change request created.

    Attributes:
        status: Always PENDING. Example: PENDING
        change_request_id: UUID of the change request. Example: 550e8400-e29b-41d4-a716-446655440000
        new_value_masked: Masked new email or phone. Example: n***@example.com
        scheduled_at: ISO 8601 date when the change will be applied. Example: 2025-01-22T00:00:00Z
        can_cancel_until: ISO 8601 deadline to cancel the change. Example: 2025-01-20T00:00:00Z
    """
    status: str
    change_request_id: str
    new_value_masked: str
    scheduled_at: str
    can_cancel_until: str


@dataclass
class DelayedStatusResponse:
    """
    Status of pending delayed change.

    Attributes:
        has_pending_change: Whether there is a pending change. Example: true
        change_request_id: UUID of the pending change request. Example: 550e8400-e29b-41d4-a716-446655440000
        type: Change type: email or phone. Example: email
        new_value_masked: Masked new value. Example: n***@example.com
        created_at: ISO 8601 creation time. Example: 2025-01-15T12:00:00Z
        scheduled_at: ISO 8601 scheduled execution time. Example: 2025-01-22T00:00:00Z
        days_remaining: Days until the change is applied. Example: 5
        notifications_sent: List of notification types already sent.
    """
    has_pending_change: bool
    change_request_id: Optional[str] = None
    type: Optional[str] = None
    new_value_masked: Optional[str] = None
    created_at: Optional[str] = None
    scheduled_at: Optional[str] = None
    days_remaining: Optional[int] = None
    notifications_sent: Optional[List[str]] = None


@dataclass
class DelayedCancelResponse:
    """
    Delayed change cancelled.

    Attributes:
        status: Always CANCELLED. Example: CANCELLED
        message: Cancellation confirmation message. Example: Change request cancelled
    """
    status: str
    message: str


# ── Password ─────────────────────────────────────────────────────────────────


class PasswordMethodType(str, Enum):
    """
    Method for password change or reset.

    Members:
        PASSWORD: Change via the current (old) password.
        EMAIL: Change via OTP sent to the verified email.
        PHONE: Change via OTP sent to the verified phone.
        TOTP: Change via TOTP authenticator app code.
    """
    PASSWORD = 'password'
    EMAIL = 'email'
    PHONE = 'phone'
    TOTP = 'totp'


@dataclass
class PasswordMethod:
    """
    A single available password change / reset method.

    Attributes:
        method: Method identifier. Example: email
        target: Masked contact (email/phone) for otp-based methods. Example: u***@example.com
    """
    method: PasswordMethodType
    target: Optional[str] = None


@dataclass
class PasswordMethodsResponse:
    """
    Available methods for changing or resetting the password.

    Attributes:
        has_password: Whether the account already has a password set. Example: true
        methods: List of available change methods.
    """
    has_password: bool
    methods: List[PasswordMethod]


# ── TOTP ─────────────────────────────────────────────────────────────────────


class TOTPChallengeStatus(str, Enum):
    """
    Status value for the TOTP challenge response.

    Members:
        TOTP_REQUIRED: Login succeeded but TOTP verification is needed to complete it.
    """
    TOTP_REQUIRED = 'TOTP_REQUIRED'


@dataclass
class TOTPChallengeResponse:
    """
    Intermediate response when TOTP 2FA is required to complete login.

    Attributes:
        status: Always TOTP_REQUIRED. Example: TOTP_REQUIRED
        challenge_token: Opaque token to pass to /totp/challenge/verify/. Example: abc123xyz
        expires_in: Seconds until the challenge expires. Example: 300
    """
    status: TOTPChallengeStatus
    challenge_token: str
    expires_in: int


# ── QR Auth ──────────────────────────────────────────────────────────────────


class QRType(str, Enum):
    """
    QR auth code type.

    Members:
        SESSION_SHARE: Logged-in user shares their session to another device.
        LOGIN_REQUEST: Unauthenticated device requests approval from a logged-in scanner.
    """
    SESSION_SHARE = 'session_share'
    LOGIN_REQUEST = 'login_request'


class QRStatus(str, Enum):
    """
    QR auth key lifecycle status.

    Members:
        PENDING: Waiting for scan or confirm.
        FULFILLED: Action completed; tokens available for login_request.
        EXPIRED: Key not found (TTL elapsed).
        REJECTED: Scanner or confirmer explicitly rejected the request.
    """
    PENDING = 'pending'
    FULFILLED = 'fulfilled'
    EXPIRED = 'expired'
    REJECTED = 'rejected'


@dataclass
class QRGenerateResponse:
    """
    Generated QR auth key.

    Attributes:
        key: Short-lived Redis key (5 min TTL). Example: abc123xyz
        type: QR type. Example: session_share
        expires_in: Seconds until the key expires. Example: 300
        scan_url: The URL to encode inside the QR image. When a phone camera scans the QR code it opens this URL on the scanner's device, which triggers the auth flow. Pass this to your QR-code renderer (e.g. qrcode.js). Example: https://app.example.com/auth/api/qr/abc123xyz/scan/
    """
    key: str
    type: QRType
    expires_in: int
    scan_url: str


@dataclass
class QRStatusResponse:
    """
    Current status of a QR auth key.

    Attributes:
        status: Key lifecycle status. Example: pending
        access_token: Issued access token (login_request fulfilled only). Example: eyJ...
        refresh_token: Issued refresh token (login_request fulfilled only). Example: eyJ...
    """
    status: QRStatus
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None


# =============================================================================
# Audit Log DTOs
# =============================================================================

@dataclass
class AuditLogEntryDTO:
    """
    Single audit log entry.

    Attributes:
        id: Entry UUID. Example: 550e8400-e29b-41d4-a716-446655440000
        event_type: Type of security event. Example: login_success
        ip_address: Client IP address. Example: 95.24.17.5
        user_agent: Client user agent. Example: Mozilla/5.0 ...
        metadata: Additional context. Example: {}
        created_at: Event timestamp. Example: 2026-06-19T12:00:00Z
    """
    id: str
    event_type: str
    ip_address: Optional[str]
    user_agent: str
    metadata: dict
    created_at: str


@dataclass
class AuditLogListDTO:
    """
    Paginated audit log response.

    Attributes:
        results: List of audit log entries.
        count: Total entry count. Example: 42
        next: Next page URL or null. Example: null
    """
    results: list
    count: int
    next: Optional[str]


# =============================================================================
# Magic Link DTOs
# =============================================================================

@dataclass
class MagicLinkRequestDTO:
    """
    Response to magic link request.

    Attributes:
        message: Status message. Example: If this email is registered, a login link has been sent.
    """
    message: str


# =============================================================================
# Passkey DTOs
# =============================================================================

@dataclass
class PasskeyDTO:
    """
    Passkey credential summary.

    Attributes:
        id: Passkey UUID. Example: 550e8400-e29b-41d4-a716-446655440000
        device_name: Human-readable device name. Example: Touch ID
        aaguid: Authenticator AAGUID (device type identifier). Example: adce0002-35bc-c60a-648b-0b25f1f05503
        transports: Supported transports. Example: ["internal"]
        created_at: Registration timestamp. Example: 2026-06-19T12:00:00Z
        last_used_at: Last use timestamp. Example: 2026-06-19T12:00:00Z
    """
    id: str
    device_name: str
    aaguid: str
    transports: list
    created_at: str
    last_used_at: Optional[str]


@dataclass
class PasskeyListDTO:
    """
    List of registered passkeys.

    Attributes:
        passkeys: Registered passkeys.
    """
    passkeys: list


@dataclass
class PasskeyRegisterBeginDTO:
    """
    WebAuthn registration options (pass to navigator.credentials.create).

    Attributes:
        options: PublicKeyCredentialCreationOptions JSON.
    """
    options: dict


@dataclass
class PasskeyAuthBeginDTO:
    """
    WebAuthn authentication options (pass to navigator.credentials.get).

    Attributes:
        session_key: Opaque key to include in authenticate/complete.
        options: PublicKeyCredentialRequestOptions JSON.
    """
    session_key: str
    options: dict


# =============================================================================
# Security Status DTOs
# =============================================================================

@dataclass
class SecurityStatusPassword:
    """
    Password authentication status.

    Attributes:
        is_set: Whether a password is set on the account. Example: true
    """
    is_set: bool


@dataclass
class SecurityStatusTOTP:
    """
    TOTP authenticator status.

    Attributes:
        is_enabled: Whether TOTP is active. Example: true
        backup_codes_remaining: How many unused backup codes are left. Example: 6
    """
    is_enabled: bool
    backup_codes_remaining: int


@dataclass
class SecurityStatusContact:
    """
    Masked contact (email or phone) with verification state.

    Attributes:
        value: Masked contact value, null if not set. Example: u***@example.com
        is_verified: Whether contact has been verified. Example: true
    """
    value: Optional[str]
    is_verified: bool


@dataclass
class SecurityStatusOAuth:
    """
    OAuth connections.

    Attributes:
        connected_providers: List of connected OAuth provider IDs. Example: ["google"]
    """
    connected_providers: list


@dataclass
class SecurityStatusSessions:
    """
    Active session summary.

    Attributes:
        active_count: Number of currently active sessions. Example: 3
    """
    active_count: int


@dataclass
class SecurityStatusPasskeys:
    """
    Passkey summary.

    Attributes:
        count: Number of registered passkeys. Example: 1
    """
    count: int


@dataclass
class SecurityStatusResponse:
    """
    Full security posture for the current user.

    Attributes:
        password: Password authentication status.
        totp: TOTP authenticator status.
        email: Email contact status.
        phone: Phone contact status.
        oauth: OAuth connections.
        sessions: Active session summary.
        passkeys: Registered passkeys summary.
    """
    password: SecurityStatusPassword
    totp: SecurityStatusTOTP
    email: SecurityStatusContact
    phone: SecurityStatusContact
    oauth: SecurityStatusOAuth
    sessions: SecurityStatusSessions
    passkeys: SecurityStatusPasskeys


# =============================================================================
# TOTP setup DTOs
# =============================================================================

@dataclass
class TOTPSetupResponse:
    """
    TOTP enrollment data — pass to authenticator app.

    Attributes:
        secret: Base32 TOTP secret for manual entry. Example: JBSWY3DPEHPK3PXP
        qr_uri: otpauth URI suitable for QR code display. Example: otpauth://totp/Iron:user@example.com?secret=...
        expires_in: Seconds until setup session expires. Example: 300
    """
    secret: str
    qr_uri: str
    expires_in: int


@dataclass
class TOTPSetupConfirmResponse:
    """
    Result of confirming TOTP setup. Store backup codes securely.

    Attributes:
        backup_codes: One-time backup codes. Each usable once if authenticator is lost. Example: ["12345678", "87654321"]
    """
    backup_codes: list


@dataclass
class TOTPStepUpResponse:
    """
    Issued step-up token after TOTP verification.

    Attributes:
        step_up_token: Opaque token proving recent TOTP verification. Example: su_abc123
        expires_in: Seconds until the step-up token expires. Example: 300
    """
    step_up_token: str
    expires_in: int


@dataclass
class SimpleStatusResponse:
    """
    Generic operation status acknowledgment.

    Attributes:
        status: Short status key describing the completed action. Example: ok
    """
    status: str


# =============================================================================
# Session DTOs
# =============================================================================

# =============================================================================
# Auth Capabilities DTOs
# =============================================================================


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


# =============================================================================
# Password Registration DTOs
# =============================================================================


@dataclass
class PasswordRegisterRequest:
    """Password-based registration. At least one of email/phone/username required.

    Attributes:
        password: User password, minimum 8 characters. Example: secure_pass_123
        email: Email identifier. Example: user@example.com
        phone: Phone in E.164 format. Example: +79001234567
        username: Arbitrary username. Example: alice
    """
    password: str
    email: Optional[str] = None
    phone: Optional[str] = None
    username: Optional[str] = None


# =============================================================================
# Admin Broker DTOs
# =============================================================================


@dataclass
class AdminUserCreateRequest:
    """Create a user via admin broker, bypassing OTP verification.

    Attributes:
        email: User email. Example: user@example.com
        phone: Phone in E.164 format. Example: +79001234567
        username: Username. Example: alice
        display_name: Display name. Example: Alice
        password: Initial password (optional). Example: secure123
        send_welcome: Send welcome notification via notification service. Example: false
        mark_verified: Mark email/phone as verified immediately. Example: true
    """
    email: Optional[str] = None
    phone: Optional[str] = None
    username: Optional[str] = None
    display_name: Optional[str] = None
    password: Optional[str] = None
    send_welcome: bool = False
    mark_verified: bool = True


@dataclass
class AdminUserCreateResponse:
    """Created user summary.

    Attributes:
        user_id: Created user UUID. Example: 550e8400-e29b-41d4-a716-446655440000
        email: User email. Example: user@example.com
        phone: User phone. Example: +79001234567
        username: Username. Example: alice
    """
    user_id: str
    email: Optional[str]
    phone: Optional[str]
    username: Optional[str]


@dataclass
class SessionResponse:
    """
    Active user session.

    Attributes:
        id: Session UUID. Example: 550e8400-e29b-41d4-a716-446655440000
        device_type: Device category for icon rendering. Example: phone
        device_name: Human-readable name. Example: Chrome 120 on Android 14
        device_details: Extra detail (model, OS version). Example: Pixel 7
        ip_address: Client IP address. Example: 95.24.17.5
        created_at: Session creation timestamp. Example: 2026-06-19T12:00:00Z
        last_used_at: Last activity timestamp. Example: 2026-06-19T12:00:00Z
        is_current: Whether this is the caller's current session. Example: true
        is_suspicious: Whether login was flagged as suspicious. Example: false
    """
    id: str
    device_type: str
    device_name: str
    device_details: str
    ip_address: Optional[str]
    created_at: str
    last_used_at: str
    is_current: bool
    is_suspicious: bool
