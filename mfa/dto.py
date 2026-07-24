"""Data Transfer Objects for MFA (TOTP and Passkey) domain."""
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from stapel_auth.sessions.dto import TokenPairResponse


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
        tokens: Full-session JWT pair, present ONLY when the confirmation was made from a limited enroll-only session (first-login mfa_enroll policy) — activating the strong factor upgrades it to a full session. Null otherwise.
    """
    backup_codes: list
    tokens: Optional[TokenPairResponse] = None


class MfaEnrollSessionStatus(str, Enum):
    """
    Status value for the enroll-session exchange response.

    Members:
        MFA_ENROLL_SESSION: A limited enroll-only session was issued (JWT claim enroll_only) — only TOTP setup/confirm, passkey registration and logout are allowed until a strong factor is activated.
    """
    MFA_ENROLL_SESSION = 'MFA_ENROLL_SESSION'


@dataclass
class MfaEnrollSessionResponse:
    """
    Limited enroll-only session minted from a first-login mfa_enroll
    challenge (workspaces-org-program §C2).

    Access-token only — deliberately NO refresh token: a refresh would mint
    a claim-free (full) access token, silently escalating the limited
    session. When the token expires mid-enrollment the user simply logs in
    again for a fresh challenge.

    Attributes:
        status: Always MFA_ENROLL_SESSION. Example: MFA_ENROLL_SESSION
        access: JWT access token carrying the enroll_only claim. Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        expires_in: Seconds until the enroll session expires. Example: 3600
    """
    status: MfaEnrollSessionStatus
    access: str
    expires_in: int



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
