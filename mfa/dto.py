"""Data Transfer Objects for MFA (TOTP and Passkey) domain."""
from dataclasses import dataclass
from enum import Enum
from typing import Optional


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
