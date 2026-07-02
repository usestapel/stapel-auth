"""Data Transfer Objects for the step-up verification endpoints."""
from dataclasses import dataclass, field


@dataclass
class VerificationChallengeInfoResponse:
    """
    Step-up verification challenge as seen by its owner.

    Attributes:
        challenge_id: Challenge identifier from the 403 envelope. Example: chg_abc123
        scope: Scope of the protected action the challenge guards. Example: payout
        factors: Interchangeable factors this user can actually complete. Example: ["otp_email", "totp"]
        expires_at: Unix timestamp when the challenge expires. Example: 1750000000
    """
    challenge_id: str
    scope: str
    factors: list
    expires_at: int


@dataclass
class VerificationInitiateResponse:
    """
    Result of initiating a verification factor.

    Attributes:
        factor: The factor that was initiated. Example: otp_email
        data: Factor-specific client data — masked destination for OTP factors, WebAuthn request options (with session_key) for passkey. Example: {"target": "u***@example.com"}
    """
    factor: str
    data: dict = field(default_factory=dict)


@dataclass
class VerificationCompleteResponse:
    """
    Successful completion of a verification challenge.

    Attributes:
        verified: Always true on success. Example: True
        verification_token: Stateless proof of verification — send as X-Verification-Token when retrying the original request (the grant is also stored server-side). Example: vt_abc123
    """
    verified: bool
    verification_token: str


@dataclass
class VerificationPreferenceRow:
    """
    One step-up verification preference of the current user.

    Attributes:
        scope: Verification scope the preference applies to. Example: wallet.withdraw
        enabled: Whether step-up is enabled for this scope — False turns a default_on scope off, True turns an opt_in scope on. Example: false
    """
    scope: str
    enabled: bool


@dataclass
class VerificationPreferencesResponse:
    """
    The current user's step-up verification preferences.

    Attributes:
        preferences: Preference rows, one per scope the user has touched — scopes without a row follow the endpoint's level default. Example: [{"scope": "wallet.withdraw", "enabled": false}]
    """
    preferences: list[VerificationPreferenceRow] = field(default_factory=list)
