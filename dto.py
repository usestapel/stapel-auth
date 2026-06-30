"""Backward-compatibility shim — imports from sub-packages."""
from dataclasses import dataclass
from typing import Optional

# ── Sessions DTOs ─────────────────────────────────────────────────────────────
from stapel_auth.sessions.dto import (
    AuthStatus,
    TokenPairResponse,
    AuthResponse,
    TokenVerifyResponse,
    LogoutResponse,
    SessionResponse,
)

# ── OTP DTOs ──────────────────────────────────────────────────────────────────
from stapel_auth.otp.dto import (
    OtpSentResponse,
    InstantRequestOldResponse,
    InstantVerifyOldResponse,
    InstantRequestNewResponse,
    DelayedInitiateResponse,
    DelayedStatusResponse,
    DelayedCancelResponse,
)

# ── OAuth DTOs ────────────────────────────────────────────────────────────────
from stapel_auth.oauth.dto import (
    OAuthProviderInfo,
    RegistrationCapabilities,
    LoginCapabilities,
    AuthCapabilities,
)

# ── Password DTOs ─────────────────────────────────────────────────────────────
from stapel_auth.password.dto import (
    PasswordMethodType,
    PasswordMethod,
    PasswordMethodsResponse,
    PasswordRegisterRequest,
)

# ── MFA (TOTP + Passkey) DTOs ─────────────────────────────────────────────────
from stapel_auth.mfa.dto import (
    TOTPChallengeStatus,
    TOTPChallengeResponse,
    TOTPSetupResponse,
    TOTPSetupConfirmResponse,
    TOTPStepUpResponse,
    PasskeyDTO,
    PasskeyListDTO,
    PasskeyRegisterBeginDTO,
    PasskeyAuthBeginDTO,
)

# ── QR DTOs ───────────────────────────────────────────────────────────────────
from stapel_auth.qr.dto import (
    QRType,
    QRStatus,
    QRGenerateResponse,
    QRStatusResponse,
)

# ── Security DTOs ─────────────────────────────────────────────────────────────
from stapel_auth.security.dto import (
    AuditLogEntryDTO,
    AuditLogListDTO,
    SecurityStatusPassword,
    SecurityStatusTOTP,
    SecurityStatusContact,
    SecurityStatusOAuth,
    SecurityStatusSessions,
    SecurityStatusPasskeys,
    SecurityStatusResponse,
)

# ── Admin DTOs ────────────────────────────────────────────────────────────────
from stapel_auth.admin.dto import (
    AdminUserCreateRequest,
    AdminUserCreateResponse,
)


# ── DTOs not yet split into sub-packages ─────────────────────────────────────


@dataclass
class SimpleStatusResponse:
    """
    Generic operation status acknowledgment.

    Attributes:
        status: Short status key describing the completed action. Example: ok
    """
    status: str


@dataclass
class MagicLinkRequestDTO:
    """
    Response to magic link request.

    Attributes:
        message: Status message. Example: If this email is registered, a login link has been sent.
    """
    message: str
