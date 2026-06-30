"""Backward-compatibility shim — imports from sub-packages."""
from dataclasses import dataclass

from stapel_auth.sessions.dto import AuthResponse, AuthStatus, TokenPairResponse  # noqa: F401
from stapel_auth.otp.dto import OtpSentResponse  # noqa: F401
from stapel_auth.mfa.dto import TOTPChallengeResponse, TOTPChallengeStatus  # noqa: F401


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
