"""
Data Transfer Objects for OTP authentication flows and authenticator change flows.
"""
from dataclasses import dataclass
from typing import Optional, List


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
