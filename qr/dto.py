"""Data Transfer Objects for QR auth domain."""
from dataclasses import dataclass
from enum import Enum
from typing import Optional


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
