"""Data Transfer Objects for the sessions sub-package."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


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


#: One user as ``UserSerializer`` answers it — the contract examples of every
#: body that carries a user (AuthResponse, TokenVerifyResponse, LoginResponse)
#: use it, so an example cannot drop a required field again
#: (tests/test_contract_examples.py validates every example against its schema).
USER_EXAMPLE = {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "user_550e8400",
    "email": "user@example.com",
    "phone": None,
    "auth_type": "email",
    "is_email_verified": True,
    "is_phone_verified": False,
    "is_anonymous": False,
    "is_staff": False,
    "is_superuser": False,
    "oauth_provider": None,
    "avatar": None,
    "bio": "",
    "created_at": "2026-06-19T12:00:00Z",
    "last_login": "2026-06-19T12:00:00Z",
    "onboarding_completed": False,
    "profile_completed": False,
}

TOKENS_EXAMPLE = {
    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
}


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
    user: Any = field(metadata={'example': USER_EXAMPLE})
    tokens: TokenPairResponse = field(metadata={'example': TOKENS_EXAMPLE})


@dataclass
class TokenVerifyResponse:
    """
    Token verification response.

    Attributes:
        valid: Whether the token is valid. Example: true
        user: User associated with the token.
    """
    valid: bool
    user: Any = field(metadata={'example': USER_EXAMPLE})


@dataclass
class LogoutResponse:
    """
    Logout confirmation.

    Attributes:
        message: Logout confirmation message. Example: Successfully logged out
    """
    message: str


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
    is_suspicious: bool = field(metadata={'example': False})
