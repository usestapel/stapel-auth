"""Data Transfer Objects for the admin sub-package."""
from dataclasses import dataclass
from typing import Optional


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
