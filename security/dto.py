"""Data Transfer Objects for the security sub-package (audit log, security status)."""
from dataclasses import dataclass
from typing import Optional


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
