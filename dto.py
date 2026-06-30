"""Backward-compatibility shim — imports from sub-packages."""
from dataclasses import dataclass

# ── Sessions DTOs ─────────────────────────────────────────────────────────────

# ── OTP DTOs ──────────────────────────────────────────────────────────────────

# ── OAuth DTOs ────────────────────────────────────────────────────────────────

# ── Password DTOs ─────────────────────────────────────────────────────────────

# ── MFA (TOTP + Passkey) DTOs ─────────────────────────────────────────────────

# ── QR DTOs ───────────────────────────────────────────────────────────────────

# ── Security DTOs ─────────────────────────────────────────────────────────────

# ── Admin DTOs ────────────────────────────────────────────────────────────────


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
