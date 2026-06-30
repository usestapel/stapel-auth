"""Magic link DTOs."""
from dataclasses import dataclass


@dataclass
class MagicLinkRequestDTO:
    """
    Response to magic link request.

    Attributes:
        message: Status message. Example: If this email is registered, a login link has been sent.
    """
    message: str


# =============================================================================
# Passkey DTOs
# =============================================================================
