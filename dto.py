"""Cross-cutting DTOs shared by several sub-packages."""
from dataclasses import dataclass


@dataclass
class SimpleStatusResponse:
    """
    Generic operation status acknowledgment.

    Attributes:
        status: Short status key describing the completed action. Example: ok
    """
    status: str
