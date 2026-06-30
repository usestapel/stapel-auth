"""DTOs for the password authentication domain."""
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List


class PasswordMethodType(str, Enum):
    """
    Method for password change or reset.

    Members:
        PASSWORD: Change via the current (old) password.
        EMAIL: Change via OTP sent to the verified email.
        PHONE: Change via OTP sent to the verified phone.
        TOTP: Change via TOTP authenticator app code.
    """
    PASSWORD = 'password'
    EMAIL = 'email'
    PHONE = 'phone'
    TOTP = 'totp'


@dataclass
class PasswordMethod:
    """
    A single available password change / reset method.

    Attributes:
        method: Method identifier. Example: email
        target: Masked contact (email/phone) for otp-based methods. Example: u***@example.com
    """
    method: PasswordMethodType
    target: Optional[str] = None


@dataclass
class PasswordMethodsResponse:
    """
    Available methods for changing or resetting the password.

    Attributes:
        has_password: Whether the account already has a password set. Example: true
        methods: List of available change methods.
    """
    has_password: bool
    methods: List[PasswordMethod]


@dataclass
class PasswordRegisterRequest:
    """Password-based registration. At least one of email/phone/username required.

    Attributes:
        password: User password, minimum 8 characters. Example: secure_pass_123
        email: Email identifier. Example: user@example.com
        phone: Phone in E.164 format. Example: +79001234567
        username: Arbitrary username. Example: alice
    """
    password: str
    email: Optional[str] = None
    phone: Optional[str] = None
    username: Optional[str] = None
