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


class FirstLoginRequirement(str, Enum):
    """
    What the account must complete before a full session is issued
    (workspaces-org-program §C2 first-login policy).

    Members:
        PASSWORD_CHANGE: The org-set password must be replaced first — POST /password/forced-change/.
        MFA_ENROLL: A strong second factor must be enrolled first — POST /mfa/enroll/exchange/ for a limited enroll session.
    """
    PASSWORD_CHANGE = 'password_change'
    MFA_ENROLL = 'mfa_enroll'


class FirstLoginChallengeStatus(str, Enum):
    """
    Status value for the first-login challenge response.

    Members:
        FIRST_LOGIN_REQUIRED: Credentials were correct but a first-login step must be completed before a session is issued.
    """
    FIRST_LOGIN_REQUIRED = 'FIRST_LOGIN_REQUIRED'


@dataclass
class FirstLoginChallengeResponse:
    """
    Intermediate login response for org-provisioned accounts with a
    first-login policy flag (password_change_required /
    mfa_enrollment_required). Returned instead of a session.

    Attributes:
        status: Always FIRST_LOGIN_REQUIRED. Example: FIRST_LOGIN_REQUIRED
        requires: Which step to complete. Example: password_change
        challenge_token: Opaque single-flow token. Pass to /password/forced-change/ (password_change) or /mfa/enroll/exchange/ (mfa_enroll). Example: abc123xyz
        expires_in: Seconds until the challenge expires. Example: 600
    """
    status: FirstLoginChallengeStatus
    requires: FirstLoginRequirement
    challenge_token: str
    expires_in: int


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
