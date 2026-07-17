"""Custom error keys for the auth service."""

from stapel_core.django.api.errors import ErrorKeysView, register_service_errors, format_duration

ERR_401_INVALID_CREDENTIALS = 'error.401.invalid_credentials'
ERR_401_ACCOUNT_DISABLED = 'error.401.account_disabled'
ERR_422_BLOCKED = 'error.422.blocked'
ERR_400_CODE_EXPIRED = 'error.400.code_expired'
ERR_400_INVALID_CODE = 'error.400.invalid_code'
ERR_400_INVALID_CODE_ATTEMPTS = 'error.400.invalid_code_attempts'
ERR_500_SEND_FAILED = 'error.500.send_failed'
ERR_409_EMAIL_TAKEN = 'error.409.email_taken'
ERR_409_EMAIL_RESERVED = 'error.409.email_reserved'
ERR_409_PHONE_TAKEN = 'error.409.phone_taken'
ERR_409_PHONE_RESERVED = 'error.409.phone_reserved'
ERR_409_USERNAME_TAKEN = 'error.409.username_taken'
ERR_400_TOKEN_REQUIRED = 'error.400.token_required'
ERR_401_TOKEN_REVOKED = 'error.401.token_revoked'
ERR_401_TOKEN_INVALID = 'error.401.token_invalid'
ERR_400_OAUTH_FAILED = 'error.400.oauth_failed'
ERR_400_OAUTH_FIELDS_REQUIRED = 'error.400.oauth_fields_required'
ERR_400_CREDENTIALS_REQUIRED = 'error.400.credentials_required'
ERR_401_REFRESH_INVALID = 'error.401.refresh_invalid'
ERR_401_REFRESH_NOT_PROVIDED = 'error.401.refresh_not_provided'
ERR_401_REFRESH_REVOKED = 'error.401.refresh_revoked'
ERR_401_USER_NOT_FOUND = 'error.401.user_not_found'
ERR_400_NOT_AVAILABLE = 'error.400.not_available'
ERR_400_NO_CURRENT_VALUE = 'error.400.no_current_value'
ERR_400_INVALID_CHANGE_TOKEN = 'error.400.invalid_change_token'
ERR_404_CHANGE_NOT_FOUND = 'error.404.change_not_found'
ERR_400_PHONE_REQUIRED = 'error.400.phone_required'
ERR_400_EMAIL_REQUIRED = 'error.400.email_required'
ERR_400_INVALID_PHONE_FORMAT = 'error.400.invalid_phone_format'
ERR_400_INVALID_PHONE = 'error.400.invalid_phone'
ERR_400_PHONE_TOO_LONG = 'error.400.phone_too_long'
ERR_400_PASSWORDS_DONT_MATCH = 'error.400.passwords_dont_match'
ERR_400_EMAIL_OR_PHONE_REQUIRED = 'error.400.email_or_phone_required'
ERR_400_EMAIL_OR_PHONE_NOT_BOTH = 'error.400.email_or_phone_not_both'
# Password
ERR_400_WRONG_PASSWORD = 'error.400.wrong_password'
ERR_400_PASSWORD_ALREADY_SET = 'error.400.password_already_set'
ERR_400_NO_PASSWORD = 'error.400.no_password'
ERR_400_NO_VERIFIED_CONTACT = 'error.400.no_verified_contact'
ERR_400_INVALID_METHOD = 'error.400.invalid_method'
ERR_404_USER_FOR_RESET = 'error.404.user_for_reset'
ERR_403_MOCK_OTP_ADMIN = 'error.403.mock_otp_admin'
# QR auth
ERR_404_QR_NOT_FOUND = 'error.404.qr_not_found'
ERR_400_QR_EXPIRED = 'error.400.qr_expired'
ERR_400_QR_FULFILLED = 'error.400.qr_fulfilled'
ERR_400_QR_TYPE_REQUIRED = 'error.400.qr_type_required'
ERR_401_QR_AUTH_REQUIRED = 'error.401.qr_auth_required'
ERR_409_QR_ACCOUNT_CONFLICT = 'error.409.qr_account_conflict'
ERR_403_QR_DEVICE_MISMATCH = 'error.403.qr_device_mismatch'
ERR_403_QR_UNAUTH_SCAN = 'error.403.qr_unauth_scan'
# Sessions
ERR_404_NOT_FOUND = 'error.404.not_found'
# TOTP
ERR_400_CODE_REQUIRED = 'error.400.code_required'
ERR_400_TOTP_NOT_PENDING = 'error.400.totp_not_pending'
# Lockout
ERR_423_ACCOUNT_LOCKED = 'error.423.account_locked'
# Magic links
ERR_400_INVALID_REDIRECT_URL = 'error.400.invalid_redirect_url'
ERR_400_MAGIC_LINK_INVALID = 'error.400.magic_link_invalid'
ERR_429_MAGIC_LINK_RATE = 'error.429.magic_link_rate'
# Passkeys
ERR_400_PASSKEY_INVALID = 'error.400.passkey_invalid'
ERR_400_PASSKEY_CHALLENGE_EXPIRED = 'error.400.passkey_challenge_expired'
ERR_409_PASSKEY_ALREADY_REGISTERED = 'error.409.passkey_already_registered'
ERR_400_LAST_AUTH_METHOD = 'error.400.last_auth_method'
ERR_404_PASSKEY_NOT_FOUND = 'error.404.passkey_not_found'
# OAuth account links (security-profile inventory)
ERR_409_OAUTH_ALREADY_LINKED = 'error.409.oauth_already_linked'
ERR_409_OAUTH_ACCOUNT_LINKED_ELSEWHERE = 'error.409.oauth_account_linked_elsewhere'
ERR_404_OAUTH_LINK_NOT_FOUND = 'error.404.oauth_link_not_found'
# SSO
ERR_404_SSO_ORG_NOT_FOUND = 'error.404.sso_org_not_found'
ERR_400_SSO_NOT_CONFIGURED = 'error.400.sso_not_configured'
ERR_400_SSO_INVALID_RESPONSE = 'error.400.sso_invalid_response'
ERR_403_SSO_REQUIRED = 'error.403.sso_required'
ERR_409_SSO_ORG_SLUG_TAKEN = 'error.409.sso_org_slug_taken'
# Captcha
ERR_400_CAPTCHA_INVALID  = 'error.400.captcha_invalid'
ERR_400_CAPTCHA_REQUIRED = 'error.400.captcha_required'
# Staff roles (admin-suite AS-2)
ERR_400_UNKNOWN_STAFF_ROLE = 'error.400.unknown_staff_role'
ERR_400_STAFF_ROLE_TARGET_NOT_STAFF = 'error.400.staff_role_target_not_staff'

AUTH_ERRORS = {
    ERR_401_INVALID_CREDENTIALS: 'Invalid credentials',
    ERR_401_ACCOUNT_DISABLED: 'User account is disabled',
    ERR_422_BLOCKED: 'Account temporarily blocked. Try again in {retry_after_minutes} minutes.',
    ERR_400_CODE_EXPIRED: 'Verification code has expired. Please request a new one.',
    ERR_400_INVALID_CODE: 'Invalid verification code',
    ERR_400_INVALID_CODE_ATTEMPTS: 'Invalid verification code. {attempts_remaining} attempts remaining.',
    ERR_500_SEND_FAILED: 'Failed to send verification code',
    ERR_409_EMAIL_TAKEN: 'This email is already registered to another account.',
    ERR_409_EMAIL_RESERVED: 'This email is reserved by another pending change request.',
    ERR_409_PHONE_TAKEN: 'This phone number is already registered to another account.',
    ERR_409_PHONE_RESERVED: 'This phone number is reserved by another pending change request.',
    ERR_409_USERNAME_TAKEN: 'This username is already taken.',
    ERR_400_TOKEN_REQUIRED: 'Token is required',
    ERR_401_TOKEN_REVOKED: 'Token has been revoked',
    ERR_401_TOKEN_INVALID: 'Invalid token',
    ERR_400_OAUTH_FAILED: 'Failed to authenticate with OAuth provider',
    ERR_400_OAUTH_FIELDS_REQUIRED: 'Provider and access_token are required',
    ERR_400_CREDENTIALS_REQUIRED: 'Username/email and password are required',
    ERR_401_REFRESH_INVALID: 'Invalid or expired refresh token',
    ERR_401_REFRESH_NOT_PROVIDED: 'Refresh token not provided',
    ERR_401_REFRESH_REVOKED: 'Token has been revoked',
    ERR_401_USER_NOT_FOUND: 'User not found',
    ERR_400_NOT_AVAILABLE: 'This value is already registered or reserved.',
    ERR_400_NO_CURRENT_VALUE: 'No current value on this account.',
    ERR_400_INVALID_CHANGE_TOKEN: 'Invalid or expired change token.',
    ERR_404_CHANGE_NOT_FOUND: 'Change request not found.',
    ERR_400_PHONE_REQUIRED: 'Phone number is required.',
    ERR_400_EMAIL_REQUIRED: 'Email is required.',
    ERR_400_INVALID_PHONE_FORMAT: 'Invalid phone number format',
    ERR_400_INVALID_PHONE: 'Invalid phone number',
    ERR_400_PHONE_TOO_LONG: 'Phone number is too long',
    ERR_400_PASSWORDS_DONT_MATCH: "Password fields didn't match",
    ERR_400_EMAIL_OR_PHONE_REQUIRED: 'Either email or phone is required',
    ERR_400_EMAIL_OR_PHONE_NOT_BOTH: 'Provide either email or phone, not both',
    # Password
    ERR_400_WRONG_PASSWORD: 'Wrong password.',
    ERR_400_PASSWORD_ALREADY_SET: 'Password is already set. Use the change password flow.',
    ERR_400_NO_PASSWORD: 'No password is set. Use set password first.',
    ERR_400_NO_VERIFIED_CONTACT: 'No verified email or phone on this account.',
    ERR_400_INVALID_METHOD: 'Invalid or unavailable method for this account.',
    ERR_404_USER_FOR_RESET: 'No account found with this email or phone.',
    ERR_403_MOCK_OTP_ADMIN: 'OTP-based auth is disabled for admin accounts in mock mode.',
    # QR auth
    ERR_404_QR_NOT_FOUND: 'QR code not found or expired.',
    ERR_400_QR_EXPIRED: 'QR code has expired.',
    ERR_400_QR_FULFILLED: 'QR code has already been used.',
    ERR_400_QR_TYPE_REQUIRED: 'QR type is required (session_share or login_request).',
    ERR_401_QR_AUTH_REQUIRED: 'Authentication required to generate a session_share QR code.',
    ERR_409_QR_ACCOUNT_CONFLICT: 'A different account is already signed in on this device.',
    ERR_403_QR_DEVICE_MISMATCH: 'This QR code belongs to another device.',
    ERR_403_QR_UNAUTH_SCAN: 'This QR code cannot be scanned by an unauthenticated device.',
    # Sessions
    ERR_404_NOT_FOUND: 'Not found.',
    # TOTP
    ERR_400_CODE_REQUIRED: 'A verification code is required.',
    ERR_400_TOTP_NOT_PENDING: 'No pending TOTP setup. Call /totp/setup/ first.',
    # Lockout
    ERR_423_ACCOUNT_LOCKED: 'Account temporarily locked due to too many failed attempts. Try again in {retry_after_minutes} minutes.',
    ERR_400_INVALID_REDIRECT_URL: 'redirect_url must be a relative path starting with /  — absolute URLs are not allowed.',
    # Magic links
    ERR_400_MAGIC_LINK_INVALID: 'Magic link is invalid or has expired.',
    ERR_429_MAGIC_LINK_RATE: 'Too many magic link requests. Please try again later.',
    # Passkeys
    ERR_400_PASSKEY_INVALID: 'Passkey verification failed.',
    ERR_400_PASSKEY_CHALLENGE_EXPIRED: 'Passkey challenge has expired. Please try again.',
    ERR_409_PASSKEY_ALREADY_REGISTERED: 'This passkey is already registered.',
    ERR_400_LAST_AUTH_METHOD: 'Cannot remove the last authentication method.',
    ERR_404_PASSKEY_NOT_FOUND: 'Passkey not found.',
    # OAuth account links
    ERR_409_OAUTH_ALREADY_LINKED: 'This provider is already linked to your account.',
    ERR_409_OAUTH_ACCOUNT_LINKED_ELSEWHERE: 'This provider account is already linked to a different user.',
    ERR_404_OAUTH_LINK_NOT_FOUND: 'No linked account found for this provider.',
    # SSO
    ERR_404_SSO_ORG_NOT_FOUND: 'Organization not found.',
    ERR_400_SSO_NOT_CONFIGURED: 'SSO is not configured for this organization.',
    ERR_400_SSO_INVALID_RESPONSE: 'Invalid SSO response from identity provider.',
    ERR_403_SSO_REQUIRED: 'This account must sign in via SSO. Use your organization SSO link.',
    ERR_409_SSO_ORG_SLUG_TAKEN: 'An organization with this slug already exists.',
    # Captcha
    ERR_400_CAPTCHA_INVALID:  'Captcha verification failed. Please try again.',
    ERR_400_CAPTCHA_REQUIRED: 'Captcha token is required.',
    # Staff roles
    ERR_400_UNKNOWN_STAFF_ROLE: 'Unknown staff role. Define it in the STAPEL_ACCESS["ROLES"] deploy config first.',
    ERR_400_STAFF_ROLE_TARGET_NOT_STAFF: 'Staff roles can only be assigned to staff accounts. Make the user staff first.',
}

# Machine-readable recovery hints (remediation) — the canonical "what to do"
# for each key, emitted into the errors.json codegen artifact and consumed by the
# frontend/LLM (frontend-core-architecture §2.5). Vocabulary: retry |
# wait_and_retry | reauthenticate | verify | fix_input | contact_support | bug.
# Declared here (backend = canon) rather than left to the status+name heuristic —
# several keys need intent the heuristic gets wrong (oauth/captcha/passkey
# ceremonies are retryable, not fix_input; a disabled account or unconfigured SSO
# needs support, not a re-login).
AUTH_REMEDIATION = {
    # Credentials / login
    ERR_401_INVALID_CREDENTIALS: 'reauthenticate',
    ERR_401_ACCOUNT_DISABLED: 'contact_support',
    ERR_422_BLOCKED: 'wait_and_retry',
    ERR_423_ACCOUNT_LOCKED: 'wait_and_retry',
    ERR_400_CREDENTIALS_REQUIRED: 'fix_input',
    ERR_400_WRONG_PASSWORD: 'fix_input',
    # OTP / verification codes
    ERR_400_CODE_EXPIRED: 'retry',
    ERR_400_INVALID_CODE: 'fix_input',
    ERR_400_INVALID_CODE_ATTEMPTS: 'fix_input',
    ERR_400_CODE_REQUIRED: 'fix_input',
    ERR_500_SEND_FAILED: 'retry',
    # OAuth
    ERR_400_OAUTH_FAILED: 'retry',
    ERR_400_OAUTH_FIELDS_REQUIRED: 'fix_input',
    # Tokens / refresh — session is gone, re-login
    ERR_400_TOKEN_REQUIRED: 'fix_input',
    ERR_401_TOKEN_REVOKED: 'reauthenticate',
    ERR_401_TOKEN_INVALID: 'reauthenticate',
    ERR_401_REFRESH_INVALID: 'reauthenticate',
    ERR_401_REFRESH_NOT_PROVIDED: 'reauthenticate',
    ERR_401_REFRESH_REVOKED: 'reauthenticate',
    ERR_401_USER_NOT_FOUND: 'reauthenticate',
    # Contact/username conflicts — pick a different value
    ERR_409_EMAIL_TAKEN: 'fix_input',
    ERR_409_EMAIL_RESERVED: 'fix_input',
    ERR_409_PHONE_TAKEN: 'fix_input',
    ERR_409_PHONE_RESERVED: 'fix_input',
    ERR_409_USERNAME_TAKEN: 'fix_input',
    # Contact change flow
    ERR_400_NOT_AVAILABLE: 'fix_input',
    ERR_400_NO_CURRENT_VALUE: 'fix_input',
    ERR_400_INVALID_CHANGE_TOKEN: 'retry',
    ERR_404_CHANGE_NOT_FOUND: 'retry',
    ERR_400_PHONE_REQUIRED: 'fix_input',
    ERR_400_EMAIL_REQUIRED: 'fix_input',
    ERR_400_INVALID_PHONE_FORMAT: 'fix_input',
    ERR_400_INVALID_PHONE: 'fix_input',
    ERR_400_PHONE_TOO_LONG: 'fix_input',
    ERR_400_PASSWORDS_DONT_MATCH: 'fix_input',
    ERR_400_EMAIL_OR_PHONE_REQUIRED: 'fix_input',
    ERR_400_EMAIL_OR_PHONE_NOT_BOTH: 'fix_input',
    # Password management
    ERR_400_PASSWORD_ALREADY_SET: 'fix_input',
    ERR_400_NO_PASSWORD: 'fix_input',
    ERR_400_NO_VERIFIED_CONTACT: 'verify',
    ERR_400_INVALID_METHOD: 'fix_input',
    ERR_404_USER_FOR_RESET: 'fix_input',
    ERR_403_MOCK_OTP_ADMIN: 'contact_support',
    # QR auth
    ERR_404_QR_NOT_FOUND: 'retry',
    ERR_400_QR_EXPIRED: 'retry',
    ERR_400_QR_FULFILLED: 'retry',
    ERR_400_QR_TYPE_REQUIRED: 'fix_input',
    ERR_401_QR_AUTH_REQUIRED: 'reauthenticate',
    ERR_409_QR_ACCOUNT_CONFLICT: 'reauthenticate',
    ERR_403_QR_DEVICE_MISMATCH: 'retry',
    ERR_403_QR_UNAUTH_SCAN: 'reauthenticate',
    # Sessions
    ERR_404_NOT_FOUND: 'retry',
    # TOTP
    ERR_400_TOTP_NOT_PENDING: 'retry',
    # Magic links
    ERR_400_INVALID_REDIRECT_URL: 'fix_input',
    ERR_400_MAGIC_LINK_INVALID: 'retry',
    ERR_429_MAGIC_LINK_RATE: 'wait_and_retry',
    # Passkeys — WebAuthn ceremonies are retryable
    ERR_400_PASSKEY_INVALID: 'retry',
    ERR_400_PASSKEY_CHALLENGE_EXPIRED: 'retry',
    ERR_409_PASSKEY_ALREADY_REGISTERED: 'fix_input',
    ERR_400_LAST_AUTH_METHOD: 'fix_input',
    ERR_404_PASSKEY_NOT_FOUND: 'retry',
    # OAuth account links
    ERR_409_OAUTH_ALREADY_LINKED: 'fix_input',
    ERR_409_OAUTH_ACCOUNT_LINKED_ELSEWHERE: 'fix_input',
    ERR_404_OAUTH_LINK_NOT_FOUND: 'retry',
    # SSO
    ERR_404_SSO_ORG_NOT_FOUND: 'fix_input',
    ERR_400_SSO_NOT_CONFIGURED: 'contact_support',
    ERR_400_SSO_INVALID_RESPONSE: 'retry',
    ERR_403_SSO_REQUIRED: 'reauthenticate',
    ERR_409_SSO_ORG_SLUG_TAKEN: 'fix_input',
    # Captcha — re-solve, not a form field to fix
    ERR_400_CAPTCHA_INVALID: 'retry',
    ERR_400_CAPTCHA_REQUIRED: 'retry',
    # Staff roles — an unknown role means the deploy config lacks it, an
    # operator input problem in both cases
    ERR_400_UNKNOWN_STAFF_ROLE: 'fix_input',
    ERR_400_STAFF_ROLE_TARGET_NOT_STAFF: 'fix_input',
}

register_service_errors(AUTH_ERRORS, remediation=AUTH_REMEDIATION)


def retry_params(retry_after):
    """Build params with retry_after (seconds), minutes, and display."""
    import math
    seconds = int(retry_after or 0)
    minutes = max(1, math.ceil(seconds / 60))
    return {'retry_after': seconds, 'retry_after_minutes': minutes, 'retry_after_display': format_duration(seconds)}


class AuthErrorKeysView(ErrorKeysView):
    def get_service_errors(self):
        return AUTH_ERRORS
