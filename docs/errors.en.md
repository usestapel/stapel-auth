# Errors — English

`118` error keys. Canonical texts live in the code (`register_service_errors`); localized texts in `translations/errors.en.json`.

| Code | Status | Params | Remediation | Text |
|---|---|---|---|---|
| `error.400.bad_request` | 400 | — | `fix_input` | Bad request |
| `error.400.captcha_invalid` | 400 | — | `retry` | Captcha verification failed. Please try again. |
| `error.400.captcha_required` | 400 | — | `retry` | Captcha token is required. |
| `error.400.code_expired` | 400 | — | `retry` | Verification code has expired. Please request a new one. |
| `error.400.code_required` | 400 | — | `fix_input` | A verification code is required. |
| `error.400.credentials_required` | 400 | — | `fix_input` | Username/email and password are required |
| `error.400.email_or_phone_not_both` | 400 | — | `fix_input` | Provide either email or phone, not both |
| `error.400.email_or_phone_required` | 400 | — | `fix_input` | Either email or phone is required |
| `error.400.email_required` | 400 | — | `fix_input` | Email is required. |
| `error.400.expected_list` | 400 | — | `fix_input` | Expected a list of items |
| `error.400.field.blank` | 400 | `field` | `fix_input` | {field} may not be blank |
| `error.400.field.does_not_exist` | 400 | `field` | `fix_input` | {field} does not exist |
| `error.400.field.invalid` | 400 | `field` | `fix_input` | {field} is invalid |
| `error.400.field.invalid_choice` | 400 | `field` | `fix_input` | {field} is not a valid choice |
| `error.400.field.max_length` | 400 | `field`, `max_length` | `fix_input` | {field} must be at most {max_length} characters |
| `error.400.field.max_value` | 400 | `field`, `max_value` | `fix_input` | {field} must be at most {max_value} |
| `error.400.field.min_length` | 400 | `field`, `min_length` | `fix_input` | {field} must be at least {min_length} characters |
| `error.400.field.min_value` | 400 | `field`, `min_value` | `fix_input` | {field} must be at least {min_value} |
| `error.400.field.null` | 400 | `field` | `fix_input` | {field} may not be null |
| `error.400.field.required` | 400 | `field` | `fix_input` | {field} is required |
| `error.400.field.unique` | 400 | `field` | `fix_input` | {field} must be unique |
| `error.400.invalid_ad_id` | 400 | — | `fix_input` | Invalid advertisement ID |
| `error.400.invalid_change_token` | 400 | — | `retry` | Invalid or expired change token. |
| `error.400.invalid_code` | 400 | — | `fix_input` | Invalid verification code |
| `error.400.invalid_code_attempts` | 400 | `attempts_remaining` | `fix_input` | Invalid verification code. {attempts_remaining} attempts remaining. |
| `error.400.invalid_method` | 400 | — | `fix_input` | Invalid or unavailable method for this account. |
| `error.400.invalid_phone` | 400 | — | `fix_input` | Invalid phone number |
| `error.400.invalid_phone_format` | 400 | — | `fix_input` | Invalid phone number format |
| `error.400.invalid_redirect_url` | 400 | — | `fix_input` | redirect_url must be a relative path starting with /  — absolute URLs are not allowed. |
| `error.400.last_auth_method` | 400 | — | `fix_input` | Cannot remove the last authentication method. |
| `error.400.magic_link_invalid` | 400 | — | `retry` | Magic link is invalid or has expired. |
| `error.400.no_current_value` | 400 | — | `fix_input` | No current value on this account. |
| `error.400.no_password` | 400 | — | `fix_input` | No password is set. Use set password first. |
| `error.400.no_verified_contact` | 400 | — | `verify` | No verified email or phone on this account. |
| `error.400.not_available` | 400 | — | `fix_input` | This value is already registered or reserved. |
| `error.400.oauth_failed` | 400 | — | `retry` | Failed to authenticate with OAuth provider |
| `error.400.oauth_fields_required` | 400 | — | `fix_input` | Provider and access_token are required |
| `error.400.passkey_challenge_expired` | 400 | — | `retry` | Passkey challenge has expired. Please try again. |
| `error.400.passkey_invalid` | 400 | — | `retry` | Passkey verification failed. |
| `error.400.password_already_set` | 400 | — | `fix_input` | Password is already set. Use the change password flow. |
| `error.400.passwords_dont_match` | 400 | — | `fix_input` | Password fields didn't match |
| `error.400.phone_required` | 400 | — | `fix_input` | Phone number is required. |
| `error.400.phone_too_long` | 400 | — | `fix_input` | Phone number is too long |
| `error.400.qr_expired` | 400 | — | `retry` | QR code has expired. |
| `error.400.qr_fulfilled` | 400 | — | `retry` | QR code has already been used. |
| `error.400.qr_type_required` | 400 | — | `fix_input` | QR type is required (session_share or login_request). |
| `error.400.sso_invalid_response` | 400 | — | `retry` | Invalid SSO response from identity provider. |
| `error.400.sso_not_configured` | 400 | — | `contact_support` | SSO is not configured for this organization. |
| `error.400.staff_role_target_not_staff` | 400 | — | `fix_input` | Staff roles can only be assigned to staff accounts. Make the user staff first. |
| `error.400.token_required` | 400 | — | `fix_input` | Token is required |
| `error.400.totp_not_pending` | 400 | — | `retry` | No pending TOTP setup. Call /totp/setup/ first. |
| `error.400.unknown_staff_role` | 400 | — | `fix_input` | Unknown staff role. Define it in the STAPEL_ACCESS["ROLES"] deploy config first. |
| `error.400.validation_error` | 400 | — | `fix_input` | Validation error |
| `error.400.verification_failed` | 400 | — | `verify` | Verification failed |
| `error.400.verification_invalid_factor` | 400 | — | `verify` | This verification factor is not available |
| `error.400.wrong_password` | 400 | — | `fix_input` | Wrong password. |
| `error.401.account_disabled` | 401 | — | `contact_support` | User account is disabled |
| `error.401.invalid_credentials` | 401 | — | `reauthenticate` | Invalid credentials |
| `error.401.qr_auth_required` | 401 | — | `reauthenticate` | Authentication required to generate a session_share QR code. |
| `error.401.refresh_invalid` | 401 | — | `reauthenticate` | Invalid or expired refresh token |
| `error.401.refresh_not_provided` | 401 | — | `reauthenticate` | Refresh token not provided |
| `error.401.refresh_revoked` | 401 | — | `reauthenticate` | Token has been revoked |
| `error.401.token_invalid` | 401 | — | `reauthenticate` | Invalid token |
| `error.401.token_revoked` | 401 | — | `reauthenticate` | Token has been revoked |
| `error.401.unauthorized` | 401 | — | `reauthenticate` | Authentication required |
| `error.401.user_not_found` | 401 | — | `reauthenticate` | User not found |
| `error.402.payment_required` | 402 | — | `retry` | Payment required |
| `error.403.forbidden` | 403 | — | `retry` | You do not have permission to perform this action |
| `error.403.mock_otp_admin` | 403 | — | `contact_support` | OTP-based auth is disabled for admin accounts in mock mode. |
| `error.403.network_blocked` | 403 | — | `contact_support` | Requests from this network are not allowed |
| `error.403.qr_device_mismatch` | 403 | — | `retry` | This QR code belongs to another device. |
| `error.403.qr_unauth_scan` | 403 | — | `reauthenticate` | This QR code cannot be scanned by an unauthenticated device. |
| `error.403.sso_required` | 403 | — | `reauthenticate` | This account must sign in via SSO. Use your organization SSO link. |
| `error.403.verification_enrollment_required` | 403 | — | `verify` | Verification factor enrollment required |
| `error.403.verification_required` | 403 | — | `verify` | Additional verification required |
| `error.404.ad_not_found` | 404 | — | `retry` | Listing not found |
| `error.404.change_not_found` | 404 | — | `retry` | Change request not found. |
| `error.404.gdpr.export_not_found` | 404 | — | `retry` | Export request not found. |
| `error.404.gdpr.no_active_closure` | 404 | — | `fix_input` | No pending account closure found. |
| `error.404.not_found` | 404 | — | `retry` | Not found. |
| `error.404.oauth_link_not_found` | 404 | — | `retry` | No linked account found for this provider. |
| `error.404.passkey_not_found` | 404 | — | `retry` | Passkey not found. |
| `error.404.qr_not_found` | 404 | — | `retry` | QR code not found or expired. |
| `error.404.sso_org_not_found` | 404 | — | `fix_input` | Organization not found. |
| `error.404.user_for_reset` | 404 | — | `fix_input` | No account found with this email or phone. |
| `error.404.verification_challenge_not_found` | 404 | — | `verify` | Verification challenge not found or expired |
| `error.405.method_not_allowed` | 405 | — | `retry` | Method not allowed |
| `error.406.not_acceptable` | 406 | — | `retry` | Not acceptable |
| `error.408.request_timeout` | 408 | — | `retry` | Request timeout |
| `error.409.conflict` | 409 | — | `fix_input` | Resource already exists |
| `error.409.email_reserved` | 409 | — | `fix_input` | This email is reserved by another pending change request. |
| `error.409.email_taken` | 409 | — | `fix_input` | This email is already registered to another account. |
| `error.409.gdpr.closure_already_pending` | 409 | — | `fix_input` | Account closure is already in progress. |
| `error.409.gdpr.export_cooldown` | 409 | — | `fix_input` | A data export was already requested in the last 30 days. |
| `error.409.gdpr.legal_hold` | 409 | — | `fix_input` | Account data is under a legal hold and cannot be deleted. |
| `error.409.oauth_account_linked_elsewhere` | 409 | — | `fix_input` | This provider account is already linked to a different user. |
| `error.409.oauth_already_linked` | 409 | — | `fix_input` | This provider is already linked to your account. |
| `error.409.passkey_already_registered` | 409 | — | `fix_input` | This passkey is already registered. |
| `error.409.phone_reserved` | 409 | — | `fix_input` | This phone number is reserved by another pending change request. |
| `error.409.phone_taken` | 409 | — | `fix_input` | This phone number is already registered to another account. |
| `error.409.qr_account_conflict` | 409 | — | `reauthenticate` | A different account is already signed in on this device. |
| `error.409.sso_org_slug_taken` | 409 | — | `fix_input` | An organization with this slug already exists. |
| `error.409.username_taken` | 409 | — | `fix_input` | This username is already taken. |
| `error.410.gdpr.download_expired` | 410 | — | `retry` | Download link has expired. |
| `error.410.gone` | 410 | — | `retry` | Resource has been permanently removed |
| `error.413.payload_too_large` | 413 | — | `retry` | Request body is too large |
| `error.415.unsupported_media_type` | 415 | — | `retry` | Unsupported media type |
| `error.422.blocked` | 422 | `retry_after_minutes` | `wait_and_retry` | Account temporarily blocked. Try again in {retry_after_minutes} minutes. |
| `error.422.unprocessable_entity` | 422 | — | `wait_and_retry` | Unprocessable entity |
| `error.423.account_locked` | 423 | `retry_after_minutes` | `wait_and_retry` | Account temporarily locked due to too many failed attempts. Try again in {retry_after_minutes} minutes. |
| `error.423.locked` | 423 | — | `wait_and_retry` | Resource is locked |
| `error.423.verification_locked` | 423 | — | `wait_and_retry` | Too many failed attempts — verification locked |
| `error.425.gdpr.export_not_ready` | 425 | — | `retry` | Export is still being prepared. |
| `error.429.magic_link_rate` | 429 | — | `wait_and_retry` | Too many magic link requests. Please try again later. |
| `error.429.rate_limit` | 429 | `retry_after_minutes` | `wait_and_retry` | Too many attempts. Try again in {retry_after_minutes} minutes. |
| `error.429.too_many_requests` | 429 | — | `wait_and_retry` | Too many requests. Please try again later. |
| `error.500.internal` | 500 | — | `contact_support` | Something went wrong |
| `error.500.send_failed` | 500 | — | `retry` | Failed to send verification code |
