"""
Utility functions for the authentication service.
"""


def mask_phone(phone: str) -> str:
    """
    Mask a phone number for display.
    "+79994561234" -> "+7 *** *** 12 34"
    """
    digits = ''.join(c for c in phone if c.isdigit())
    if len(digits) < 4:
        return phone
    # Country code is everything before the last 10 digits
    if phone.startswith('+'):
        country_code = '+' + digits[:len(digits) - 10] if len(digits) > 10 else '+'
        last4 = digits[-4:]
        return f"{country_code} *** *** {last4[:2]} {last4[2:]}"
    last4 = digits[-4:]
    return f"*** *** {last4[:2]} {last4[2:]}"


def mask_email(email: str) -> str:
    """
    Mask an email address for display.
    "user@example.com" -> "u***@example.com"
    """
    if '@' not in email:
        return email
    local, domain = email.split('@', 1)
    if len(local) <= 1:
        masked_local = local
    else:
        masked_local = local[0] + '***'
    return f"{masked_local}@{domain}"


def mask_value(value: str, change_type: str) -> str:
    """Dispatch to the appropriate masking function based on change_type."""
    if change_type == 'phone':
        return mask_phone(value)
    elif change_type == 'email':
        return mask_email(value)
    return value
