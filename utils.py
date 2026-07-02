"""
Utility functions for the authentication service.
"""


class SerializerSeamsMixin:
    """Overridable serializer seams for stapel-auth API views.

    Views declare ``<purpose>_serializer_class`` class attributes following the
    ``*_request_serializer_class`` / ``*_response_serializer_class`` naming
    convention (e.g. ``request_serializer_class`` or, when a view uses several
    serializers, purpose-prefixed names such as ``login_request_serializer_class``
    or ``auth_response_serializer_class``). For every such attribute this mixin
    supplies the matching ``get_<purpose>_serializer_class()`` getter, so hosts
    can swap a serializer by subclassing the view and overriding either the
    attribute or the getter::

        class MyMagicLinkViewSet(MagicLinkViewSet):
            response_serializer_class = MyResponseSerializer

    Handler bodies instantiate serializers exclusively through the getters, so
    an override is picked up everywhere the serializer is used.
    """

    def __getattr__(self, name):
        if name.startswith("get_") and name.endswith("_serializer_class"):
            attr = name[len("get_"):]
            if hasattr(type(self), attr):
                return lambda: getattr(self, attr)
        raise AttributeError(
            f"{type(self).__name__!r} object has no attribute {name!r}"
        )


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
