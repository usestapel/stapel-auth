"""
Utility functions for the authentication service.
"""
import re

from stapel_core.django.api.views import SerializerSeamMixin


# ── Namespaced org logins (workspaces-org-program §C1) ───────────────────────
#
# Org-provisioned logins are namespaced ``org_slug/local``: the workspace
# slug, ONE literal ``/`` separator, then a local username. The alphabet
# canon lives in stapel-core (``StapelUsernameValidator`` on the user model);
# these helpers are the parsing/validation seam auth-side callers
# (``auth.provision_user``) build on.

#: Stock Django username alphabet — each side of the namespace separator
#: must match it on its own (mirrors StapelUsernameValidator's per-part rule).
_LOCAL_USERNAME_RE = re.compile(r"^[\w.@+-]+\Z")


def parse_namespaced_login(username: str) -> tuple:
    """Split ``org_slug/local`` into ``(org_slug, local)``.

    A bare (slash-free) username parses as ``(None, username)``. More than
    one slash, or an empty side, raises ``ValueError`` — both sides of the
    separator must themselves be valid usernames.
    """
    if not isinstance(username, str) or not username:
        raise ValueError("username must be a non-empty string")
    if "/" not in username:
        return None, username
    org_slug, sep, local = username.partition("/")
    if "/" in local:
        raise ValueError("username may contain at most one '/' separator")
    if not org_slug or not local:
        raise ValueError("both sides of the '/' separator must be non-empty")
    return org_slug, local


def validate_local_username(local: str) -> bool:
    """Whether *local* is a valid slash-free username part (stock canon)."""
    return bool(isinstance(local, str) and _LOCAL_USERNAME_RE.match(local))


# Base: stapel_core.django.api.views.SerializerSeamMixin — the fleet's one copy
# of the two-name seam (``request_serializer_class`` / ``response_serializer_class``
# and their getters), which is no longer redefined below. What the subclass adds
# is the part core deliberately leaves to the view: core documents the
# purpose-prefixed convention (``list_response_serializer_class`` ↔
# ``get_list_response_serializer_class()``) and expects each getter to be spelled
# out, while this module declares 83 such attributes across 11 viewsets. 83
# hand-written one-line getters is a copy of a seam, not a seam, so they are
# derived instead.
#
# NB: this docstring is load-bearing for the CONTRACT, not just for readers.
# Several viewsets (PasskeyViewSet among them) carry no docstring of their own,
# so drf-spectacular walks the MRO and renders THIS text as the OpenAPI
# description of their operations. Editing it rewrites docs/schema.json for
# endpoints that did not change — keep it byte-stable unless that churn is the
# point of the release.
class SerializerSeamsMixin(SerializerSeamMixin):
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
