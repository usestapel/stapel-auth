"""
Utility functions for the authentication service.
"""
import re

from rest_framework import serializers

from stapel_core.django.api.views import SerializerSeamMixin


def _is_serializer_class(candidate) -> bool:
    """Is *candidate* something DRF can instantiate as a serializer?

    A seam may legitimately hold a ``drf_spectacular`` proxy — a
    ``PolymorphicProxySerializer`` INSTANCE standing for a union of bodies —
    which documents an endpoint but cannot be called. Handing that to
    ``get_serializer()`` is a ``TypeError`` inside OPTIONS, i.e. the same 500
    from the other side, so a seam that is not a serializer class is treated
    as "no declaration" rather than trusted.
    """
    return isinstance(candidate, type) and issubclass(
        candidate, serializers.BaseSerializer
    )


class EmptyRequestSerializer(serializers.Serializer):
    """A request body with no declared fields.

    What :meth:`SerializerSeamsMixin.get_serializer_class` answers for an
    action that reads nothing off the body — a logout, a refresh that takes
    its token from a cookie. ``OPTIONS`` then reports an empty ``actions``
    entry, which is the truth, instead of DRF raising ``AssertionError``
    behind a 500.
    """


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

    def _serializer_seam_action(self):
        """Which action's body is being described.

        ``ViewSetMixin.initialize_request`` pins ``self.action`` to the
        literal ``"metadata"`` for an OPTIONS request, so on the one request
        that asks this question ``self.action`` names no action at all.
        ``SimpleMetadata`` then clones the request as POST and puts it on the
        view, which is what makes the answer derivable anyway: read the verb
        the metadata pass is asking about out of the same map the router
        built.
        """
        action = getattr(self, "action", None)
        if action and action != "metadata":
            return action
        action_map = getattr(self, "action_map", None) or {}
        method = getattr(getattr(self, "request", None), "method", "") or ""
        return action_map.get(method.lower()) or action

    def get_serializer_class(self):
        """DRF's own answer to "what does this endpoint accept?".

        Every viewset here is a ``GenericViewSet`` whose serializers are
        per-action seams, so none of them set ``serializer_class`` — and
        ``GenericAPIView.get_serializer_class`` answers a missing one with
        ``AssertionError``, which is not an ``APIException`` and so escapes
        the exception handler. Anything that asks DRF for a serializer
        generically therefore got a 500 with a traceback rather than an
        answer. ``OPTIONS`` is exactly that: ``SimpleMetadata`` builds the
        ``actions`` block by instantiating the view's serializer, so a
        cross-origin client's CORS preflight against a pre-auth route — the
        one request it makes before it can sign in — died on it (measured on
        a client stand, 2026-09-09).

        The seams already hold the answer, so it is derived rather than
        declared: the request serializer of the action being dispatched,
        then the view-wide seam, then whatever ``serializer_class`` a
        subclass set. An action that genuinely takes no body answers
        :class:`EmptyRequestSerializer` — "no declared fields", which is
        true, and which keeps ``OPTIONS`` a 200 for every route this package
        mounts (``tests/test_options_metadata.py`` walks the URLconf and
        proves it).
        """
        action = self._serializer_seam_action()
        candidates = []
        if action:
            candidates = [f"{action}_request_serializer_class"]
            if action.endswith("_request"):
                # The seam names a PURPOSE, and for an action already called
                # `<thing>_request` the purpose is the action name itself:
                # `email_request` reads `email_request_serializer_class`, not
                # `email_request_request_serializer_class`. Only the
                # `_request` suffix is accepted here, so this can never pick
                # up a response seam.
                candidates.append(f"{action}_serializer_class")
        candidates.extend(("request_serializer_class", "serializer_class"))
        for name in candidates:
            declared = getattr(self, name, None)
            if _is_serializer_class(declared):
                return declared
        return EmptyRequestSerializer


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
