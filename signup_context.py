"""``signup_context``: an opaque object a client hands to a sign-up door.

Another module may want to know something about the visit that produced an
account — a referral code, a campaign it ran itself — without a second
client call after the sign-up. The client sends it as ``signup_context`` on
the request that signs the person up, and auth copies it verbatim into the
``user.signed_up`` fact. Auth never reads, stores or interprets it: what the
keys mean is the consumer's business.

It is untrusted input, so the shape is bounded and nothing nested gets in:
a JSON object of at most :data:`MAX_KEYS` keys (``[A-Za-z0-9_.:-]``, at most
:data:`KEY_MAX_LENGTH` characters), each value a scalar — a string of at
most :data:`VALUE_MAX_LENGTH` characters, a bool, a finite number or null —
and at most :data:`MAX_BYTES` bytes as compact JSON. A body field that breaks
this refuses the request with ``error.400.signup_context_invalid``; an empty
object is the same as none.

The OAuth redirect flow has no body: ``/oauth/{provider}/authorize/`` takes
the object JSON-encoded in the ``signup_context`` query parameter, parks it
in the flow state and hands it to the callback. A malformed one there is
dropped with a warning, not refused — the answer to that request is a
redirect to the provider, and an error in the address bar would take the
sign-in down over a field auth does not even read.
"""
from __future__ import annotations

import json
import logging
import math
import re

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from stapel_core.django.api.errors import StapelValidationError

from stapel_auth.errors import ERR_400_SIGNUP_CONTEXT_INVALID

logger = logging.getLogger(__name__)

MAX_KEYS = 16
KEY_MAX_LENGTH = 64
VALUE_MAX_LENGTH = 256
MAX_BYTES = 2048
KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]+$")
#: Largest integer a JSON consumer in any language reads back exactly.
INT_LIMIT = 2**53

SIGNUP_CONTEXT_HELP = (
    "Optional opaque object copied verbatim into the user.signed_up fact "
    "(e.g. a referral code another module reads). Auth never interprets it. "
    f"At most {MAX_KEYS} keys of [A-Za-z0-9_.:-] (max {KEY_MAX_LENGTH} "
    f"characters), scalar values only (string up to {VALUE_MAX_LENGTH} "
    f"characters, bool, number, null), at most {MAX_BYTES} bytes as JSON. "
    "Anything else refuses the request with error.400.signup_context_invalid."
)

_SCALAR_SCHEMA = {
    "oneOf": [
        {"type": "string", "maxLength": VALUE_MAX_LENGTH},
        {"type": "number"},
        {"type": "boolean"},
    ],
    "nullable": True,
}


def _valid_value(value) -> bool:
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -INT_LIMIT <= value <= INT_LIMIT
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, str):
        return len(value) <= VALUE_MAX_LENGTH
    return False


def parse_signup_context(value):
    """The validated context (a new dict), or ``None`` when absent or empty.

    Raises ``StapelValidationError(error.400.signup_context_invalid)`` on any
    shape outside the bounds in the module docstring.
    """
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > MAX_KEYS:
        raise StapelValidationError(ERR_400_SIGNUP_CONTEXT_INVALID)
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or len(key) > KEY_MAX_LENGTH
            or not KEY_PATTERN.match(key)
            or not _valid_value(item)
        ):
            raise StapelValidationError(ERR_400_SIGNUP_CONTEXT_INVALID)
    if not value:
        return None
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > MAX_BYTES:
        raise StapelValidationError(ERR_400_SIGNUP_CONTEXT_INVALID)
    return dict(value)


@extend_schema_field(
    {
        "type": "object",
        "maxProperties": MAX_KEYS,
        "additionalProperties": _SCALAR_SCHEMA,
        "nullable": True,
    }
)
class SignupContextField(serializers.Field):
    """The ``signup_context`` request field; see the module docstring."""

    def __init__(self, **kwargs):
        kwargs.setdefault("required", False)
        kwargs.setdefault("allow_null", True)
        kwargs.setdefault("help_text", SIGNUP_CONTEXT_HELP)
        super().__init__(**kwargs)

    def to_internal_value(self, data):
        return parse_signup_context(data)

    def to_representation(self, value):
        return value


def signup_context_from_query(query_params):
    """Read a JSON-encoded ``signup_context`` off a redirect flow's query.

    ``None`` when absent; ``None`` with a warning when malformed (see the
    module docstring for why a navigation is not refused).
    """
    raw = query_params.get("signup_context")
    if not raw:
        return None
    try:
        return parse_signup_context(json.loads(raw))
    except (ValueError, StapelValidationError):
        logger.warning(
            "stapel-auth: dropping a malformed signup_context on an OAuth "
            "authorize query (the sign-in itself is unaffected)"
        )
        return None


def signup_context_from_body(data):
    """The validated ``signup_context`` of a body read field by field.

    For a door that does not run a request serializer; raises like the
    field does.
    """
    getter = getattr(data, "get", None)
    return parse_signup_context(getter("signup_context") if getter else None)


__all__ = [
    "KEY_MAX_LENGTH",
    "MAX_BYTES",
    "MAX_KEYS",
    "SIGNUP_CONTEXT_HELP",
    "SignupContextField",
    "VALUE_MAX_LENGTH",
    "parse_signup_context",
    "signup_context_from_body",
    "signup_context_from_query",
]
