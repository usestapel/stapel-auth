"""comm Function providers of the auth service.

Registered from ``StapelAuthConfig.ready()`` (importing this module is
enough: re-imports are no-ops and re-registering the same handler object is
idempotent). Other modules call these by name via ``stapel_core.comm.call``
— no import of this package needed:

    from stapel_core.comm import call

    call("auth.verification.policy", {"user_id": "42"})
"""
import logging

from stapel_core.comm import function

logger = logging.getLogger(__name__)

VERIFICATION_POLICY_SCHEMA = {
    "type": "object",
    "properties": {
        "user_id": {
            "type": "string",
            "description": "Primary key of the user whose policy is resolved.",
        },
    },
    "required": ["user_id"],
    "additionalProperties": False,
}


@function("auth.verification.policy", schema=VERIFICATION_POLICY_SCHEMA)
def verification_policy(payload: dict) -> dict:
    """Per-user step-up verification policy.

    Payload: ``{"user_id": "<pk>"}``. Returns
    ``{"disabled_scopes": [...], "enabled_scopes": [...]}`` — the scopes the
    user explicitly turned off (``default_on`` endpoints) or on (``opt_in``
    endpoints). Unknown users simply have empty lists: absence of
    preferences means framework defaults apply.

    Consumed by ``stapel_core.verification.policy.get_user_policy`` (cached
    core-side for ``POLICY_CACHE_TTL`` seconds).
    """
    from .models import VerificationPreference

    disabled: list[str] = []
    enabled: list[str] = []
    rows = VerificationPreference.objects.filter(
        user_id=payload["user_id"]
    ).values_list("scope", "enabled")
    for scope, is_enabled in rows:
        (enabled if is_enabled else disabled).append(scope)
    return {"disabled_scopes": sorted(disabled), "enabled_scopes": sorted(enabled)}
