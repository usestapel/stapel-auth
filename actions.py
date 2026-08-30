"""Action subscriptions of the auth module.

Auth's ``user.deleted`` subscriber is not written here — it is the closure
:func:`stapel_core.gdpr.register_gdpr_owner` builds from
:func:`stapel_auth.erasure.erase_subject` (see ``apps.py``). What lives here is
the other half of the account life cycle, and the reason it is a no-op.
"""
import logging

from stapel_core.comm import on_action

from .events import EVENT_USER_MERGED

logger = logging.getLogger(__name__)


@on_action(EVENT_USER_MERGED)
def handle_user_merged(event):
    """No-op by design: this module is the event's author, not its consumer.

    :func:`stapel_auth.otp.services.merge_anonymous_into` performs the merge
    and emits the announcement inside one transaction — the survivor is saved
    and the guest row deleted there, and everything auth owns through that row
    (sessions, passkeys, OAuth links, verification state) goes with it by
    cascade. There is nothing left for a subscriber to re-parent.

    Answering our own announcement would be a second implementation of the
    merge racing the first: the handler runs in-process, inside the emitting
    transaction, against a guest row the same block is about to delete.

    Registered rather than omitted so ``stapel_core.lifecycle.E001`` reads a
    stated position instead of silence.
    """
    payload = getattr(event, "payload", None) or {}
    logger.debug(
        "%s %s -> %s: auth performs the merge inline, nothing to re-parent",
        EVENT_USER_MERGED,
        payload.get("from_user_id"),
        payload.get("into_user_id"),
    )


__all__ = ["handle_user_merged"]
