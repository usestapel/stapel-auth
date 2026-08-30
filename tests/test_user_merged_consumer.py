"""Auth's own position on ``user.merged`` — a stated no-op, not silence.

Auth emits ``user.merged``; it does not consume it. The merge is performed and
announced in one transaction (``otp.services.merge_anonymous_into``), so there
is nothing left for a subscriber to re-parent. ``stapel_core.lifecycle.E001``
asks every app that handles ``user.deleted`` to say so out loud, and auth
handles ``user.deleted`` through its gdpr-owner registration.
"""
import pytest
from stapel_core.comm.registry import action_registry

from stapel_auth.actions import handle_user_merged
from stapel_auth.events import EVENT_USER_MERGED


class _Event:
    def __init__(self, payload):
        self.payload = payload
        self.event_id = "test-event"


def test_the_no_op_handler_is_subscribed():
    assert handle_user_merged in action_registry.handlers(EVENT_USER_MERGED)


def test_the_lifecycle_check_is_clean_for_auth():
    from stapel_core.comm.lifecycle_checks import check_lifecycle_pairs

    reported = [error for error in check_lifecycle_pairs() if "stapel_auth" in error.msg]
    assert reported == []


@pytest.mark.parametrize(
    "payload",
    [
        {"from_user_id": "not-a-uuid", "into_user_id": "also-not-a-uuid"},
        {"from_user_id": "", "into_user_id": ""},
        {},
        None,
    ],
)
def test_a_malformed_payload_is_accepted_not_raised(payload):
    """A raise here would put the bus into a redelivery loop on one bad event."""
    assert handle_user_merged(_Event(payload)) is None
