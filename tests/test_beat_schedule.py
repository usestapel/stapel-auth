"""
`BEAT_SCHEDULE` (MODULE.md "Celery beat schedule"): without a host merging
this into its own `CELERY_BEAT_SCHEDULE`, the delayed (14-day) authenticator-
change strategy's day-1/7/13 notifications and the change itself never fire —
a `PENDING` request just sits there forever. This is a discoverability
contract: the schedule must name the three real tasks with sane intervals,
and it must be importable from both the lazy public API and the module it's
defined in (same object, not a copy).
"""

from datetime import timedelta

from stapel_auth.tasks import BEAT_SCHEDULE, cleanup_expired_requests, execute_pending_changes, send_change_notifications

EXPECTED_TASKS = {
    "send_change_notifications": send_change_notifications,
    "execute_pending_changes": execute_pending_changes,
    "cleanup_expired_requests": cleanup_expired_requests,
}


def test_beat_schedule_is_reachable_from_the_public_api():
    import stapel_auth

    assert stapel_auth.BEAT_SCHEDULE is BEAT_SCHEDULE


def test_beat_schedule_names_exactly_the_three_delayed_change_tasks():
    scheduled_task_names = {entry["task"] for entry in BEAT_SCHEDULE.values()}
    expected_dotted_names = {f"stapel_auth.tasks.{name}" for name in EXPECTED_TASKS}
    assert scheduled_task_names == expected_dotted_names


def test_beat_schedule_task_paths_resolve_to_the_real_shared_tasks():
    for entry in BEAT_SCHEDULE.values():
        dotted = entry["task"]
        short_name = dotted.rsplit(".", 1)[-1]
        assert short_name in EXPECTED_TASKS, f"unexpected task {dotted!r} in BEAT_SCHEDULE"
        # `@shared_task` gives every task its dotted-path name by default —
        # this is the actual contract celery beat dispatches against.
        assert EXPECTED_TASKS[short_name].name == dotted


def test_beat_schedule_intervals_are_sane():
    # Sane = positive, and ordered the way the tasks' own urgency is ordered
    # in MODULE.md: applying a due change (execute_pending_changes) can't be
    # slower than sending the notifications that precede it, and cleanup
    # (pure bookkeeping) is allowed to be the slowest of the three.
    intervals = {
        entry["task"].rsplit(".", 1)[-1]: entry["schedule"] for entry in BEAT_SCHEDULE.values()
    }
    for name, schedule in intervals.items():
        assert isinstance(schedule, timedelta), f"{name}: schedule must be a timedelta"
        assert schedule.total_seconds() > 0, f"{name}: schedule must be positive"

    assert intervals["execute_pending_changes"] <= intervals["send_change_notifications"]
    assert intervals["send_change_notifications"] <= intervals["cleanup_expired_requests"]
    # Concretely: minutes-scale for execution, hours-scale for notifications,
    # at most daily for cleanup — catches an accidental order-of-magnitude typo.
    assert timedelta(minutes=1) <= intervals["execute_pending_changes"] <= timedelta(minutes=30)
    assert timedelta(minutes=30) <= intervals["send_change_notifications"] <= timedelta(hours=6)
    assert timedelta(hours=6) <= intervals["cleanup_expired_requests"] <= timedelta(hours=24)


def test_beat_schedule_entry_names_are_namespaced():
    # Entry keys (not task paths) are what a host's CELERY_BEAT_SCHEDULE dict
    # merges by — namespaced so merging into a host's own schedule can't
    # silently collide with an unrelated periodic task of the same short name.
    for key in BEAT_SCHEDULE:
        assert key.startswith("stapel-auth-"), key
