"""
Celery tasks for authenticator change flows.
"""

import logging
from celery import shared_task
from django.db import transaction
from django.utils import timezone
from datetime import timedelta

from stapel_core.notifications import request_notification

logger = logging.getLogger(__name__)

# =============================================================================
# Beat schedule (MODULE.md "Celery beat schedule") — a HOST APP concern, not
# auto-wired by this module (installing this app does not touch a host's
# celery.py). Without a beat entry, `send_change_notifications`,
# `execute_pending_changes` and `cleanup_expired_requests` below never run on
# their own: a delayed (14-day) authenticator change is created, its day-1/7/13
# notifications never fire, and it never actually applies at `scheduled_at` —
# the request just sits `PENDING` forever. A host merges this dict into its own
# `CELERY_BEAT_SCHEDULE` (see MODULE.md for the exact merge snippet); this
# constant is the single source of truth for the task names + intervals so the
# three tasks stay discoverable from the code that defines them, not only from
# prose.
BEAT_SCHEDULE = {
    "stapel-auth-send-change-notifications": {
        "task": "stapel_auth.tasks.send_change_notifications",
        # Hourly: cheap (a `PENDING`-status filter + a per-day-threshold flag
        # check), and keeps the day-1/7/13 notifications from lagging a
        # full day behind the actual threshold.
        "schedule": timedelta(hours=1),
    },
    "stapel-auth-execute-pending-changes": {
        "task": "stapel_auth.tasks.execute_pending_changes",
        # Every 5 minutes: this is what actually flips the user's email/phone
        # at `scheduled_at` — a coarser interval would mean the change sits
        # applied-but-not-yet-executed for up to a full schedule tick.
        "schedule": timedelta(minutes=5),
    },
    "stapel-auth-cleanup-expired-requests": {
        "task": "stapel_auth.tasks.cleanup_expired_requests",
        # Daily: pure bookkeeping (marks >30-day-old abandoned requests
        # EXPIRED), nothing time-sensitive depends on it running sooner.
        "schedule": timedelta(hours=24),
    },
}


def _contact_kwargs(change_type: str, value: str) -> dict:
    """Build email/phone kwargs for request_notification based on change_type."""
    return {
        "email": value if change_type == "email" else None,
        "phone": value if change_type == "phone" else None,
    }


def _notify_kwargs_for_request(req) -> dict:
    """Resolve the email/phone kwargs to notify for a change request.

    Phone/email changes notify the OLD (pre-change) contact — the address
    the account is being taken away from — via ``req.old_value``. TOTP
    changes have no such address (see AuthenticatorChangeRequest
    docstring): they notify the user's CURRENT verified email (falling
    back to verified phone), since that channel is unaffected by a TOTP
    change and is exactly what ``initiate_delayed_totp`` required to
    exist before it would create the request.
    """
    if req.change_type in ("email", "phone"):
        return _contact_kwargs(req.change_type, req.old_value)

    user = req.user
    if user.email and getattr(user, "is_email_verified", False):
        return {"email": user.email, "phone": None}
    if user.phone and getattr(user, "is_phone_verified", False):
        return {"email": None, "phone": user.phone}
    return {"email": None, "phone": None}


def _masked_new_value_for_request(req) -> str:
    """Display-safe 'new value' for a change request (see get_pending_status)."""
    if req.change_type == "totp":
        return "authenticator app"
    from .utils import mask_value

    return mask_value(req.new_value, req.change_type)


@shared_task
def send_change_notifications():
    """Send notifications for pending delayed authenticator changes (day 1/7/13)."""
    from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

    now = timezone.now()
    pending = AuthenticatorChangeRequest.objects.filter(
        status=AuthenticatorChangeStatus.PENDING,
        scheduled_at__isnull=False,
    )

    sent_count = 0
    for req in pending:
        days_since = (now - req.created_at).days

        if days_since >= 1 and not req.notification_day_1_sent:
            try:
                request_notification(
                    notification_type="auth_change_requested",
                    user_id=str(req.user_id),
                    variables={
                        "change_type": req.change_type,
                        "masked_new_value": _masked_new_value_for_request(req),
                        "scheduled_date": req.scheduled_at.strftime("%Y-%m-%d %H:%M UTC"),
                    },
                    source_service="auth",
                    **_notify_kwargs_for_request(req),
                )
                req.notification_day_1_sent = True
                req.save(update_fields=['notification_day_1_sent'])
                sent_count += 1
            except Exception:
                logger.exception("Failed to send day-1 notification for request %s", req.id)

        if days_since >= 7 and not req.notification_day_7_sent:
            try:
                request_notification(
                    notification_type="auth_change_reminder",
                    user_id=str(req.user_id),
                    variables={
                        "change_type": req.change_type,
                        "masked_new_value": _masked_new_value_for_request(req),
                        "days_remaining": "7",
                    },
                    source_service="auth",
                    **_notify_kwargs_for_request(req),
                )
                req.notification_day_7_sent = True
                req.save(update_fields=['notification_day_7_sent'])
                sent_count += 1
            except Exception:
                logger.exception("Failed to send day-7 notification for request %s", req.id)

        if days_since >= 13 and not req.notification_day_13_sent:
            try:
                request_notification(
                    notification_type="auth_change_urgent",
                    user_id=str(req.user_id),
                    variables={
                        "change_type": req.change_type,
                        "scheduled_date": req.scheduled_at.strftime("%Y-%m-%d"),
                    },
                    source_service="auth",
                    **_notify_kwargs_for_request(req),
                )
                req.notification_day_13_sent = True
                req.save(update_fields=['notification_day_13_sent'])
                sent_count += 1
            except Exception:
                logger.exception("Failed to send day-13 notification for request %s", req.id)

    logger.info(f"Sent {sent_count} change notifications")
    return sent_count


@shared_task
def execute_pending_changes():
    """Execute authenticator changes that have reached their scheduled time."""
    from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
    from .otp.services import AuthenticatorChangeService

    now = timezone.now()
    due_ids = list(
        AuthenticatorChangeRequest.objects.filter(
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at__lte=now,
            scheduled_at__isnull=False,
        ).values_list('id', flat=True)
    )

    executed = 0
    for req_id in due_ids:
        try:
            with transaction.atomic():
                req = AuthenticatorChangeRequest.objects.select_for_update().get(
                    id=req_id,
                    status=AuthenticatorChangeStatus.PENDING,
                )
                user = req.user

                if req.change_type == "totp":
                    # No "new value" to apply — TOTP delayed mode is a
                    # scheduled disable (see initiate_delayed_totp); the
                    # user re-enrolls afterward via the normal instant
                    # setup/confirm_setup pair.
                    from .mfa.services import TOTPService

                    TOTPService.force_disable(user)
                else:
                    AuthenticatorChangeService._apply_change(user, req.change_type, req.new_value)
                AuthenticatorChangeService._invalidate_all_tokens(user)

                req.status = AuthenticatorChangeStatus.COMPLETED
                req.completed_at = now
                req.save(update_fields=['status', 'completed_at'])

            # Notify. Phone/email changes notify BOTH the old and new
            # contact (the address gained the account, and the address
            # that lost it); TOTP has no "new contact" — a single
            # notification to the verified contact suffices.
            if req.change_type == "totp":
                try:
                    request_notification(
                        notification_type="auth_change_completed",
                        user_id=str(req.user_id),
                        variables={"change_type": req.change_type},
                        source_service="auth",
                        **_notify_kwargs_for_request(req),
                    )
                except Exception:
                    logger.exception("Failed to send auth_change_completed notification for request %s", req.id)
            else:
                for target_value in (req.new_value, req.old_value):
                    try:
                        request_notification(
                            notification_type="auth_change_completed",
                            user_id=str(req.user_id),
                            variables={"change_type": req.change_type},
                            source_service="auth",
                            **_contact_kwargs(req.change_type, target_value),
                        )
                    except Exception:
                        logger.exception("Failed to send auth_change_completed notification for request %s", req.id)

            executed += 1
        except AuthenticatorChangeRequest.DoesNotExist:
            # Already processed by another worker
            continue
        except Exception as e:
            logger.error(f"Failed to execute change request {req_id}: {e}")

    logger.info(f"Executed {executed} pending changes")
    return executed


@shared_task
def cleanup_expired_requests():
    """Mark old pending requests (>30 days) as expired."""
    from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

    cutoff = timezone.now() - timedelta(days=30)
    expired = AuthenticatorChangeRequest.objects.filter(
        status=AuthenticatorChangeStatus.PENDING,
        created_at__lt=cutoff,
    ).update(status=AuthenticatorChangeStatus.EXPIRED)

    logger.info(f"Marked {expired} requests as expired")
    return expired


# =============================================================================
# Login notification tasks
# =============================================================================

@shared_task
def evaluate_login_notification(user_id: str, session_id: str):
    """Check if login is from new/suspicious device and send appropriate email."""
    from django.contrib.auth import get_user_model
    from .models import UserSession, AuthEventType
    from .sessions.services import LoginNotificationService, AuditService

    User = get_user_model()
    try:
        user = User.objects.get(id=user_id)
        session = UserSession.objects.get(id=session_id)
    except Exception:
        logger.warning('evaluate_login_notification: missing user or session %s/%s', user_id, session_id)
        return

    is_new = LoginNotificationService.is_new_device(user, session)
    is_suspicious = LoginNotificationService.is_suspicious_ip(user, session)

    if is_suspicious:
        session.is_suspicious = True
        session.save(update_fields=['is_suspicious'])
        AuditService.log(AuthEventType.SUSPICIOUS_LOGIN, user=user, session=session)

    if is_new or is_suspicious:
        _send_login_alert_email(user, session, is_suspicious)


def _send_login_alert_email(user, session, is_suspicious: bool):
    from stapel_core.notifications import request_notification
    from django.core.signing import TimestampSigner

    from .conf import auth_settings
    frontend_url = auth_settings.FRONTEND_URL or ''
    secure_url = f'{frontend_url}/security/sessions'

    notification_type = 'suspicious_login' if is_suspicious else 'new_device_login'
    extra = {}
    if is_suspicious:
        signer = TimestampSigner()
        token = signer.sign(f'{session.user_id}:{session.id}')
        backend_url = auth_settings.BACKEND_URL or frontend_url
        extra['revoke_url'] = f'{backend_url}/auth/api/v1/security/revoke-suspicious/?token={token}'

    if user.email:
        try:
            request_notification(
                notification_type=notification_type,
                user_id=str(user.id),
                email=user.email,
                variables={
                    'device_name': session.device_name or 'Unknown device',
                    'ip_address': session.ip_address or '',
                    'secure_url': secure_url,
                    **extra,
                },
                source_service='auth',
            )
        except Exception:
            logger.exception('Failed to send login notification for user %s', user.id)
