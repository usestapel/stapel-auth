"""A first-ever login can never be "suspicious".

INCIDENT 2026-08-08 (meettoday). Someone was invited by link to a meeting
in a private space. They logged in for the first time — and a minute later
got a "SUSPICIOUS LOGIN DETECTED" email with a red "This wasn't me — end
all sessions" button.

CAUSE. Both watchdog predicates ask "does this login differ from prior
ones", and both are expressed as a negated existence check:

    not UserSession.objects.filter(...).exclude(id=session.id).exists()

For a user with no history the set is empty, the negation is true, and the
answer "yes, it differs" is GUARANTEED — not as a conclusion, but as a
property of the empty set. Every new user got the email, always.

SECOND DEFECT, found by the same investigation: `LOGIN_NOTIFICATION_ENABLED`
existed in `DEFAULTS` (default False) and in MODULE.md, but nothing read it.
A deployment had no real way to switch the mailing off, and the documented
default promised exactly the opposite ("off"). The tests below pin both
sides of the switch so it can't quietly go back to being just documentation.
"""
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from stapel_auth.models import UserSession
from stapel_auth.sessions.services import LoginNotificationService

User = get_user_model()


def _user():
    return User.objects.create_user(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )


def _session(user, **kwargs):
    defaults = dict(
        jti=uuid.uuid4().hex,
        device_name="Chrome on Mac",
        device_type="desktop",
        ip_address="203.0.113.20",
        expires_at=timezone.now() + timedelta(days=30),
    )
    defaults.update(kwargs)
    return UserSession.objects.create(user=user, **defaults)


class ColdStartTests(TestCase):
    """A user with no login history has nothing to compare against."""

    def setUp(self):
        self.user = _user()

    def test_first_login_is_not_suspicious_network(self):
        first = _session(self.user)
        self.assertFalse(
            LoginNotificationService.is_suspicious_ip(self.user, first)
        )

    def test_first_login_is_not_new_device(self):
        first = _session(self.user)
        self.assertFalse(
            LoginNotificationService.is_new_device(self.user, first)
        )

    def test_first_login_sends_no_email_at_all(self):
        # End-to-end slice: this is the exact path that fired the incident.
        first = _session(self.user)
        with patch("stapel_auth.tasks._send_login_alert_email") as send:
            from stapel_auth.tasks import evaluate_login_notification
            evaluate_login_notification(str(self.user.id), str(first.id))
        send.assert_not_called()

    def test_first_login_is_not_flagged_suspicious_in_the_log(self):
        # The flag is visible to the user under "My sessions" — no false
        # alarm should show up there either.
        first = _session(self.user)
        from stapel_auth.tasks import evaluate_login_notification
        evaluate_login_notification(str(self.user.id), str(first.id))
        first.refresh_from_db()
        self.assertFalse(first.is_suspicious)

    def test_history_from_a_revoked_session_still_counts_as_history(self):
        # `_has_login_history` is deliberately broader than the predicates:
        # a revoked, year-old login is still proof the user isn't new, so an
        # unfamiliar network after it is a genuine signal.
        _session(
            self.user,
            ip_address="198.51.100.7",
            is_revoked=True,
            created_at=timezone.now() - timedelta(days=400),
        )
        second = _session(self.user, ip_address="203.0.113.20")
        self.assertTrue(
            LoginNotificationService.is_suspicious_ip(self.user, second)
        )


class WatchdogStillWorksTests(TestCase):
    """Fixing the cold start must not deafen the watchdog."""

    def setUp(self):
        self.user = _user()

    def test_second_login_from_a_different_network_is_suspicious(self):
        _session(self.user, ip_address="198.51.100.7")
        second = _session(self.user, ip_address="203.0.113.20")
        self.assertTrue(
            LoginNotificationService.is_suspicious_ip(self.user, second)
        )

    def test_second_login_from_a_new_device_is_a_new_device(self):
        _session(self.user, device_name="Old Laptop")
        second = _session(self.user, device_name="Brand New Phone")
        self.assertTrue(
            LoginNotificationService.is_new_device(self.user, second)
        )

    @override_settings(STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": True})
    def test_a_genuinely_suspicious_login_reaches_the_email(self):
        _session(self.user, ip_address="198.51.100.7")
        second = _session(self.user, ip_address="203.0.113.20")
        with patch("stapel_auth.tasks._send_login_alert_email") as send:
            from stapel_auth.tasks import evaluate_login_notification
            evaluate_login_notification(str(self.user.id), str(second.id))
        send.assert_called_once()
        # Third positional arg is is_suspicious: the email must be the
        # alarmed variant, not "new device".
        self.assertTrue(send.call_args[0][2])


class SwitchTests(TestCase):
    """`LOGIN_NOTIFICATION_ENABLED` has to actually mean something."""

    def setUp(self):
        self.user = _user()
        _session(self.user, ip_address="198.51.100.7")
        self.session = _session(self.user, ip_address="203.0.113.20")

    @override_settings(STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": False})
    def test_switch_off_sends_nothing(self):
        with patch("stapel_core.notifications.request_notification") as req:
            from stapel_auth.tasks import _send_login_alert_email
            _send_login_alert_email(self.user, self.session, True)
        req.assert_not_called()

    @override_settings(
        STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": True, "FRONTEND_URL": "https://x.dev"}
    )
    def test_switch_on_sends(self):
        with patch("stapel_core.notifications.request_notification") as req:
            from stapel_auth.tasks import _send_login_alert_email
            _send_login_alert_email(self.user, self.session, True)
        req.assert_called_once()

    def test_default_is_off(self):
        # Documented default is False. The code used to disagree, and the
        # mismatch cost the product its first impression.
        from stapel_auth.conf import auth_settings
        self.assertFalse(auth_settings.LOGIN_NOTIFICATION_ENABLED)

    @override_settings(STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": False})
    def test_switch_suppresses_the_email_but_not_the_audit_log(self):
        # It's about the mailing, not about whether the security log gets
        # written: a user checking "My sessions" must still see the flag
        # even with emails switched off.
        with patch("stapel_auth.tasks._send_login_alert_email") as send:
            from stapel_auth.tasks import evaluate_login_notification
            evaluate_login_notification(str(self.user.id), str(self.session.id))
        send.assert_called_once()  # the send decision happens inside

        with patch("stapel_core.notifications.request_notification") as req:
            from stapel_auth.tasks import evaluate_login_notification
            evaluate_login_notification(str(self.user.id), str(self.session.id))
        req.assert_not_called()

        self.session.refresh_from_db()
        self.assertTrue(self.session.is_suspicious)
        from stapel_auth.models import AuthAuditLog, AuthEventType
        self.assertTrue(
            AuthAuditLog.objects.filter(
                user=self.user, event_type=AuthEventType.SUSPICIOUS_LOGIN
            ).exists()
        )
