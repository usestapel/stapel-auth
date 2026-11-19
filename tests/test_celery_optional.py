"""A sign-in never fails because the login alert could not be enqueued.

Session issuance hands the login alert to ``tasks.evaluate_login_notification``.
That module imported celery unconditionally, and celery is not a declared
dependency: a project without it answered every sign-in with a 500. With
celery present, a broker that refuses the message (down, unreachable, or the
unconfigured default app a threaded server binds ``@shared_task`` to) did the
same. Celery is now the optional ``celery`` extra:

* without it the task functions are plain callables and the alert is
  evaluated in the request (``stapel_auth.W014`` says so);
* with it, a failed enqueue falls back to the same in-request evaluation.
"""
import importlib.util
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_auth.models import UserSession

User = get_user_model()
_PW = "Sign-in-pass-123!"
_TASKS = Path(__file__).resolve().parent.parent / "tasks.py"


def _tasks_without_celery():
    """``stapel_auth.tasks`` as a process without celery imports it."""
    spec = importlib.util.spec_from_file_location("stapel_auth.tasks", _TASKS)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"celery": None}):
        spec.loader.exec_module(module)
    return module


class TasksModuleWithoutCelery(SimpleTestCase):
    def test_imports_and_exposes_plain_callables(self):
        module = _tasks_without_celery()
        self.assertFalse(module.CELERY_AVAILABLE)
        for name in ("evaluate_login_notification", "send_change_notifications",
                     "execute_pending_changes", "cleanup_expired_requests"):
            self.assertTrue(callable(getattr(module, name)))
            self.assertFalse(hasattr(getattr(module, name), "delay"), name)

    def test_with_celery_they_are_tasks_under_the_same_names(self):
        from stapel_auth import tasks

        self.assertTrue(tasks.CELERY_AVAILABLE)
        self.assertEqual(
            tasks.evaluate_login_notification.name,
            "stapel_auth.tasks.evaluate_login_notification",
        )

    def test_w014_fires_only_without_celery(self):
        from stapel_auth.checks import W014_NO_TASK_RUNNER, check_task_runner

        self.assertEqual(check_task_runner(), [])
        with patch.dict(sys.modules, {"stapel_auth.tasks": _tasks_without_celery()}):
            self.assertEqual([w.id for w in check_task_runner()], [W014_NO_TASK_RUNNER])


@override_settings(URL_PREFIX="", STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True})
class SignInSurvivesTheAlert(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            email=f"{uuid.uuid4().hex[:8]}@example.com",
            username=uuid.uuid4().hex[:12],
            password=_PW,
        )

    def _login(self):
        return self.client.post(
            reverse("password_login"),
            {"login": self.user.username, "password": _PW},
            format="json",
        )

    def _assert_signed_in(self, response):
        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
        self.assertEqual(response.data["status"], "LOGGED_IN")
        self.assertTrue(response.data["tokens"]["access"])
        self.assertEqual(UserSession.objects.filter(user=self.user).count(), 1)

    def test_without_celery_the_alert_runs_in_the_request(self):
        module = _tasks_without_celery()
        seen = []
        original = module.evaluate_login_notification

        def spy(*args, **kwargs):
            seen.append(args)
            return original(*args, **kwargs)

        module.evaluate_login_notification = spy
        with patch.dict(sys.modules, {"stapel_auth.tasks": module}):
            response = self._login()
        self._assert_signed_in(response)
        session = UserSession.objects.get(user=self.user)
        self.assertEqual(seen, [(str(self.user.id), str(session.id))])

    def test_a_refused_enqueue_falls_back_to_the_request(self):
        from kombu.exceptions import OperationalError

        with patch(
            "stapel_auth.tasks.evaluate_login_notification.delay",
            side_effect=OperationalError("[Errno 61] Connection refused"),
        ), patch("stapel_auth.tasks._send_login_alert_email") as send, \
                self.assertLogs("stapel_auth.sessions.services", "WARNING"):
            response = self._login()
        self._assert_signed_in(response)
        send.assert_not_called()  # a first-ever login has no history to differ from

    def test_an_unreachable_broker_does_not_fail_the_sign_in(self):
        """A real non-eager app whose broker nobody listens on."""
        from celery import Celery
        from celery._state import get_current_app

        previous = get_current_app()
        app = Celery("stapel_auth_unreachable")
        app.config_from_object({
            "broker_url": "amqp://guest:guest@127.0.0.1:9//",
            "broker_connection_retry": False,
            "broker_connection_max_retries": 0,
            "broker_connection_timeout": 1,
            "task_publish_retry": False,
        })
        app.set_current()
        try:
            with self.assertLogs("stapel_auth.sessions.services", "WARNING") as logs:
                response = self._login()
        finally:
            previous.set_current()
        self._assert_signed_in(response)
        # The broker really was tried and refused — not an eager run.
        self.assertTrue(any("enqueue failed" in line for line in logs.output), logs.output)

    def test_a_failing_evaluation_does_not_fail_the_sign_in(self):
        module = _tasks_without_celery()

        def broken(*args, **kwargs):
            raise RuntimeError("notification service down")

        module.evaluate_login_notification = broken
        with patch.dict(sys.modules, {"stapel_auth.tasks": module}):
            response = self._login()
        self._assert_signed_in(response)
