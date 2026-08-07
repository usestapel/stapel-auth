"""Первый в жизни вход не может быть подозрительным.

ИНЦИДЕНТ 08.08.2026, миттудей. Человека позвали по ссылке на встречу в
приватном спейсе. Он вошёл впервые — и через минуту получил письмо
«ОБНАРУЖЕН ПОДОЗРИТЕЛЬНЫЙ ВХОД» с красной кнопкой «Это не я — завершить все
сеансы». Разбор Олега: «первое знакомство с брендом — тревога на пустом
месте».

ПРИЧИНА. Оба предиката сторожа спрашивают «отличается ли этот вход от
прежних», и оба выражены отрицанием существования:

    not UserSession.objects.filter(...).exclude(id=session.id).exists()

У человека без истории множество пусто, отрицание истинно, и ответ «да,
отличается» приходит ГАРАНТИРОВАННО — не как вывод, а как свойство пустого
множества. То есть письмо получал каждый новый пользователь, всегда.

ВТОРОЙ ДЕФЕКТ, найденный тем же разбором: `LOGIN_NOTIFICATION_ENABLED`
существовал в `DEFAULTS` (дефолт False) и в MODULE.md, но его не читал НИКТО.
Развёртывание не могло погасить рассылку штатно вообще никак, а
задокументированный дефолт обещал ровно обратное — «выключено». Тесты ниже
пришпиливают обе стороны выключателя, чтобы он не смог снова стать
документацией.
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


class ХолодныйСтарт(TestCase):
    """У человека без истории входов сравнивать не с чем."""

    def setUp(self):
        self.user = _user()

    def test_первый_вход_не_подозрительная_сеть(self):
        first = _session(self.user)
        self.assertFalse(
            LoginNotificationService.is_suspicious_ip(self.user, first)
        )

    def test_первый_вход_не_новое_устройство(self):
        first = _session(self.user)
        self.assertFalse(
            LoginNotificationService.is_new_device(self.user, first)
        )

    def test_первый_вход_не_шлёт_письма_вообще(self):
        # Сквозной срез: именно этот путь и написал Елене.
        first = _session(self.user)
        with patch("stapel_auth.tasks._send_login_alert_email") as send:
            from stapel_auth.tasks import evaluate_login_notification
            evaluate_login_notification(str(self.user.id), str(first.id))
        send.assert_not_called()

    def test_первый_вход_не_помечается_подозрительным_в_журнале(self):
        # Пометка видна человеку в «Мои сессии» — там тоже не должно быть
        # тревоги на пустом месте.
        first = _session(self.user)
        from stapel_auth.tasks import evaluate_login_notification
        evaluate_login_notification(str(self.user.id), str(first.id))
        first.refresh_from_db()
        self.assertFalse(first.is_suspicious)

    def test_история_из_отозванной_сессии_всё_равно_история(self):
        # `_has_login_history` намеренно шире предикатов: отозванный вход
        # годичной давности — всё ещё доказательство, что человек не новичок,
        # и незнакомая сеть после него уже настоящий сигнал.
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


class СторожПродолжаетРаботать(TestCase):
    """Починка холодного старта не должна оглушить сторожа."""

    def setUp(self):
        self.user = _user()

    def test_второй_вход_из_чужой_сети_подозрителен(self):
        _session(self.user, ip_address="198.51.100.7")
        second = _session(self.user, ip_address="203.0.113.20")
        self.assertTrue(
            LoginNotificationService.is_suspicious_ip(self.user, second)
        )

    def test_второй_вход_с_нового_устройства_новое_устройство(self):
        _session(self.user, device_name="Old Laptop")
        second = _session(self.user, device_name="Brand New Phone")
        self.assertTrue(
            LoginNotificationService.is_new_device(self.user, second)
        )

    @override_settings(STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": True})
    def test_настоящий_подозрительный_вход_доезжает_до_письма(self):
        _session(self.user, ip_address="198.51.100.7")
        second = _session(self.user, ip_address="203.0.113.20")
        with patch("stapel_auth.tasks._send_login_alert_email") as send:
            from stapel_auth.tasks import evaluate_login_notification
            evaluate_login_notification(str(self.user.id), str(second.id))
        send.assert_called_once()
        # Третий позиционный аргумент — is_suspicious: письмо должно быть
        # тревожным, а не «новое устройство».
        self.assertTrue(send.call_args[0][2])


class Выключатель(TestCase):
    """`LOGIN_NOTIFICATION_ENABLED` обязан что-то значить."""

    def setUp(self):
        self.user = _user()
        _session(self.user, ip_address="198.51.100.7")
        self.session = _session(self.user, ip_address="203.0.113.20")

    @override_settings(STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": False})
    def test_выключенный_не_шлёт(self):
        with patch("stapel_core.notifications.request_notification") as req:
            from stapel_auth.tasks import _send_login_alert_email
            _send_login_alert_email(self.user, self.session, True)
        req.assert_not_called()

    @override_settings(
        STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": True, "FRONTEND_URL": "https://x.dev"}
    )
    def test_включённый_шлёт(self):
        with patch("stapel_core.notifications.request_notification") as req:
            from stapel_auth.tasks import _send_login_alert_email
            _send_login_alert_email(self.user, self.session, True)
        req.assert_called_once()

    def test_дефолт_выключен(self):
        # Задокументированный дефолт — False. Раньше код с ним расходился, и
        # расхождение стоило первого впечатления о продукте.
        from stapel_auth.conf import auth_settings
        self.assertFalse(auth_settings.LOGIN_NOTIFICATION_ENABLED)

    @override_settings(STAPEL_AUTH={"LOGIN_NOTIFICATION_ENABLED": False})
    def test_выключатель_гасит_письмо_но_не_журнал(self):
        # Он про рассылку, а не про то, вести ли журнал безопасности:
        # человек, открывший «Мои сессии», обязан увидеть пометку и с
        # выключенными письмами.
        with patch("stapel_auth.tasks._send_login_alert_email") as send:
            from stapel_auth.tasks import evaluate_login_notification
            evaluate_login_notification(str(self.user.id), str(self.session.id))
        send.assert_called_once()  # решение о рассылке принимается внутри

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
