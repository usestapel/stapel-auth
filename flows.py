"""Business flows of the auth service (stapel_core.flows).

Autodiscovered via INSTALLED_APPS by ``autodiscover_flows()`` (the
``check_flows`` / ``generate_flow_docs`` management commands run it).

HTTP steps are attached here, post-hoc, by decorating the already-imported
view methods: views must not import this module (flows.py imports the view
classes — the dependency points one way, so no import cycle), and
``@flow_step`` only annotates the callable, so decorating after class
creation is equivalent to stacking the decorator in the view module.
"""
from stapel_core.flows import Flow, flow_step

from stapel_auth.mfa.views import TOTPViewSet
from stapel_auth.otp.views import AuthViewSet
from stapel_auth.password.views import PasswordViewSet
from stapel_auth.verification.views import VerificationViewSet

# ─────────────────────────────────────────────────────────────────────────────
# auth.passwordless_login
# ─────────────────────────────────────────────────────────────────────────────

PASSWORDLESS_LOGIN = Flow(
    "auth.passwordless_login",
    title="Вход без пароля (email OTP)",
    description=(
        "Анонимный пользователь получает одноразовый код на почту и обменивает "
        "его на JWT-сессию (cookies + пара токенов в теле ответа). Повторный "
        "запрос кода ограничен рейт-лимитом (30 секунд между отправками, 429/422 "
        "при превышении); после серии неверных кодов адрес временно блокируется. "
        "Если адрес не был зарегистрирован, при первом успешном входе создаётся "
        "новый пользователь (status=REGISTERED вместо LOGGED_IN)."
    ),
    actors=["Анонимный пользователь"],
)

PASSWORDLESS_LOGIN.human(order=0, note="Пользователь вводит email на форме входа")
flow_step(
    PASSWORDLESS_LOGIN, order=1,
    note="Запросить одноразовый код на email; 429 при рейт-лимите, 422 при блокировке",
)(AuthViewSet.email_request)
flow_step(
    PASSWORDLESS_LOGIN, order=2,
    note="Обменять код на JWT-сессию; неверный код уменьшает счётчик попыток",
)(AuthViewSet.email_verify)
PASSWORDLESS_LOGIN.action(
    "user.registered", order=3,
    note="Эмитится при первом входе — профиль и воркспейс создаются подписчиками",
)

# ─────────────────────────────────────────────────────────────────────────────
# auth.password_login
# ─────────────────────────────────────────────────────────────────────────────

PASSWORD_LOGIN = Flow(
    "auth.password_login",
    title="Вход по паролю (+ опциональный TOTP)",
    description=(
        "Пользователь входит по логину (email/username) и паролю. Эндпоинт "
        "включается настройкой AUTH_PASSWORD_LOGIN. Неудачные попытки ведут к "
        "прогрессивной блокировке (423 c retry_after). Если у пользователя "
        "включён TOTP и настройка PASSWORD_LOGIN_STEP_UP активна (по умолчанию "
        "да), вместо токенов возвращается TOTP_REQUIRED c challenge_token — "
        "сессия выдаётся только после проверки кода аутентификатора."
    ),
    actors=["Анонимный пользователь"],
)

PASSWORD_LOGIN.human(order=0, note="Пользователь вводит логин и пароль на форме входа")
flow_step(
    PASSWORD_LOGIN, order=1,
    note=(
        "Проверить пароль; 423 при блокировке; при включённом TOTP и "
        "PASSWORD_LOGIN_STEP_UP — ответ TOTP_REQUIRED c challenge_token"
    ),
)(PasswordViewSet.login)
flow_step(
    PASSWORD_LOGIN, order=2,
    note=(
        "Опциональный шаг (только при TOTP_REQUIRED): обменять challenge_token "
        "и код аутентификатора на JWT-сессию"
    ),
)(TOTPViewSet.challenge_verify)

# ─────────────────────────────────────────────────────────────────────────────
# auth.step_up_verification — THE reference flow for the verification contract
# ─────────────────────────────────────────────────────────────────────────────

STEP_UP_VERIFICATION = Flow(
    "auth.step_up_verification",
    title="Step-up-верификация на защищённом эндпоинте (референсный флоу)",
    description=(
        "РЕФЕРЕНСНЫЙ флоу контракта step-up-верификации "
        "(stapel_core.verification, см. flows-and-verification.md §2) — клиенты "
        "любого сервиса реализуют его один раз и переиспользуют для всех "
        "эндпоинтов, защищённых @requires_verification. Цикл: защищённый "
        "эндпоинт отвечает 403 со структурированным конвертом verification "
        "(challenge_id, scope, factors, expires_at) → клиент читает challenge, "
        "выбирает доступный фактор (факторы взаимозаменяемы: otp_email, "
        "otp_phone, totp, passkey закрывают один challenge), инициирует его и "
        "завершает проверку → повторяет исходный запрос. Grant хранится "
        "сервер-сайд (cache, ключ user+scope, TTL=max_age); stateless-клиенты "
        "могут вместо этого прислать заголовок X-Verification-Token из ответа "
        "завершения. После MAX_ATTEMPTS неверных попыток challenge сгорает "
        "(423) — нужно снова вызвать исходный эндпоинт за новым challenge."
    ),
    actors=["Аутентифицированный пользователь"],
)

STEP_UP_VERIFICATION.human(
    order=0,
    note=(
        "Клиент вызывает защищённый эндпоинт и получает 403 с конвертом "
        "verification: challenge_id, scope, factors, expires_at"
    ),
)
flow_step(
    STEP_UP_VERIFICATION, order=1,
    note=(
        "Прочитать challenge: scope и факторы, отфильтрованные до реально "
        "доступных пользователю; 404 для чужого/истёкшего challenge"
    ),
)(VerificationViewSet.info)
flow_step(
    STEP_UP_VERIFICATION, order=2,
    note=(
        "Инициировать выбранный фактор: отправить код (otp_email/otp_phone) "
        "или получить WebAuthn-опции (passkey); totp инициации не требует"
    ),
)(VerificationViewSet.initiate)
flow_step(
    STEP_UP_VERIFICATION, order=3,
    note=(
        "Завершить challenge доказательством фактора; успех = "
        "{verified, verification_token} + grant сервер-сайд; 400 при неверном "
        "коде, 423 когда challenge сгорел от перебора"
    ),
)(VerificationViewSet.complete)
STEP_UP_VERIFICATION.human(
    order=4,
    note=(
        "Повторить исходный запрос — grant уже на сервере; stateless-клиент "
        "передаёт X-Verification-Token из ответа завершения"
    ),
)

__all__ = ["PASSWORDLESS_LOGIN", "PASSWORD_LOGIN", "STEP_UP_VERIFICATION"]
