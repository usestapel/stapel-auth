[English](../en/README.md) · **Русский**

# Флоу

### [Первый вход орг-провиженной учётной записи](auth.first_login.md)

`auth.first_login` · 5 шагов · Актор(ы): Org-provisioned user

Администратор организации создал учётную запись (auth.provision_user: неймспейсный логин org_slug/local, пароль от организации или сгенерированный сервером, флаг политики первого входа). Первый вход по паролю возвращает FIRST_LOGIN_REQUIRED с 10-минутным challenge_token вместо сессии: requires=password_change ведёт к обязательной смене пароля, requires=mfa_enroll — к ограниченной enroll-сессии, в которой доступны только настройка/подтверждение TOTP, регистрация ключа доступа и выход. Завершение шага снимает флаг и выдаёт полную сессию; если выставлены оба флага, смена пароля сразу переходит в челлендж mfa_enroll.

### [Вход по паролю (+ опциональный TOTP)](auth.password_login.md)

`auth.password_login` · 3 шагов · Актор(ы): Anonymous user

Пользователь входит по логину (email/username) и паролю. Эндпоинт включается настройкой AUTH_PASSWORD_LOGIN. Неудачные попытки ведут к прогрессивной блокировке (423 c retry_after). Если у пользователя включён TOTP и настройка PASSWORD_LOGIN_STEP_UP активна (по умолчанию да), вместо токенов возвращается TOTP_REQUIRED c challenge_token — сессия выдаётся только после проверки кода аутентификатора.

### [Вход без пароля (email OTP)](auth.passwordless_login.md)

`auth.passwordless_login` · 4 шагов · Актор(ы): Anonymous user

Анонимный пользователь получает одноразовый код на почту и обменивает его на JWT-сессию (cookies + пара токенов в теле ответа). Повторный запрос кода ограничен рейт-лимитом (30 секунд между отправками, 429/422 при превышении); после серии неверных кодов адрес временно блокируется. Если адрес не был зарегистрирован, при первом успешном входе создаётся новый пользователь (status=REGISTERED вместо LOGGED_IN).

### [Step-up-верификация на защищённом эндпоинте (референсный флоу)](auth.step_up_verification.md)

`auth.step_up_verification` · 7 шагов · Актор(ы): Authenticated user

РЕФЕРЕНСНЫЙ флоу контракта step-up-верификации (stapel_core.verification, см. flows-and-verification.md §2) — клиенты любого сервиса реализуют его один раз и переиспользуют для всех эндпоинтов, защищённых @requires_verification. Цикл: защищённый эндпоинт отвечает 403 со структурированным конвертом verification (challenge_id, scope, factors, expires_at) → клиент читает challenge, выбирает доступный фактор (факторы взаимозаменяемы: otp_email, otp_phone, totp, passkey закрывают один challenge), инициирует его и завершает проверку → повторяет исходный запрос. Grant хранится сервер-сайд (cache, ключ user+scope, TTL=max_age); stateless-клиенты могут вместо этого прислать заголовок X-Verification-Token из ответа завершения. После MAX_ATTEMPTS неверных попыток challenge сгорает (423) — нужно снова вызвать исходный эндпоинт за новым challenge.

## Эндпоинт → флоу

- `GET /auth/api/v1/verification/<str:challenge_id>/` → auth.step_up_verification
- `GET /auth/api/v1/verification/preferences/` → auth.step_up_verification
- `POST /auth/api/v1/email/request/` → auth.passwordless_login
- `POST /auth/api/v1/email/verify/` → auth.passwordless_login
- `POST /auth/api/v1/mfa/enroll/exchange/` → auth.first_login
- `POST /auth/api/v1/password/forced-change/` → auth.first_login
- `POST /auth/api/v1/password/login/` → auth.first_login, auth.password_login
- `POST /auth/api/v1/totp/challenge/verify/` → auth.password_login
- `POST /auth/api/v1/totp/setup/confirm/` → auth.first_login
- `POST /auth/api/v1/verification/<str:challenge_id>/complete/` → auth.step_up_verification
- `POST /auth/api/v1/verification/<str:challenge_id>/initiate/` → auth.step_up_verification
- `PUT /auth/api/v1/verification/preferences/` → auth.step_up_verification
