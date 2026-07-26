# Флоу

| ID | Название | Шагов |
|---|---|---|
| [`auth.first_login`](auth.first_login.md) | Первый вход орг-провиженной учётной записи | 5 |
| [`auth.password_login`](auth.password_login.md) | Вход по паролю (+ опциональный TOTP) | 3 |
| [`auth.passwordless_login`](auth.passwordless_login.md) | Вход без пароля (email OTP) | 4 |
| [`auth.step_up_verification`](auth.step_up_verification.md) | Step-up-верификация на защищённом эндпоинте (референсный флоу) | 7 |

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
