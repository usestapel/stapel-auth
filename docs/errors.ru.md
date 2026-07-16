# Errors — Русский

`119` error keys. Canonical texts live in the code (`register_service_errors`); localized texts in `translations/errors.ru.json`.

| Код | Статус | Параметры | Действие | Текст |
|---|---|---|---|---|
| `error.400.bad_request` | 400 | — | `fix_input` | Некорректный запрос |
| `error.400.captcha_invalid` | 400 | — | `retry` | Проверка капчи не пройдена. Пожалуйста, попробуйте ещё раз. |
| `error.400.captcha_required` | 400 | — | `retry` | Требуется токен капчи. |
| `error.400.code_expired` | 400 | — | `retry` | Срок действия кода подтверждения истёк. Пожалуйста, запросите новый. |
| `error.400.code_required` | 400 | — | `fix_input` | Требуется код подтверждения. |
| `error.400.credentials_required` | 400 | — | `fix_input` | Необходимо указать имя пользователя или адрес электронной почты и пароль |
| `error.400.email_or_phone_not_both` | 400 | — | `fix_input` | Укажите либо адрес электронной почты, либо номер телефона, но не оба |
| `error.400.email_or_phone_required` | 400 | — | `fix_input` | Необходимо указать адрес электронной почты или номер телефона |
| `error.400.email_required` | 400 | — | `fix_input` | Необходимо указать адрес электронной почты. |
| `error.400.expected_list` | 400 | — | `fix_input` | Ожидался список элементов |
| `error.400.field.blank` | 400 | `field` | `fix_input` | Поле «{field}» не может быть пустым |
| `error.400.field.does_not_exist` | 400 | `field` | `fix_input` | «{field}» не существует |
| `error.400.field.invalid` | 400 | `field` | `fix_input` | Поле «{field}» содержит недопустимое значение |
| `error.400.field.invalid_choice` | 400 | `field` | `fix_input` | Недопустимый вариант для поля «{field}» |
| `error.400.field.max_length` | 400 | `field`, `max_length` | `fix_input` | Поле «{field}» должно содержать не более {max_length} символов |
| `error.400.field.max_value` | 400 | `field`, `max_value` | `fix_input` | Значение поля «{field}» должно быть не больше {max_value} |
| `error.400.field.min_length` | 400 | `field`, `min_length` | `fix_input` | Поле «{field}» должно содержать не менее {min_length} символов |
| `error.400.field.min_value` | 400 | `field`, `min_value` | `fix_input` | Значение поля «{field}» должно быть не меньше {min_value} |
| `error.400.field.null` | 400 | `field` | `fix_input` | Поле «{field}» не может быть null |
| `error.400.field.required` | 400 | `field` | `fix_input` | Поле «{field}» обязательно |
| `error.400.field.unique` | 400 | `field` | `fix_input` | Значение поля «{field}» должно быть уникальным |
| `error.400.invalid_ad_id` | 400 | — | `fix_input` | Недопустимый идентификатор объявления |
| `error.400.invalid_change_token` | 400 | — | `retry` | Недействительный или просроченный токен изменения. |
| `error.400.invalid_code` | 400 | — | `fix_input` | Неверный код подтверждения |
| `error.400.invalid_code_attempts` | 400 | `attempts_remaining` | `fix_input` | Неверный код подтверждения. Осталось попыток: {attempts_remaining}. |
| `error.400.invalid_method` | 400 | — | `fix_input` | Недопустимый или недоступный способ для этой учётной записи. |
| `error.400.invalid_phone` | 400 | — | `fix_input` | Неверный номер телефона |
| `error.400.invalid_phone_format` | 400 | — | `fix_input` | Неверный формат номера телефона |
| `error.400.invalid_redirect_url` | 400 | — | `fix_input` | redirect_url должен быть относительным путём, начинающимся с / — абсолютные URL не допускаются. |
| `error.400.last_auth_method` | 400 | — | `fix_input` | Нельзя удалить последний способ входа. |
| `error.400.magic_link_invalid` | 400 | — | `retry` | Ссылка для входа недействительна или её срок действия истёк. |
| `error.400.no_current_value` | 400 | — | `fix_input` | У этой учётной записи нет текущего значения. |
| `error.400.no_password` | 400 | — | `fix_input` | Пароль не установлен. Сначала установите пароль. |
| `error.400.no_verified_contact` | 400 | — | `verify` | У этой учётной записи нет подтверждённого адреса электронной почты или номера телефона. |
| `error.400.not_available` | 400 | — | `fix_input` | Это значение уже зарегистрировано или зарезервировано. |
| `error.400.oauth_failed` | 400 | — | `retry` | Не удалось выполнить аутентификацию через провайдера OAuth |
| `error.400.oauth_fields_required` | 400 | — | `fix_input` | Необходимо указать provider и access_token |
| `error.400.passkey_challenge_expired` | 400 | — | `retry` | Срок действия запроса для ключа доступа истёк. Пожалуйста, попробуйте ещё раз. |
| `error.400.passkey_invalid` | 400 | — | `retry` | Не удалось выполнить проверку ключа доступа. |
| `error.400.password_already_set` | 400 | — | `fix_input` | Пароль уже установлен. Используйте смену пароля. |
| `error.400.passwords_dont_match` | 400 | — | `fix_input` | Пароли не совпадают |
| `error.400.phone_required` | 400 | — | `fix_input` | Необходимо указать номер телефона. |
| `error.400.phone_too_long` | 400 | — | `fix_input` | Номер телефона слишком длинный |
| `error.400.qr_expired` | 400 | — | `retry` | Срок действия QR-кода истёк. |
| `error.400.qr_fulfilled` | 400 | — | `retry` | QR-код уже был использован. |
| `error.400.qr_type_required` | 400 | — | `fix_input` | Необходимо указать тип QR-кода (session_share или login_request). |
| `error.400.sso_invalid_response` | 400 | — | `retry` | Недействительный ответ SSO от провайдера идентификации. |
| `error.400.sso_not_configured` | 400 | — | `contact_support` | SSO не настроен для этой организации. |
| `error.400.staff_role_target_not_staff` | 400 | — | `fix_input` | Служебные роли можно назначать только служебным учётным записям. Сначала сделайте пользователя сотрудником. |
| `error.400.token_required` | 400 | — | `fix_input` | Требуется токен |
| `error.400.totp_not_pending` | 400 | — | `retry` | Нет незавершённой настройки TOTP. Сначала вызовите /totp/setup/. |
| `error.400.unknown_staff_role` | 400 | — | `fix_input` | Неизвестная служебная роль. Сначала определите её в конфигурации развёртывания STAPEL_ACCESS["ROLES"]. |
| `error.400.validation_error` | 400 | — | `fix_input` | Ошибка валидации |
| `error.400.verification_failed` | 400 | — | `verify` | Проверка не пройдена |
| `error.400.verification_invalid_factor` | 400 | — | `verify` | Этот способ подтверждения недоступен |
| `error.400.wrong_password` | 400 | — | `fix_input` | Неверный пароль. |
| `error.401.account_disabled` | 401 | — | `contact_support` | Учётная запись пользователя отключена |
| `error.401.invalid_credentials` | 401 | — | `reauthenticate` | Неверные учётные данные |
| `error.401.qr_auth_required` | 401 | — | `reauthenticate` | Для создания QR-кода session_share требуется аутентификация. |
| `error.401.refresh_invalid` | 401 | — | `reauthenticate` | Недействительный или просроченный refresh-токен |
| `error.401.refresh_not_provided` | 401 | — | `reauthenticate` | Refresh-токен не предоставлен |
| `error.401.refresh_revoked` | 401 | — | `reauthenticate` | Токен был отозван |
| `error.401.token_invalid` | 401 | — | `reauthenticate` | Недействительный токен |
| `error.401.token_revoked` | 401 | — | `reauthenticate` | Токен был отозван |
| `error.401.unauthorized` | 401 | — | `reauthenticate` | Требуется аутентификация |
| `error.401.user_not_found` | 401 | — | `reauthenticate` | Пользователь не найден |
| `error.402.payment_required` | 402 | — | `retry` | Требуется оплата |
| `error.403.forbidden` | 403 | — | `retry` | У вас нет прав для выполнения этого действия |
| `error.403.mock_otp_admin` | 403 | — | `contact_support` | Аутентификация по OTP отключена для учётных записей администраторов в mock-режиме. |
| `error.403.network_blocked` | 403 | — | `contact_support` | Запросы из этой сети не разрешены. |
| `error.403.qr_device_mismatch` | 403 | — | `retry` | Этот QR-код принадлежит другому устройству. |
| `error.403.qr_unauth_scan` | 403 | — | `reauthenticate` | Этот QR-код нельзя отсканировать с неаутентифицированного устройства. |
| `error.403.sso_required` | 403 | — | `reauthenticate` | Для этой учётной записи вход возможен только через SSO. Используйте SSO-ссылку вашей организации. |
| `error.403.step_up_required` | 403 | — | `verify` | Для этого действия требуется подтверждение TOTP. Сначала получите step-up-токен. |
| `error.403.verification_enrollment_required` | 403 | — | `verify` | Требуется регистрация фактора подтверждения. |
| `error.403.verification_required` | 403 | — | `verify` | Требуется дополнительная проверка |
| `error.404.ad_not_found` | 404 | — | `retry` | Объявление не найдено |
| `error.404.change_not_found` | 404 | — | `retry` | Запрос на изменение не найден. |
| `error.404.gdpr.export_not_found` | 404 | — | `retry` | Запрос на экспорт не найден. |
| `error.404.gdpr.no_active_closure` | 404 | — | `fix_input` | Незавершённый запрос на закрытие учётной записи не найден. |
| `error.404.not_found` | 404 | — | `retry` | Запрошенный ресурс не найден |
| `error.404.oauth_link_not_found` | 404 | — | `retry` | Привязанная учётная запись для этого провайдера не найдена. |
| `error.404.passkey_not_found` | 404 | — | `retry` | Ключ доступа не найден. |
| `error.404.qr_not_found` | 404 | — | `retry` | QR-код не найден или истёк. |
| `error.404.sso_org_not_found` | 404 | — | `fix_input` | Организация не найдена. |
| `error.404.user_for_reset` | 404 | — | `fix_input` | Учётная запись с таким адресом электронной почты или номером телефона не найдена. |
| `error.404.verification_challenge_not_found` | 404 | — | `verify` | Запрос на подтверждение не найден или истёк |
| `error.405.method_not_allowed` | 405 | — | `retry` | Метод не разрешён |
| `error.406.not_acceptable` | 406 | — | `retry` | Недопустимый формат ответа |
| `error.408.request_timeout` | 408 | — | `retry` | Время ожидания запроса истекло |
| `error.409.conflict` | 409 | — | `fix_input` | Ресурс уже существует |
| `error.409.email_reserved` | 409 | — | `fix_input` | Этот адрес электронной почты зарезервирован другим незавершённым запросом на изменение. |
| `error.409.email_taken` | 409 | — | `fix_input` | Этот адрес электронной почты уже привязан к другой учётной записи. |
| `error.409.gdpr.closure_already_pending` | 409 | — | `fix_input` | Закрытие учётной записи уже выполняется. |
| `error.409.gdpr.export_cooldown` | 409 | — | `fix_input` | Экспорт данных уже был запрошен за последние 30 дней. |
| `error.409.gdpr.legal_hold` | 409 | — | `fix_input` | Данные учётной записи находятся под юридическим удержанием и не могут быть удалены. |
| `error.409.oauth_account_linked_elsewhere` | 409 | — | `fix_input` | Эта учётная запись провайдера уже привязана к другому пользователю. |
| `error.409.oauth_already_linked` | 409 | — | `fix_input` | Этот провайдер уже привязан к вашей учётной записи. |
| `error.409.passkey_already_registered` | 409 | — | `fix_input` | Этот ключ доступа уже зарегистрирован. |
| `error.409.phone_reserved` | 409 | — | `fix_input` | Этот номер телефона зарезервирован другим незавершённым запросом на изменение. |
| `error.409.phone_taken` | 409 | — | `fix_input` | Этот номер телефона уже привязан к другой учётной записи. |
| `error.409.qr_account_conflict` | 409 | — | `reauthenticate` | На этом устройстве уже выполнен вход в другую учётную запись. |
| `error.409.sso_org_slug_taken` | 409 | — | `fix_input` | Организация с таким slug уже существует. |
| `error.409.username_taken` | 409 | — | `fix_input` | Это имя пользователя уже занято. |
| `error.410.gdpr.download_expired` | 410 | — | `retry` | Срок действия ссылки для скачивания истёк. |
| `error.410.gone` | 410 | — | `retry` | Ресурс был безвозвратно удалён |
| `error.413.payload_too_large` | 413 | — | `retry` | Тело запроса слишком большое |
| `error.415.unsupported_media_type` | 415 | — | `retry` | Неподдерживаемый тип данных |
| `error.422.blocked` | 422 | `retry_after_minutes` | `wait_and_retry` | Учётная запись временно заблокирована. Повторите попытку через {retry_after_minutes} мин. |
| `error.422.unprocessable_entity` | 422 | — | `wait_and_retry` | Невозможно обработать данные запроса |
| `error.423.account_locked` | 423 | `retry_after_minutes` | `wait_and_retry` | Учётная запись временно заблокирована из-за слишком большого числа неудачных попыток. Повторите попытку через {retry_after_minutes} мин. |
| `error.423.locked` | 423 | — | `wait_and_retry` | Ресурс заблокирован |
| `error.423.verification_locked` | 423 | — | `wait_and_retry` | Слишком много неудачных попыток — подтверждение заблокировано |
| `error.425.gdpr.export_not_ready` | 425 | — | `retry` | Экспорт ещё готовится. |
| `error.429.magic_link_rate` | 429 | — | `wait_and_retry` | Слишком много запросов ссылки для входа. Пожалуйста, повторите попытку позже. |
| `error.429.rate_limit` | 429 | `retry_after_minutes` | `wait_and_retry` | Слишком много попыток. Повторите попытку через {retry_after_minutes} мин. |
| `error.429.too_many_requests` | 429 | — | `wait_and_retry` | Слишком много запросов. Пожалуйста, повторите попытку позже. |
| `error.500.internal` | 500 | — | `contact_support` | Что-то пошло не так |
| `error.500.send_failed` | 500 | — | `retry` | Не удалось отправить код подтверждения |
