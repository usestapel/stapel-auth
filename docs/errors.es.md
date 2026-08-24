# Errors — Español

`138` error keys. Canonical texts live in the code (`register_service_errors`); localized texts in `translations/errors.es.json`.

| Código | Estado | Parámetros | Acción | Texto |
|---|---|---|---|---|
| `error.400.bad_request` | 400 | — | `fix_input` | Solicitud incorrecta |
| `error.400.captcha_invalid` | 400 | — | `retry` | La verificación del captcha ha fallado. Inténtalo de nuevo. |
| `error.400.captcha_required` | 400 | — | `retry` | Se requiere el token del captcha. |
| `error.400.code_expired` | 400 | — | `retry` | La espera de tu código ha caducado. Vuelve a iniciar sesión. |
| `error.400.code_required` | 400 | — | `fix_input` | Se requiere un código de verificación. |
| `error.400.credentials_required` | 400 | — | `fix_input` | Se requieren nombre de usuario/correo electrónico y contraseña |
| `error.400.email_or_phone_not_both` | 400 | — | `fix_input` | Proporciona un correo electrónico o un teléfono, no ambos |
| `error.400.email_or_phone_required` | 400 | — | `fix_input` | Se requiere un correo electrónico o un número de teléfono |
| `error.400.email_required` | 400 | — | `fix_input` | El correo electrónico es obligatorio. |
| `error.400.expected_list` | 400 | — | `fix_input` | Se esperaba una lista de elementos |
| `error.400.field.blank` | 400 | `field` | `fix_input` | {field} no puede estar vacío |
| `error.400.field.does_not_exist` | 400 | `field` | `fix_input` | {field} no existe |
| `error.400.field.invalid` | 400 | `field` | `fix_input` | {field} no es válido |
| `error.400.field.invalid_choice` | 400 | `field` | `fix_input` | {field} no es una opción válida |
| `error.400.field.max_length` | 400 | `field`, `max_length` | `fix_input` | {field} debe tener como máximo {max_length} caracteres |
| `error.400.field.max_value` | 400 | `field`, `max_value` | `fix_input` | {field} debe ser como máximo {max_value} |
| `error.400.field.min_length` | 400 | `field`, `min_length` | `fix_input` | {field} debe tener al menos {min_length} caracteres |
| `error.400.field.min_value` | 400 | `field`, `min_value` | `fix_input` | {field} debe ser como mínimo {min_value} |
| `error.400.field.null` | 400 | `field` | `fix_input` | {field} no puede ser nulo |
| `error.400.field.required` | 400 | `field` | `fix_input` | {field} es obligatorio |
| `error.400.field.unique` | 400 | `field` | `fix_input` | {field} debe ser único |
| `error.400.first_login_challenge_invalid` | 400 | — | `reauthenticate` | El desafío de primer inicio de sesión no es válido o ha caducado. Vuelve a iniciar sesión para empezar de nuevo. |
| `error.400.gdpr.unknown_dsar_kind` | 400 | — | `fix_input` | Tipo de solicitud de protección de datos desconocido. |
| `error.400.gdpr.unknown_subject_type` | 400 | — | `fix_input` | Este tipo de datos no se puede eliminar a través de este endpoint. |
| `error.400.grant_invalid` | 400 | — | `retry` | La concesión de inicio de sesión no es válida, ya se ha utilizado o ha caducado. |
| `error.400.invalid_ad_id` | 400 | — | `fix_input` | ID de anuncio no válido |
| `error.400.invalid_change_token` | 400 | — | `retry` | Token de cambio no válido o caducado. |
| `error.400.invalid_code` | 400 | — | `fix_input` | Código de verificación no válido |
| `error.400.invalid_code_attempts` | 400 | `attempts_remaining` | `fix_input` | Código de verificación no válido. Quedan {attempts_remaining} intentos. |
| `error.400.invalid_method` | 400 | — | `fix_input` | Método no válido o no disponible para esta cuenta. |
| `error.400.invalid_phone` | 400 | — | `fix_input` | Número de teléfono no válido |
| `error.400.invalid_phone_format` | 400 | — | `fix_input` | Formato de número de teléfono no válido |
| `error.400.invalid_redirect_url` | 400 | — | `fix_input` | redirect_url debe ser una ruta relativa que empiece por / — no se permiten URL absolutas. |
| `error.400.last_auth_method` | 400 | — | `fix_input` | No se puede eliminar el último método de autenticación. |
| `error.400.magic_link_invalid` | 400 | — | `retry` | El enlace mágico no es válido o ha caducado. |
| `error.400.no_current_value` | 400 | — | `fix_input` | No hay ningún valor actual en esta cuenta. |
| `error.400.no_password` | 400 | — | `fix_input` | No hay ninguna contraseña establecida. Primero establece una contraseña. |
| `error.400.no_verified_contact` | 400 | — | `verify` | No hay ningún correo electrónico ni teléfono verificado en esta cuenta. |
| `error.400.not_available` | 400 | — | `fix_input` | Este valor ya está registrado o reservado. |
| `error.400.oauth_failed` | 400 | — | `retry` | No se pudo autenticar con el proveedor de OAuth |
| `error.400.oauth_fields_required` | 400 | — | `fix_input` | Se requieren provider y access_token |
| `error.400.passkey_challenge_expired` | 400 | — | `retry` | El desafío de la llave de acceso ha caducado. Inténtalo de nuevo. |
| `error.400.passkey_invalid` | 400 | — | `retry` | La verificación de la llave de acceso ha fallado. |
| `error.400.password_already_set` | 400 | — | `fix_input` | Ya hay una contraseña establecida. Usa el proceso de cambio de contraseña. |
| `error.400.passwords_dont_match` | 400 | — | `fix_input` | Las contraseñas no coinciden |
| `error.400.phone_required` | 400 | — | `fix_input` | El número de teléfono es obligatorio. |
| `error.400.phone_too_long` | 400 | — | `fix_input` | El número de teléfono es demasiado largo |
| `error.400.qr_expired` | 400 | — | `retry` | El código QR ha caducado. |
| `error.400.qr_fulfilled` | 400 | — | `retry` | El código QR ya se ha utilizado. |
| `error.400.qr_type_required` | 400 | — | `fix_input` | Se requiere el tipo de QR (session_share o login_request). |
| `error.400.sso_invalid_response` | 400 | — | `retry` | Respuesta SSO no válida del proveedor de identidad. |
| `error.400.sso_not_configured` | 400 | — | `contact_support` | El SSO no está configurado para esta organización. |
| `error.400.staff_role_target_not_staff` | 400 | — | `fix_input` | Los roles de personal solo pueden asignarse a cuentas de personal. Concede primero al usuario la condición de personal. |
| `error.400.token_required` | 400 | — | `fix_input` | Se requiere un token |
| `error.400.totp_not_enabled` | 400 | — | `fix_input` | TOTP no está activado en esta cuenta. |
| `error.400.totp_not_pending` | 400 | — | `retry` | No hay ninguna configuración TOTP pendiente. Llama primero a /totp/setup/. |
| `error.400.totp_proof_required` | 400 | — | `verify` | Ya existe un TOTP en esta cuenta. Introduce el código actual o un código de respaldo para sustituirlo, o utiliza el flujo de cambio diferido si has perdido tu autenticador. |
| `error.400.unknown_staff_role` | 400 | — | `fix_input` | Rol de personal desconocido. Defínelo primero en la configuración de despliegue STAPEL_ACCESS["ROLES"]. |
| `error.400.username_namespace_invalid` | 400 | — | `fix_input` | Inicio de sesión con espacio de nombres no válido. Usa 'org_slug/username' con exactamente una '/' y caracteres válidos a ambos lados. |
| `error.400.validation_error` | 400 | — | `fix_input` | Error de validación |
| `error.400.verification_failed` | 400 | — | `verify` | La verificación ha fallado |
| `error.400.verification_invalid_factor` | 400 | — | `verify` | Este factor de verificación no está disponible |
| `error.400.wrong_password` | 400 | — | `fix_input` | Contraseña incorrecta. |
| `error.401.account_disabled` | 401 | — | `contact_support` | La cuenta de usuario está deshabilitada |
| `error.401.invalid_credentials` | 401 | — | `reauthenticate` | Credenciales no válidas |
| `error.401.qr_auth_required` | 401 | — | `reauthenticate` | Se requiere autenticación para generar un código QR de session_share. |
| `error.401.refresh_invalid` | 401 | — | `reauthenticate` | Token de actualización no válido o caducado |
| `error.401.refresh_not_provided` | 401 | — | `reauthenticate` | No se proporcionó el token de actualización |
| `error.401.refresh_revoked` | 401 | — | `reauthenticate` | El token ha sido revocado |
| `error.401.token_invalid` | 401 | — | `reauthenticate` | Token no válido |
| `error.401.token_revoked` | 401 | — | `reauthenticate` | El token ha sido revocado |
| `error.401.unauthorized` | 401 | — | `reauthenticate` | Se requiere autenticación |
| `error.401.user_not_found` | 401 | — | `reauthenticate` | Usuario no encontrado |
| `error.402.payment_required` | 402 | — | `retry` | Se requiere pago |
| `error.403.change_requires_current` | 403 | — | `verify` | Para cambiar un correo o un teléfono verificados hace falta un código enviado al actual. Usa el flujo de cambio. |
| `error.403.forbidden` | 403 | — | `retry` | No tienes permiso para realizar esta acción |
| `error.403.gdpr.account_closed` | 403 | — | `retry` | Esta cuenta se está eliminando y ya no se puede utilizar. |
| `error.403.gdpr.erasure_forbidden` | 403 | — | `contact_support` | No tienes permiso para solicitar la eliminación de este elemento. |
| `error.403.mfa_enrollment_required` | 403 | — | `verify` | Es necesario registrar la autenticación de dos factores antes de poder usar esta cuenta. Configura primero una aplicación de autenticación o una llave de acceso. |
| `error.403.mock_otp_admin` | 403 | — | `contact_support` | La autenticación por OTP está deshabilitada para cuentas de administrador en modo mock. |
| `error.403.network_blocked` | 403 | — | `contact_support` | No se permiten solicitudes desde esta red. |
| `error.403.password_change_required` | 403 | — | `reauthenticate` | Es necesario cambiar la contraseña antes de que esta cuenta pueda iniciar sesión. Completa primero el cambio de contraseña obligatorio. |
| `error.403.privileged_account` | 403 | — | `contact_support` | Esta cuenta posee privilegios en todo el despliegue. Su contraseña no puede restablecerse desde una interfaz de organización. |
| `error.403.qr_device_mismatch` | 403 | — | `retry` | Este código QR pertenece a otro dispositivo. |
| `error.403.qr_unauth_scan` | 403 | — | `reauthenticate` | Este código QR no puede ser escaneado por un dispositivo no autenticado. |
| `error.403.registration_closed` | 403 | — | `contact_support` | Aquí no está abierto el registro de cuentas nuevas. Pide a un administrador que te cree una. |
| `error.403.sso_required` | 403 | — | `reauthenticate` | Esta cuenta debe iniciar sesión mediante SSO. Usa el enlace SSO de tu organización. |
| `error.403.verification_enrollment_required` | 403 | — | `verify` | Es necesario registrar un factor de verificación. |
| `error.403.verification_required` | 403 | — | `verify` | Se requiere verificación adicional |
| `error.404.ad_not_found` | 404 | — | `retry` | Anuncio no encontrado |
| `error.404.change_not_found` | 404 | — | `retry` | Solicitud de cambio no encontrada. |
| `error.404.gdpr.dsar_not_found` | 404 | — | `retry` | Solicitud de protección de datos no encontrada. |
| `error.404.gdpr.erasure_not_found` | 404 | — | `retry` | Solicitud de eliminación no encontrada. |
| `error.404.gdpr.export_not_found` | 404 | — | `retry` | Solicitud de exportación no encontrada. |
| `error.404.gdpr.no_active_closure` | 404 | — | `fix_input` | No se encontró ningún cierre de cuenta pendiente. |
| `error.404.not_found` | 404 | — | `retry` | Recurso solicitado no encontrado |
| `error.404.oauth_link_not_found` | 404 | — | `retry` | No se ha encontrado ninguna cuenta vinculada para este proveedor. |
| `error.404.passkey_not_found` | 404 | — | `retry` | Llave de acceso no encontrada. |
| `error.404.qr_not_found` | 404 | — | `retry` | Código QR no encontrado o caducado. |
| `error.404.sso_org_not_found` | 404 | — | `fix_input` | Organización no encontrada. |
| `error.404.user_for_reset` | 404 | — | `fix_input` | No se encontró ninguna cuenta con este correo electrónico o teléfono. |
| `error.404.verification_challenge_not_found` | 404 | — | `verify` | Desafío de verificación no encontrado o caducado |
| `error.405.method_not_allowed` | 405 | — | `retry` | Método no permitido |
| `error.406.not_acceptable` | 406 | — | `retry` | No aceptable |
| `error.408.request_timeout` | 408 | — | `retry` | Tiempo de espera de la solicitud agotado |
| `error.409.conflict` | 409 | — | `fix_input` | El recurso ya existe |
| `error.409.email_reserved` | 409 | — | `fix_input` | Este correo electrónico está reservado por otra solicitud de cambio pendiente. |
| `error.409.email_taken` | 409 | — | `fix_input` | Este correo electrónico ya está registrado en otra cuenta. |
| `error.409.gdpr.closure_already_pending` | 409 | — | `fix_input` | El cierre de la cuenta ya está en curso. |
| `error.409.gdpr.export_cooldown` | 409 | — | `fix_input` | Ya se solicitó una exportación de datos en los últimos 30 días. |
| `error.409.gdpr.legal_hold` | 409 | — | `fix_input` | Los datos de la cuenta están sujetos a una retención legal y no se pueden eliminar. |
| `error.409.oauth_account_linked_elsewhere` | 409 | — | `fix_input` | Esta cuenta de proveedor ya está vinculada a otro usuario. |
| `error.409.oauth_already_linked` | 409 | — | `fix_input` | Este proveedor ya está vinculado a tu cuenta. |
| `error.409.passkey_already_registered` | 409 | — | `fix_input` | Esta llave de acceso ya está registrada. |
| `error.409.phone_reserved` | 409 | — | `fix_input` | Este número de teléfono está reservado por otra solicitud de cambio pendiente. |
| `error.409.phone_taken` | 409 | — | `fix_input` | Este número de teléfono ya está registrado en otra cuenta. |
| `error.409.qr_account_conflict` | 409 | — | `reauthenticate` | Ya hay otra cuenta con la sesión iniciada en este dispositivo. |
| `error.409.sso_org_slug_taken` | 409 | — | `fix_input` | Ya existe una organización con este slug. |
| `error.409.username_taken` | 409 | — | `fix_input` | Este nombre de usuario ya está en uso. |
| `error.410.gdpr.download_consumed` | 410 | — | `retry` | El enlace de descarga ya se ha utilizado. Solicita una nueva exportación. |
| `error.410.gdpr.download_expired` | 410 | — | `retry` | El enlace de descarga ha caducado. |
| `error.410.gone` | 410 | — | `retry` | El recurso se ha eliminado permanentemente |
| `error.413.payload_too_large` | 413 | — | `retry` | El cuerpo de la solicitud es demasiado grande |
| `error.415.unsupported_media_type` | 415 | — | `retry` | Tipo de contenido no compatible |
| `error.422.blocked` | 422 | `retry_after_minutes` | `wait_and_retry` | Cuenta bloqueada temporalmente. Inténtalo de nuevo en {retry_after_minutes} minutos. |
| `error.422.unprocessable_entity` | 422 | — | `wait_and_retry` | Entidad no procesable |
| `error.423.account_locked` | 423 | `retry_after_minutes` | `wait_and_retry` | Cuenta bloqueada temporalmente por demasiados intentos fallidos. Inténtalo de nuevo en {retry_after_minutes} minutos. |
| `error.423.locked` | 423 | — | `wait_and_retry` | El recurso está bloqueado |
| `error.423.verification_locked` | 423 | — | `wait_and_retry` | Demasiados intentos fallidos — verificación bloqueada |
| `error.425.gdpr.export_not_ready` | 425 | — | `retry` | La exportación todavía se está preparando. |
| `error.429.magic_link_rate` | 429 | — | `wait_and_retry` | Demasiadas solicitudes de enlace mágico. Inténtalo de nuevo más tarde. |
| `error.429.rate_limit` | 429 | `retry_after_minutes` | `wait_and_retry` | Demasiados intentos. Inténtalo de nuevo en {retry_after_minutes} minutos. |
| `error.429.too_many_requests` | 429 | — | `wait_and_retry` | Demasiadas solicitudes. Inténtalo de nuevo más tarde. |
| `error.500.internal` | 500 | — | `contact_support` | Algo salió mal |
| `error.500.send_failed` | 500 | — | `retry` | No se pudo enviar el código de verificación |
| `error.503.gdpr.closure_unavailable` | 503 | — | `retry` | El cierre de la cuenta no está disponible temporalmente. Inténtalo de nuevo más tarde. |
| `error.503.mandate_unavailable` | 503 | — | `retry` | No se puede verificar el mandato del espacio de trabajo |
| `error.503.verification_unavailable` | 503 | — | `wait_and_retry` | Ahora mismo no podemos comprobar tu inicio de sesión. Inténtalo de nuevo en un momento. |
