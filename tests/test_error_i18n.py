"""Localized error catalogs (``translations/errors.<lang>.json``) + provenance gate.

i18n-shipping.md §5 / wave 1. stapel-auth is the *reference* application of the
``stapel_core.i18n`` catalog contour to the ``errors`` domain: the en canon lives
in ``errors.py`` (``register_service_errors``), each target language ships
as a flat ``translations/errors.<lang>.json`` catalog with a shared ``translations/.state.json``
provenance sidecar, and :func:`check_translation_catalogs` gates coverage,
staleness, params and byte-stability.

Provenance of the localized values (honest, per §5):

* the bulk is **seeded** from the already-curated ``stapel-translate`` builtin
  fixtures (``origin: seed:stapel-builtin``) — requirement 5 ("clients don't
  spend tokens") met by copying the paid-for corpus, not re-running an LLM;
* the handful of keys the fixtures do not cover are **machine translations**
  recorded here per language in :data:`_MACHINE` and written with
  ``origin: llm`` (unreviewed — the gate's W-counter). In a live deployment
  ``translate_catalogs --domain errors --lang <lang> --llm`` produces these
  through the ``STAPEL_I18N["TRANSLATOR"]`` comm seam; offline they come from
  that map so the module regenerates deterministically without a live LLM.

Adding a language is a three-line change here: append the tag to
:data:`LANGUAGES`, add its ``_MACHINE_<TAG>`` table for whatever the corpus
misses, and regenerate. Everything else — the catalog, the provenance sidecar,
the reference doc, the gate — follows.

Regenerate after adding/changing an error key or a translation:

    STAPEL_REGEN_ERROR_I18N=1 python -m pytest tests/test_error_i18n.py::test_regen

then commit ``translations/errors.<lang>.json`` + ``translations/.state.json``
+ ``docs/errors.<lang>.md``. Without the env var the same module is the CI gate.
"""
import io
import os
from pathlib import Path

from django.core.management import call_command

from stapel_core.i18n import (
    check_translation_catalogs,
    source_texts,
    summarize,
    translate_catalog,
)
from stapel_core.i18n.catalogs import load_catalog_file

REPO = Path(__file__).resolve().parent.parent
TRANSLATIONS = REPO / "translations"
DOCS = REPO / "docs"
#: Languages this module ships error catalogs in. en is the canon (the
#: registry literals); every other tag needs a catalog + a docs page.
LANGUAGES = ["en", "ru", "es"]
#: The languages that need a catalog — everything but the source language.
TARGET_LANGUAGES = [lang for lang in LANGUAGES if lang != "en"]

#: stapel-translate builtin fixtures (the curated seed corpus). Overridable for
#: an out-of-tree checkout via STAPEL_TRANSLATE_FIXTURES.
_FIXTURES = Path(
    os.environ.get(
        "STAPEL_TRANSLATE_FIXTURES",
        REPO.parent / "stapel-translate" / "fixtures" / "builtin",
    )
)

#: Machine translations (origin: llm) of the auth-only error keys the builtin
#: fixtures do not cover. All param-free; edit here + regen when the en changes.
_MACHINE_RU = {
    "error.400.grant_invalid":
        "Грант для входа недействителен, уже использован или его срок "
        "действия истёк.",
    "error.400.staff_role_target_not_staff":
        "Служебные роли можно назначать только служебным учётным записям. "
        "Сначала сделайте пользователя сотрудником.",
    "error.400.unknown_staff_role":
        "Неизвестная служебная роль. Сначала определите её в конфигурации "
        "развёртывания STAPEL_ACCESS[\"ROLES\"].",
    "error.409.oauth_already_linked":
        "Этот провайдер уже привязан к вашей учётной записи.",
    "error.409.oauth_account_linked_elsewhere":
        "Эта учётная запись провайдера уже привязана к другому пользователю.",
    "error.404.oauth_link_not_found":
        "Привязанная учётная запись для этого провайдера не найдена.",
    # First-login policy / org provisioning (workspaces-org-program §C1-C2)
    "error.403.password_change_required":
        "Перед входом необходимо сменить пароль. Сначала завершите "
        "обязательную смену пароля.",
    "error.403.mfa_enrollment_required":
        "Перед использованием этой учётной записи необходимо настроить "
        "двухфакторную аутентификацию. Сначала подключите приложение-"
        "аутентификатор или ключ доступа.",
    "error.400.username_namespace_invalid":
        "Недопустимый логин с пространством имён. Используйте формат "
        "'org_slug/username' ровно с одним символом '/' и допустимыми "
        "символами с обеих сторон.",
    "error.400.first_login_challenge_invalid":
        "Челлендж первого входа недействителен или истёк. Войдите ещё раз, "
        "чтобы начать заново.",
    "error.403.privileged_account":
        "Эта учётная запись обладает правами уровня всего развёртывания. "
        "Её пароль нельзя сбросить из интерфейса организации.",
    "error.403.registration_closed":
        "Здесь нельзя зарегистрироваться самостоятельно. Попросите "
        "администратора создать вам учётную запись.",
    "error.403.change_requires_current":
        "Чтобы изменить подтверждённые эл. почту или телефон, нужен код, "
        "отправленный на текущие. Воспользуйтесь процедурой смены.",
    "error.400.device_id_weak":
        "device_id должен быть непрозрачным случайным токеном длиной не "
        "менее 16 символов (латинские буквы, цифры и - . _ ~ : + / =) — "
        "отправьте UUID или случайное шестнадцатеричное/base64-значение, "
        "созданное один раз при установке, а не читаемое имя.",
    "error.400.attribution_invalid":
        "Объект attribution имеет неверный формат. Ожидается {click_id, "
        "click_id_type: gclid|gbraid|wbraid, captured_at} и необязательный "
        "объект utm.",
}

_MACHINE_ES = {
    "error.400.grant_invalid":
        "La concesión de inicio de sesión no es válida, ya se ha utilizado o "
        "ha caducado.",
    "error.400.staff_role_target_not_staff":
        "Los roles de personal solo pueden asignarse a cuentas de personal. "
        "Concede primero al usuario la condición de personal.",
    "error.400.unknown_staff_role":
        "Rol de personal desconocido. Defínelo primero en la configuración de "
        "despliegue STAPEL_ACCESS[\"ROLES\"].",
    "error.400.totp_not_enabled":
        "TOTP no está activado en esta cuenta.",
    "error.400.totp_proof_required":
        "Ya existe un TOTP en esta cuenta. Introduce el código actual o un "
        "código de respaldo para sustituirlo, o utiliza el flujo de cambio "
        "diferido si has perdido tu autenticador.",
    "error.409.oauth_already_linked":
        "Este proveedor ya está vinculado a tu cuenta.",
    "error.409.oauth_account_linked_elsewhere":
        "Esta cuenta de proveedor ya está vinculada a otro usuario.",
    "error.404.oauth_link_not_found":
        "No se ha encontrado ninguna cuenta vinculada para este proveedor.",
    # First-login policy / org provisioning (workspaces-org-program C1-C2).
    "error.403.password_change_required":
        "Es necesario cambiar la contraseña antes de que esta cuenta pueda "
        "iniciar sesión. Completa primero el cambio de contraseña obligatorio.",
    "error.403.mfa_enrollment_required":
        "Es necesario registrar la autenticación de dos factores antes de "
        "poder usar esta cuenta. Configura primero una aplicación de "
        "autenticación o una llave de acceso.",
    "error.400.username_namespace_invalid":
        "Inicio de sesión con espacio de nombres no válido. Usa "
        "'org_slug/username' con exactamente una '/' y caracteres válidos a "
        "ambos lados.",
    "error.400.first_login_challenge_invalid":
        "El desafío de primer inicio de sesión no es válido o ha caducado. "
        "Vuelve a iniciar sesión para empezar de nuevo.",
    "error.403.privileged_account":
        "Esta cuenta posee privilegios en todo el despliegue. Su contraseña "
        "no puede restablecerse desde una interfaz de organización.",
    "error.403.registration_closed":
        "Aquí no está abierto el registro de cuentas nuevas. Pide a un "
        "administrador que te cree una.",
    "error.403.change_requires_current":
        "Para cambiar un correo o un teléfono verificados hace falta un "
        "código enviado al actual. Usa el flujo de cambio.",
    "error.400.device_id_weak":
        "device_id debe ser un token aleatorio opaco de al menos 16 "
        "caracteres (letras, dígitos y - . _ ~ : + / =): envía un UUID o un "
        "valor hexadecimal/base64 aleatorio generado una sola vez por "
        "instalación, nunca un nombre legible.",
    "error.400.attribution_invalid":
        "El objeto attribution tiene un formato incorrecto. Se espera "
        "{click_id, click_id_type: gclid|gbraid|wbraid, captured_at} y un "
        "objeto utm opcional.",
}

#: language -> machine-translation table, consulted for the keys the
#: curated corpus does not carry. Values land as ``origin: llm``.
_MACHINE = {"ru": _MACHINE_RU, "es": _MACHINE_ES}


class _DictTranslator:
    """Offline translator seam — returns fixed machine translations by key."""

    def __init__(self, table):
        self._table = table

    def translate(self, entries, source_language, target_language):
        return {k: self._table[k] for k in entries if k in self._table}


def _seed_from_fixtures(lang: str) -> dict[str, str]:
    """Flat ``{error.*: text}`` seed from the builtin fixtures for *lang*."""
    import json

    path = _FIXTURES / f"{lang}.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        k: v for k, v in data.items()
        if isinstance(k, str) and k.startswith("error.")
        and isinstance(v, str) and v
    }


def _regen(lang: str):
    """Materialize one target-language catalog from corpus + machine map."""
    return translate_catalog(
        "errors", lang, TRANSLATIONS,
        source_texts=source_texts("errors"),
        seed=_seed_from_fixtures(lang),
        seed_label="stapel-builtin",
        llm=True,
        translator=_DictTranslator(_MACHINE.get(lang, {})),
    )


def test_regen():
    """Regenerate (env-gated) or assert every catalog is a no-op regen (drift)."""
    if os.environ.get("STAPEL_REGEN_ERROR_I18N"):
        for lang in TARGET_LANGUAGES:
            result = _regen(lang)
            assert not result.missing, f"{lang}: still missing: {result.missing}"
        for lang in LANGUAGES:
            call_command("generate_error_docs", "--lang", lang,
                         "--out", str(DOCS), "--translations", str(TRANSLATIONS),
                         stdout=io.StringIO())
        return

    # Drift gate: regenerating in place (kept, since committed hashes match) must
    # not change any committed catalog.
    for lang in TARGET_LANGUAGES:
        path = TRANSLATIONS / f"errors.{lang}.json"
        before = path.read_bytes()
        _regen(lang)
        assert path.read_bytes() == before, (
            f"errors.{lang}.json drifted — run "
            f"STAPEL_REGEN_ERROR_I18N=1 pytest tests/test_error_i18n.py::test_regen"
        )


def test_catalog_gate_green():
    """E: missing / stale / params-mismatch / not-byte-stable — all zero."""
    issues = check_translation_catalogs(
        "errors", TRANSLATIONS,
        source_texts=source_texts("errors"),
        languages=LANGUAGES,
    )
    errors, _warnings = summarize(issues)
    blocking = [i for i in issues if i.level == "error"]
    assert not blocking, "\n".join(f"[{i.code}] {i.message}" for i in blocking)
    assert errors == 0


def test_every_language_covers_every_key_this_module_owns():
    """Coverage is scoped to OWNERSHIP (stapel-core 0.22.0).

    Core ships its own catalogs now and the loader merges the owner's, so a
    module that also translated core's keys was maintaining a second, drifting
    copy of them — the gate calls that ``foreign`` and fails on it. What this
    module still answers for is every key it owns, in every target language.
    """
    from stapel_core.i18n import owned_keys, owner_of_dir, source_owners

    source = owned_keys(
        source_texts("errors"),
        source_owners("errors"),
        owner_of_dir(TRANSLATIONS),
    )
    for lang in TARGET_LANGUAGES:
        catalog = load_catalog_file(TRANSLATIONS / f"errors.{lang}.json")
        missing = [k for k in source if k not in catalog]
        assert not missing, (
            f"{lang} catalog missing {len(missing)} key(s): {missing[:8]}"
        )


def test_translations_preserve_placeholders():
    """Every localized text keeps exactly the canon's ``{param}`` slots (§3)."""
    from stapel_core.i18n.domains import params_of

    source = source_texts("errors")
    for lang in TARGET_LANGUAGES:
        catalog = load_catalog_file(TRANSLATIONS / f"errors.{lang}.json")
        for key, text in catalog.items():
            if key in source:
                assert set(params_of(text)) == set(params_of(source[key])), \
                    f"{lang}: {key}"


def test_error_reference_matches_a_fresh_regeneration(tmp_path):
    """The committed reference is what the generator produces TODAY.

    ``test_error_docs_exist_for_every_language`` reads the committed file, so a
    reference that had stopped being reproducible stayed green: dropping the
    core-owned duplicates blanked those rows to ``_(en)_`` on the next
    regeneration, and nothing said so until somebody regenerated. stapel-core
    0.23.1 taught the reader to resolve a key this module does not own from its
    owner's catalog; this compares the bytes instead of trusting the file.
    """
    for lang in LANGUAGES:
        call_command("generate_error_docs", "--lang", lang, "--out", str(tmp_path),
                     "--translations", str(TRANSLATIONS), stdout=io.StringIO())
        assert (tmp_path / f"errors.{lang}.md").read_bytes() == \
            (DOCS / f"errors.{lang}.md").read_bytes(), (
                f"docs/errors.{lang}.md is stale — run "
                f"STAPEL_REGEN_ERROR_I18N=1 pytest tests/test_error_i18n.py::test_regen"
            )


def test_error_docs_exist_for_every_language():
    for lang in LANGUAGES:
        path = DOCS / f"errors.{lang}.md"
        assert path.is_file(), f"missing {path}"
    for lang in TARGET_LANGUAGES:
        assert "_(en)_" not in (DOCS / f"errors.{lang}.md").read_text(), (
            f"{lang} error reference has en-fallback rows — "
            f"the {lang} catalog is incomplete"
        )
