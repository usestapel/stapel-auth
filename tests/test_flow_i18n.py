"""Flow i18n reference migration (flow-system.md §2).

stapel-auth is the first-instance module for flow i18n: the flows.py
literals are the canonical English source texts, and the committed catalogs
``translations/flows.en.json`` / ``translations/flows.ru.json`` carry the
full key set. These tests are the drift gates every module copies:

- en catalog == in-code literals (byte-for-byte value equality);
- ru catalog covers exactly the same keys;
- resolution through stapel_core.flows.i18n actually renders Russian.
"""
import json
from pathlib import Path

from django.test import TestCase

CATALOG_DIR = Path(__file__).resolve().parent.parent / "translations"


def _catalog(lang: str) -> dict:
    return json.loads((CATALOG_DIR / f"flows.{lang}.json").read_text(encoding="utf-8"))


class FlowCatalogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from stapel_core.flows import autodiscover_flows, flow_registry

        autodiscover_flows()
        cls.flows = [f for f in flow_registry.all() if f.id.startswith("auth.")]

    def test_flows_present(self):
        self.assertEqual(
            [f.id for f in self.flows],
            [
                "auth.first_login",
                "auth.password_login",
                "auth.passwordless_login",
                "auth.step_up_verification",
            ],
        )

    def test_en_catalog_mirrors_literals(self):
        """Drift gate: the en catalog IS the in-code literals."""
        from stapel_core.flows import flow_source_texts

        self.assertEqual(_catalog("en"), flow_source_texts(self.flows))

    def test_ru_catalog_covers_same_key_set(self):
        en, ru = _catalog("en"), _catalog("ru")
        self.assertEqual(set(ru), set(en))
        for key, value in ru.items():
            self.assertTrue(isinstance(value, str) and value.strip(), key)

    def test_implicit_keys_follow_the_scheme(self):
        flow = next(f for f in self.flows if f.id == "auth.passwordless_login")
        self.assertEqual(flow.title_key, "flow.auth.passwordless_login.title")
        self.assertEqual(flow.description_key, "flow.auth.passwordless_login.description")
        self.assertEqual(
            [s.note_key for s in flow.sorted_steps()],
            [f"flow.auth.passwordless_login.step.{i}.note" for i in range(4)],
        )

    def test_resolve_ru_renders_russian(self):
        from stapel_core.flows import resolve_flow_texts
        from stapel_core.flows.docs import render_flow_markdown

        flow = next(f for f in self.flows if f.id == "auth.passwordless_login")
        texts = resolve_flow_texts([flow], "ru", use_translate_function=False)
        self.assertEqual(
            texts["flow.auth.passwordless_login.title"], "Вход без пароля (email OTP)"
        )
        md = render_flow_markdown(flow, {}, texts=texts)
        self.assertIn("# Вход без пароля (email OTP)", md)
        self.assertIn("Пользователь вводит email на форме входа", md)

    def test_unresolved_language_falls_back_to_english_literals(self):
        from stapel_core.flows import flow_source_texts, resolve_flow_texts

        texts = resolve_flow_texts(self.flows, "de", use_translate_function=False)
        self.assertEqual(texts, flow_source_texts(self.flows))
