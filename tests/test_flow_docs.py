"""Flow SA-document release gate (flow-system.md §4, drift gate).

stapel-auth is the reference module for the bilingual flow doc trees. The
committed ``docs/flows/{en,ru}/`` trees + ``flows.json`` must be exactly what
``generate_project_docs`` produces from the current flows + URLConf — the same
byte-stable regenerate-and-diff discipline as attributes-static.

Regenerate the committed trees after changing a flow or a catalog:

    STAPEL_REGEN_FLOW_DOCS=1 python -m pytest \
        tests/test_flow_docs.py::test_flow_docs_have_no_drift

then commit ``docs/flows/``. Without the env var the same test is the CI drift
gate: it regenerates into a temp dir and asserts byte-for-byte equality with
the committed tree (a no-op regen is a no-op diff).
"""
import io
import os
from pathlib import Path

from django.core.management import call_command

DOCS = Path(__file__).resolve().parent.parent / "docs" / "flows"


def _generate(out: Path) -> None:
    call_command("generate_project_docs", "--out", str(out), stdout=io.StringIO())


def _tree(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }


def test_flow_docs_have_no_drift(tmp_path):
    if os.environ.get("STAPEL_REGEN_FLOW_DOCS"):
        _generate(DOCS)
        return

    out = tmp_path / "flows"
    _generate(out)
    generated = _tree(out)
    committed = _tree(DOCS)

    assert set(committed) == set(generated), (
        "flow doc tree file set drifted — run "
        "STAPEL_REGEN_FLOW_DOCS=1 pytest tests/test_flow_docs.py and commit docs/flows/"
    )
    drifted = [rel for rel, data in generated.items() if committed.get(rel) != data]
    assert not drifted, (
        f"flow docs are stale: {drifted} — run "
        "STAPEL_REGEN_FLOW_DOCS=1 pytest tests/test_flow_docs.py and commit docs/flows/"
    )


def test_bilingual_trees_exist():
    # en is the canonical source; ru ships translated from the catalog.
    for lang in ("en", "ru"):
        assert (DOCS / lang / "README.md").is_file()
        for flow_id in ("auth.passwordless_login", "auth.password_login",
                        "auth.step_up_verification"):
            assert (DOCS / lang / f"{flow_id}.md").is_file()
    assert (DOCS / "flows.json").is_file()
    # chrome is localized per tree
    assert "## Steps" in (DOCS / "en" / "auth.passwordless_login.md").read_text()
    assert "## Шаги" in (DOCS / "ru" / "auth.passwordless_login.md").read_text()


def test_flow_index_is_flat_and_switches_language_in_place():
    """The list is the content, and language is a switch — not two levels.

    Owner complaint (#257): reaching a flow's description took three moves —
    pick a language, read a table of bare ids, open a flow. The picker page
    is gone, the description is on the list, and the other language is one
    click from where you already are.
    """
    assert not (DOCS / "README.md").exists()
    en = (DOCS / "en" / "README.md").read_text()
    ru = (DOCS / "ru" / "README.md").read_text()
    assert en.startswith("**English** · [Русский](../ru/README.md)")
    assert ru.startswith("[English](../en/README.md) · **Русский**")
    for text in (en, ru):
        # every documented flow, its own page one click away, description inline
        for flow_id in ("auth.first_login", "auth.password_login",
                        "auth.passwordless_login", "auth.step_up_verification"):
            assert f"]({flow_id}.md)" in text
    assert "The user signs in with a login (email/username) and password" in en
    assert "Пользователь входит по логину" in ru
