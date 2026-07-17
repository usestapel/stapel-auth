"""errors.json codegen artifact + drift gate (error-remediation task).

stapel-auth is the pilot consumer of the backend ``errors.json`` artifact — the
language-agnostic registry of every ``error.<status>.<name>`` key the service
can raise, with its HTTP ``status``, ``{param}`` slots, machine-readable
``remediation`` hint, and canonical English text. The committed
``docs/errors.json`` must be exactly what ``generate_error_keys`` emits from the
live error registry — the same byte-stable regenerate-and-diff discipline as the
flow docs and schema.json.

Regenerate after adding/changing an error key or its remediation:

    STAPEL_REGEN_ERROR_KEYS=1 python -m pytest \
        tests/test_error_keys.py::test_error_keys_have_no_drift

then commit ``docs/errors.json``. Without the env var the same test is the CI
drift gate: it regenerates into a temp dir and asserts byte-for-byte equality
with the committed artifact (a no-op regen is a no-op diff).
"""
import io
import json
import os
from pathlib import Path

from django.core.management import call_command
from stapel_core.django.api.errors import REMEDIATION_VOCAB

ERRORS_JSON = Path(__file__).resolve().parent.parent / "docs" / "errors.json"


def _generate(out: Path) -> None:
    call_command("generate_error_keys", "--out", str(out), stdout=io.StringIO())


def test_error_keys_have_no_drift(tmp_path):
    if os.environ.get("STAPEL_REGEN_ERROR_KEYS"):
        _generate(ERRORS_JSON)
        return

    out = tmp_path / "errors.json"
    _generate(out)
    generated = out.read_bytes()
    committed = ERRORS_JSON.read_bytes()
    assert committed == generated, (
        "errors.json drifted — run "
        "STAPEL_REGEN_ERROR_KEYS=1 pytest tests/test_error_keys.py and commit "
        "docs/errors.json"
    )


def test_committed_artifact_shape():
    entries = json.loads(ERRORS_JSON.read_text())
    assert isinstance(entries, list) and entries
    codes = [e["code"] for e in entries]
    assert codes == sorted(codes), "entries must be sorted by code"
    assert len(codes) == len(set(codes)), "codes must be unique"
    for e in entries:
        assert set(e) == {"code", "status", "params", "remediation", "en"}
        assert e["code"].startswith("error.")
        assert e["status"] == int(e["code"].split(".")[1])
        assert isinstance(e["params"], list)
        assert e["remediation"] in REMEDIATION_VOCAB
        assert e["en"] and isinstance(e["en"], str)
        # Every `{param}` slot in the text is declared in params.
        import re

        slots = {m.group(1) for m in re.finditer(r"\{(\w+)\}", e["en"])}
        assert slots <= set(e["params"])


def test_pilot_keys_present_with_expected_remediation():
    entries = {e["code"]: e for e in json.loads(ERRORS_JSON.read_text())}
    # Auth-declared canon (backend overrides the frontend heuristic).
    assert entries["error.400.oauth_failed"]["remediation"] == "retry"
    assert entries["error.400.captcha_invalid"]["remediation"] == "retry"
    assert entries["error.500.send_failed"]["remediation"] == "retry"
    assert entries["error.401.invalid_credentials"]["remediation"] == "reauthenticate"
    assert entries["error.422.blocked"]["remediation"] == "wait_and_retry"
    # Cross-cutting verification keys (registered by stapel_core) are included.
    assert entries["error.404.verification_challenge_not_found"]["remediation"] == "verify"
