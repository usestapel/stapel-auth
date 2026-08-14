"""Gate: this package may not probe a user attribute that does not exist.

The defect this closes, in one line: ``getattr(user, "totp_enabled", False)``
in ``magic_link/views.py`` decided whether to demand a second factor, the
user model has no such attribute, so the default answered "no TOTP" for
every account and a magic link walked past the user's strongest factor
(audit AUTH-03, P0). ``mfa/views.py`` had a second copy of the same
expression that nobody had found.

That is not a typo, it is a shape: ``getattr(obj, name, default)`` turns a
wrong name into a plausible answer instead of an ``AttributeError``, and on
a security predicate the plausible answer is usually the permissive one.
Fixing the two occurrences leaves the shape armed for the next one, so the
scan below is the fix: every string-literal attribute this package probes on
a user object must actually exist on the configured user model.

Attributes that are genuinely optional — present on one deployment's swapped
user model and absent on another — go in ``_OPTIONAL_USER_ATTRS`` with the
reason. Nothing else may be probed with a default.
"""
import ast
import pathlib

import pytest
from django.contrib.auth import get_user_model

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SKIP_DIRS = {"tests", "build", "docs", ".venv", "migrations", "__pycache__", "dist"}

#: Names that are not a user model instance even though they read like one.
_NOT_A_USER_MODEL = {"user_data"}

#: Optional-by-design attributes, with why each is allowed to be absent.
_OPTIONAL_USER_ATTRS = {
    # Set by stapel-core's JWT middleware on the request user for the
    # duration of one request; never a stored field.
    "_stapel_staff_roles_claim": "transient request-scoped claim, not a field",
}


def _probed_user_attributes():
    """``(file, line, attribute)`` for every ``getattr(user, "x", default)``."""
    probes = []
    for path in sorted(_REPO_ROOT.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in path.relative_to(_REPO_ROOT).parts):
            continue
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except SyntaxError:  # pragma: no cover - the linter owns syntax
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Name) and node.func.id == "getattr"):
                continue
            if len(node.args) < 2:
                continue
            target = node.args[0]
            base = (
                target.id
                if isinstance(target, ast.Name)
                else target.attr
                if isinstance(target, ast.Attribute)
                else None
            )
            if base is None or base in _NOT_A_USER_MODEL:
                continue
            if not (base == "user" or base.endswith("_user")):
                continue
            name_node = node.args[1]
            if not (
                isinstance(name_node, ast.Constant) and isinstance(name_node.value, str)
            ):
                # A computed name cannot be checked here; the loops that use
                # one iterate over names this suite covers individually.
                continue
            probes.append(
                (
                    str(path.relative_to(_REPO_ROOT)),
                    node.lineno,
                    name_node.value,
                )
            )
    return probes


def _exists_on_user_model(name: str) -> bool:
    user_model = get_user_model()
    if hasattr(user_model, name):
        return True
    # Django sets a few attributes only on instances (``_state``); an unsaved
    # instance is the cheapest honest way to ask.
    try:
        return hasattr(user_model(), name)
    except Exception:  # pragma: no cover - a user model that cannot be built
        return False


def test_the_scan_actually_finds_probes():
    """A gate that matches nothing is worse than no gate."""
    assert len(_probed_user_attributes()) >= 15


@pytest.mark.django_db
def test_every_probed_user_attribute_exists():
    missing = sorted(
        f"{file}:{line} getattr(user, {name!r}, ...)"
        for file, line, name in _probed_user_attributes()
        if name not in _OPTIONAL_USER_ATTRS and not _exists_on_user_model(name)
    )
    assert missing == [], "\n".join(
        [
            "",
            "These probe a user attribute the configured user model does not have.",
            "The default is therefore the ONLY answer the expression can give —",
            "silently, and on a security predicate usually the permissive one.",
            "Ask the service that owns the fact (TOTPService.is_enabled(user) for",
            "TOTP, which lives in a TOTPDevice row), or add the attribute to",
            "_OPTIONAL_USER_ATTRS with a reason if it is optional by design.",
            "",
            *missing,
            "",
        ]
    )
