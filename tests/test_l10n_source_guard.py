"""AST lint: user-facing strings in keycard_views.py must be wrapped in
``_()`` so they are translated at render time.

This would have caught the duress-PIN screen shipping raw English text
while the rest of the file (290+ ``_()`` calls) was translated.

ButtonOption labels are deliberately NOT checked: they are plain literals
by convention (extracted into the catalogs and translated at render).
"""

from __future__ import annotations

import ast
from pathlib import Path


KEYCARD_VIEWS = (
    Path(__file__).resolve().parent.parent
    / "src" / "seedsigner" / "views" / "keycard_views.py"
)

# Kwargs whose values are rendered verbatim on screen.
UI_TEXT_KWARGS = {"text", "title", "status_headline", "instructions_text"}

# Known-legitimate raw literals (add sparingly, with a reason).
ALLOWLIST: set[str] = set()


def _is_user_facing(value: str) -> bool:
    # Ignore empty strings / pure punctuation or formatting placeholders.
    return any(c.isalpha() for c in value) and value not in ALLOWLIST


def _offenders() -> list[tuple[int, str, str]]:
    tree = ast.parse(KEYCARD_VIEWS.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if (
                kw.arg in UI_TEXT_KWARGS
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
                and _is_user_facing(kw.value.value)
            ):
                found.append((kw.value.lineno, kw.arg, kw.value.value[:60]))
        # prompt_for_pin(view, "title") takes its screen title positionally.
        func = node.func
        if (
            isinstance(func, ast.Name)
            and func.id == "prompt_for_pin"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and _is_user_facing(node.args[1].value)
        ):
            found.append((node.args[1].lineno, "prompt_for_pin", node.args[1].value[:60]))
    return found


def test_keycard_views_ui_strings_are_wrapped_in_gettext():
    offenders = _offenders()
    assert not offenders, (
        "Raw user-facing string literals found in keycard_views.py — wrap "
        "them in _() and add the msgids to all 9 l10n catalogs:\n"
        + "\n".join(f"  line {ln}: {kind}={text!r}" for ln, kind, text in offenders)
    )
