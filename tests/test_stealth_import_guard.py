"""Static guard for the CLAUDE.md stealth-module rule: the Snake game
(``src/seedsigner/stealth/``) MUST NOT import from ``seedsigner.models.seed*``,
``seedsigner.helpers.keycard*``, or any module that touches secrets.

Previously this was enforced only by code review.
"""

from __future__ import annotations

import ast
from pathlib import Path


STEALTH_DIR = (
    Path(__file__).resolve().parent.parent / "src" / "seedsigner" / "stealth"
)

FORBIDDEN_PREFIXES = (
    # Seed / key material and card protocol modules.
    "seedsigner.models.seed",
    "seedsigner.helpers.keycard",
    "seedsigner.helpers.keycard_signer",
    "seedsigner.helpers.keycard_btc_signer",
    "seedsigner.helpers.seedkeeper_utils",
    "seedsigner.helpers.mnemonic_generation",
    # Controller holds cached PINs / pairing state; also a circular import.
    "seedsigner.controller",
    # Crypto / card libraries — the game has no business touching them.
    "embit",
    "shamir_mnemonic",
    "pysatochip",
    "smartcard",
)


def _imports_of(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            # Relative imports (level > 0) stay inside the stealth package.
            if node.module:
                modules.append(node.module)
    return modules


def test_stealth_module_never_imports_secret_handling_code():
    py_files = sorted(STEALTH_DIR.glob("*.py"))
    assert py_files, f"no stealth module found at {STEALTH_DIR}"

    violations = []
    for path in py_files:
        for module in _imports_of(path):
            if module.startswith(FORBIDDEN_PREFIXES):
                violations.append(f"{path.name}: import {module}")

    assert not violations, (
        "CLAUDE.md forbids the stealth module from importing seed/keycard/"
        "secret-handling code:\n" + "\n".join(f"  {v}" for v in violations)
    )
