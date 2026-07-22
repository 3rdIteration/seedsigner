"""Static guard: no shipping code references an undefined name.

A symbol used in a function body but never imported/defined in scope does **not**
fail at import time — Python only raises ``NameError`` when that exact line runs.
That is precisely how the ``tools_views.py`` module split leaked runtime crashes
(e.g. the password generator's ``_derive_camera_entropy_bytes``) past both the
import smoke tests and the menu-navigation walk, which stops before the terminal
view actually executes.

``pyflakes`` performs full lexical-scope analysis and flags every such reference
statically. This test runs it over the whole ``seedsigner`` package and fails on
any *undefined name* finding — one self-maintaining guard for this entire class
of bug. It deliberately ignores every other pyflakes category (unused imports,
``import *`` warnings, redefinitions, …): those are style, not latent crashes.
"""
import os

import pyflakes.api
import pyflakes.messages

import seedsigner


# Reviewed, genuine false positives may be parked here as ``"<rel/path>:<name>"``
# strings. This is expected to stay EMPTY; the test also fails if an entry here
# no longer occurs, forcing the allowlist to ratchet down as code is fixed.
ALLOWLIST: set[str] = set()

# pyflakes message classes that mean "this name is not defined in scope" — i.e. a
# latent ``NameError`` — as opposed to the style findings we don't gate on.
_UNDEFINED_MESSAGE_TYPES = (
    pyflakes.messages.UndefinedName,
    pyflakes.messages.UndefinedLocal,
    pyflakes.messages.UndefinedExport,
)


class _Collector:
    """Minimal pyflakes reporter that keeps only undefined-name findings."""

    def __init__(self):
        self.undefined = []      # (rel_path, lineno, name)
        self.syntax_errors = []  # (rel_path, lineno, msg)
        self.unexpected = []     # (rel_path, msg)
        self._root = os.path.dirname(seedsigner.__file__)

    def _rel(self, filename):
        return os.path.relpath(filename, self._root).replace(os.sep, "/")

    def unexpectedError(self, filename, msg):
        self.unexpected.append((self._rel(filename), msg))

    def syntaxError(self, filename, msg, lineno, offset, text):
        self.syntax_errors.append((self._rel(filename), lineno, msg))

    def flake(self, message):
        if isinstance(message, _UNDEFINED_MESSAGE_TYPES):
            name = message.message_args[0] if message.message_args else "?"
            self.undefined.append((self._rel(message.filename), message.lineno, name))


def _iter_source_files():
    root = os.path.dirname(seedsigner.__file__)
    for dirpath, _dirnames, filenames in os.walk(root):
        if "__pycache__" in dirpath.split(os.sep):
            continue
        for filename in filenames:
            if filename.endswith(".py"):
                yield os.path.join(dirpath, filename)


def test_no_undefined_names_in_package():
    collector = _Collector()
    files_checked = 0
    for path in _iter_source_files():
        pyflakes.api.checkPath(path, collector)
        files_checked += 1

    # Sanity: make sure we actually scanned the package (guards against a walk
    # that silently finds nothing and passes vacuously).
    assert files_checked > 50, f"only scanned {files_checked} files — walk is broken"

    assert not collector.syntax_errors, (
        "pyflakes could not parse:\n  "
        + "\n  ".join(f"{f}:{ln}: {m}" for f, ln, m in collector.syntax_errors)
    )

    findings_by_key = {}  # "rel:name" -> "rel:lineno: name" (first occurrence)
    for rel, lineno, name in sorted(collector.undefined):
        findings_by_key.setdefault(f"{rel}:{name}", f"{rel}:{lineno}: undefined name '{name}'")

    unexpected = sorted(v for k, v in findings_by_key.items() if k not in ALLOWLIST)
    stale = sorted(a for a in ALLOWLIST if a not in findings_by_key)

    assert not unexpected, (
        "Undefined name(s) found - a symbol is used but never imported/defined in "
        "scope, which raises NameError only when that line runs at runtime.\n"
        "Add the missing import (module-level, or local to avoid a circular "
        "import), or fix the reference:\n  " + "\n  ".join(unexpected)
    )

    assert not stale, (
        "ALLOWLIST entries no longer occur and must be removed (ratchet down):\n  "
        + "\n  ".join(stale)
    )
