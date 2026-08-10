"""
Real-pysatochip API contract tests.

The unit-test suite installs ``sys.modules['pysatochip'] = MagicMock()``
(tests/base.py, tests/conftest.py). A MagicMock auto-creates *any* attribute,
so a view importing a constant from a wrong module path, or calling a
connector method the deployed pysatochip doesn't have, sails through CI and
explodes on hardware. That is exactly how the B11 regressions shipped:

  * ``SEEDKEEPER_DIC_TYPE`` NameError — the pysatochip try-block in
    smartcard_views contained imports of non-existent modules, the whole block
    was swallowed by ``except ImportError: pass``, and the valid JCconstants
    names never bound.
  * ``card_get_ndef`` AttributeError — the Luckfox image pinned an older
    pysatochip than the glibc platforms, predating the NDEF methods the new
    NDEF views call.

These tests exercise the REAL import surface. The pysatochip-dependent ones
run in a pristine subprocess (pytest's conftest mocks don't leak there) and
are skipped when the real library isn't installed.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"


def _run_py(code: str) -> subprocess.CompletedProcess:
    """Run ``code`` in a pristine interpreter (no pytest conftest mocks)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
        timeout=120,
    )


def _real_pysatochip_available() -> bool:
    return _run_py("import pysatochip.CardConnector, pysatochip.JCconstants").returncode == 0


requires_real_pysatochip = pytest.mark.skipif(
    not _real_pysatochip_available(),
    reason="real pysatochip not installed (pip install from 3rdIteration/pysatochip)",
)


# ----------------------------------------------------------------------
# No pysatochip required — the Keycard adapter must expose every
# pysatochip-style method the NDEF views call.
# ----------------------------------------------------------------------

@pytest.mark.parametrize("method", ["card_get_ndef", "card_get_ndef_v2", "card_set_ndef"])
def test_keycard_adapter_exposes_ndef_surface(method):
    from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

    assert callable(getattr(KeycardSatochipConnector, method, None)), (
        f"KeycardSatochipConnector is missing {method}(), which the NDEF views call"
    )


# ----------------------------------------------------------------------
# Real pysatochip — import-path and connector-surface contract.
# ----------------------------------------------------------------------

@requires_real_pysatochip
def test_smartcard_views_binds_real_jcconstants():
    """B11 regression: importing smartcard_views with REAL pysatochip must bind
    the JCconstants dictionaries (and the sw-error helper) at module level."""
    result = _run_py(
        "import seedsigner.views.smartcard_views as s\n"
        "assert isinstance(s.SEEDKEEPER_DIC_TYPE, dict), type(s.SEEDKEEPER_DIC_TYPE)\n"
        "assert isinstance(s.SEEDKEEPER_DIC_ORIGIN, dict)\n"
        "assert isinstance(s.SEEDKEEPER_DIC_EXPORT_RIGHTS, dict)\n"
        "assert isinstance(s.BIP39_WORDLIST_DIC, dict)\n"
        "assert isinstance(s.UnexpectedSW12Error, type)\n"
        "assert isinstance(s.format_sw_error(0x90, 0x00), str)\n"
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"


@requires_real_pysatochip
def test_real_connector_has_seedkeeper_ndef_methods():
    """B11 regression: ToolsCommonNdefView calls these on the live connector.
    The Luckfox image shipped a pysatochip too old to have them — catch any
    such version mismatch against the installed library."""
    result = _run_py(
        "from pysatochip.CardConnector import CardConnector, UnexpectedSW12Error\n"
        "missing = [m for m in ('card_get_ndef', 'card_set_ndef')\n"
        "           if not callable(getattr(CardConnector, m, None))]\n"
        "assert not missing, f'installed pysatochip lacks {missing}'\n"
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"


@requires_real_pysatochip
@pytest.mark.xfail(
    reason="card_get_ndef_v2 (Satodime NDEF) needs 3rdIteration/pysatochip 0.6a+; "
           "stale PyPI installs lack it",
    strict=False,
)
def test_real_connector_has_satodime_ndef_v2():
    result = _run_py(
        "from pysatochip.CardConnector import CardConnector\n"
        "assert callable(getattr(CardConnector, 'card_get_ndef_v2', None))\n"
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"


@requires_real_pysatochip
def test_view_secret_listing_decode_with_real_constants():
    """Mirror ToolsSeedkeeperViewSecretsView's header decode against the real
    JCconstants dictionaries — the exact lookups that raised NameError in B11."""
    result = _run_py(
        "from pysatochip.JCconstants import (SEEDKEEPER_DIC_TYPE,\n"
        "    SEEDKEEPER_DIC_ORIGIN, SEEDKEEPER_DIC_EXPORT_RIGHTS)\n"
        "header = {'id': 1, 'type': 0x90, 'subtype': 0, 'origin': 0x01,\n"
        "          'export_rights': 0x01, 'label': 'test'}\n"
        "stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))\n"
        "origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))\n"
        "rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],\n"
        "                                          hex(header['export_rights']))\n"
        "assert stype == 'Password', stype\n"
        "assert rights == 'Plaintext export allowed', rights\n"
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
