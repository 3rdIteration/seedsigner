import importlib
import sys
from unittest.mock import MagicMock

import pytest


MODULE = "seedsigner.models.decode_qr"


@pytest.fixture(autouse=True)
def restore_module_state():
    """These tests re-import decode_qr with pyzbar hidden; restore the original
    modules afterwards so other tests keep referencing the same module objects.
    The parent package attribute must be restored too: re-importing rebinds
    seedsigner.models.decode_qr on the package, which is what
    `import seedsigner.models.decode_qr` (and monkeypatch string targets) resolve."""
    saved = {name: sys.modules.get(name) for name in (MODULE, "pyzbar", "pyzbar.pyzbar")}
    parent = sys.modules.get("seedsigner.models")
    saved_attr = getattr(parent, "decode_qr", None) if parent else None
    yield
    for name, module in saved.items():
        if module is not None:
            sys.modules[name] = module
        else:
            sys.modules.pop(name, None)
    if parent is not None and saved_attr is not None:
        parent.decode_qr = saved_attr


def test_decode_qr_import_survives_missing_pyzbar(monkeypatch):
    sys.modules.pop(MODULE, None)
    monkeypatch.setitem(sys.modules, "pyzbar", None)
    sys.modules.pop("pyzbar.pyzbar", None)

    decode_qr = importlib.import_module(MODULE)
    monkeypatch.setattr(decode_qr.DecodeQR, "_opencv_available_desktop", lambda: False)

    assert decode_qr.DecodeQR.is_qr_scanner_available() is False
    assert decode_qr.DecodeQR.extract_qr_data(image=object()) is None


def test_decode_qr_scanner_available_with_mocked_pyzbar(monkeypatch):
    sys.modules.pop(MODULE, None)

    pyzbar_pkg = MagicMock()
    pyzbar_submodule = MagicMock()
    pyzbar_submodule.ZBarSymbol = MagicMock()
    pyzbar_submodule.ZBarSymbol.QRCODE = 0
    pyzbar_submodule.decode.return_value = []

    monkeypatch.setitem(sys.modules, "pyzbar", pyzbar_pkg)
    monkeypatch.setitem(sys.modules, "pyzbar.pyzbar", pyzbar_submodule)

    decode_qr = importlib.import_module(MODULE)

    assert decode_qr.DecodeQR.is_qr_scanner_available() is True


def test_decode_qr_uses_opencv_fallback_on_desktop(monkeypatch):
    sys.modules.pop(MODULE, None)
    monkeypatch.setitem(sys.modules, "pyzbar", None)
    sys.modules.pop("pyzbar.pyzbar", None)

    decode_qr = importlib.import_module(MODULE)
    monkeypatch.setattr(decode_qr.DecodeQR, "_opencv_available_desktop", lambda: True)
    monkeypatch.setattr(decode_qr.DecodeQR, "_extract_qr_data_opencv", lambda image, is_binary=False: b"fallback")

    assert decode_qr.DecodeQR.is_qr_scanner_available() is True
    assert decode_qr.DecodeQR.extract_qr_data(image=object(), is_binary=True) == b"fallback"
