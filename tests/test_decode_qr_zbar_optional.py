import importlib
import sys
from unittest.mock import MagicMock


MODULE = "seedsigner.models.decode_qr"


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
