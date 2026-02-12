from seedsigner.helpers.qr import QR


def test_qrimage_io_falls_back_when_qrencode_missing(monkeypatch):
    qr = QR()

    def raise_not_found(_cmd):
        raise FileNotFoundError("qrencode")

    monkeypatch.setattr("seedsigner.helpers.qr.subprocess.call", raise_not_found)

    image = qr.qrimage_io("hello", width=120, height=120)

    assert image.size == (120, 120)
