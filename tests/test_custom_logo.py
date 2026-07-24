from PIL import Image

from seedsigner.views import screensaver


def test_load_boot_logo_image_uses_default_when_custom_missing(tmp_path, monkeypatch):
    default_logo = Image.new("RGB", (240, 240), "black")
    monkeypatch.setattr(screensaver, "load_image", lambda _: default_logo)
    monkeypatch.setattr("seedsigner.hardware.microsd.MicroSD.get_microsd_dir", lambda: tmp_path)

    logo = screensaver.load_boot_logo_image()

    assert logo is default_logo


def test_load_boot_logo_image_uses_custom_logo_when_present(tmp_path, monkeypatch):
    default_logo = Image.new("RGB", (240, 240), "black")
    monkeypatch.setattr(screensaver, "load_image", lambda _: default_logo)
    monkeypatch.setattr("seedsigner.hardware.microsd.MicroSD.get_microsd_dir", lambda: tmp_path)

    custom_logo_path = tmp_path / screensaver.CUSTOM_LOGO_FILENAME
    Image.new("RGB", (240, 240), "red").save(custom_logo_path, format="PNG")

    logo = screensaver.load_boot_logo_image()

    assert logo.size == (240, 240)
    assert logo.getpixel((120, 120)) == (255, 0, 0)


def test_load_boot_logo_image_falls_back_when_dimensions_invalid(tmp_path, monkeypatch):
    default_logo = Image.new("RGB", (240, 240), "black")
    monkeypatch.setattr(screensaver, "load_image", lambda _: default_logo)
    monkeypatch.setattr("seedsigner.hardware.microsd.MicroSD.get_microsd_dir", lambda: tmp_path)

    custom_logo_path = tmp_path / screensaver.CUSTOM_LOGO_FILENAME
    Image.new("RGB", (120, 120), "red").save(custom_logo_path, format="PNG")

    logo = screensaver.load_boot_logo_image()

    assert logo is default_logo


def test_load_boot_logo_image_survives_storage_error(monkeypatch):
    # A storage failure (e.g. ENOSPC) while resolving the microSD dir happens at
    # boot, before the main loop's exception handling — it must degrade to the
    # default logo, never crash.
    default_logo = Image.new("RGB", (240, 240), "black")
    monkeypatch.setattr(screensaver, "load_image", lambda _: default_logo)

    def boom():
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("seedsigner.hardware.microsd.MicroSD.get_microsd_dir", boom)

    logo = screensaver.load_boot_logo_image()

    assert logo is default_logo
