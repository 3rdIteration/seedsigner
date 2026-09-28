"""Flash Image has to list and copy from the same place, and say when it is empty.

It listed one hard-coded folder and copied from another spelling of it, so any
board whose images live elsewhere -- a Luckfox writing to /userdata, a card on
an alternate mount -- showed images it then could not find. A stock card has no
images folder at all, and an empty one crashed on a button list with no buttons.
"""
# Must import base before any seedsigner modules
from base import BaseTest

import subprocess

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON, WarningScreen
from seedsigner.models.settings import Settings
from seedsigner.views import microsd_views
from seedsigner.views.view import BackStackView, Destination


class _Done:
    stdout = ""
    stderr = ""
    returncode = 0


class TestFlashImagesDirectory(BaseTest):

    def _run(self, monkeypatch, images_dir, answers):
        monkeypatch.setattr(microsd_views, "flash_images_dir", lambda: images_dir)
        commands = []
        monkeypatch.setattr(
            subprocess, "run", lambda cmd, *a, **kw: commands.append(cmd) or _Done()
        )
        view = microsd_views.ToolsMicroSDFlashView()
        screens = []

        def fake_screen(Screen_cls, **kw):
            screens.append(Screen_cls)
            return answers.pop(0)

        monkeypatch.setattr(view, "run_screen", fake_screen)
        return view.run(), screens, commands

    def test_the_image_is_copied_from_the_folder_it_was_listed_from(self, monkeypatch, tmp_path):
        (tmp_path / "release.img").write_bytes(b"\x00" * 16)
        monkeypatch.setattr(Settings, "is_seedsigner_os", classmethod(lambda cls: True))
        monkeypatch.setattr("platform.uname",
                            lambda: ("Linux", "seedsigner-os", "", "", "", ""))
        monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: "/dev/mmcblk0")

        # Pick the image, then back out at "Insert MicroSD to be Flashed".
        _, _, commands = self._run(monkeypatch, tmp_path, [0, RET_CODE__BACK_BUTTON])

        copies = [c for c in commands if c and c[0] == "cp"]
        assert copies, commands
        assert copies[0][1] == str(tmp_path / "release.img")

    def test_a_missing_images_folder_is_a_message(self, monkeypatch, tmp_path):
        destination, screens, _ = self._run(monkeypatch, tmp_path / "absent", [0])

        assert WarningScreen in screens
        assert isinstance(destination, Destination)
        assert destination.View_cls is BackStackView

    def test_an_empty_images_folder_is_a_message(self, monkeypatch, tmp_path):
        destination, screens, _ = self._run(monkeypatch, tmp_path, [0])

        assert WarningScreen in screens
        assert destination.View_cls is BackStackView


class TestWhereImagesLive(BaseTest):

    def test_seedsigner_os_uses_the_resolved_data_directory(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Settings, "is_seedsigner_os", classmethod(lambda cls: True))
        monkeypatch.setattr(microsd_views, "resolve_microsd_images_dir", lambda: tmp_path)

        assert microsd_views.flash_images_dir() == tmp_path

    def test_raspberry_pi_os_keeps_the_boot_partition(self, monkeypatch):
        monkeypatch.setattr(Settings, "is_seedsigner_os", classmethod(lambda cls: False))

        assert str(microsd_views.flash_images_dir()) == "/boot/microsd-images"
