"""A flash or a wipe has only happened if what dd wrote reached the card."""
# Must import base before any seedsigner modules
from base import BaseTest

import pytest

from seedsigner.views import microsd_views
from seedsigner.views.view import MainMenuView

from test_microsd_device_guard import (
    FILE, SD_DEV, build_view, fake_kernel, patch_environment,
)
from test_microsd_unmount_before_write import (
    RAW_WRITERS, SEEDSIGNER_OS_LOOPS, SEEDSIGNER_OS_MOUNTS, writes,
)


SUCCESS = {
    microsd_views.ToolsMicroSDFlashView: "MicroSD Flashed",
    microsd_views.ToolsMicroSDWipeZeroView: "MicroSD Wiped",
    microsd_views.ToolsMicroSDWipeRandomView: "MicroSD Wiped",
}


def removed(commands):
    """The paths rm was run on, in order."""
    return [cmd[-1] for cmd in commands if "rm" in cmd]


def run_view(monkeypatch, tmp_path, view_cls, on_seedsigner_os=True, dd_returncode=0, **kernel):
    commands = []
    patch_environment(monkeypatch, commands, on_seedsigner_os=on_seedsigner_os,
                      dd_returncode=dd_returncode)
    dev = fake_kernel(monkeypatch, tmp_path, SEEDSIGNER_OS_MOUNTS, SEEDSIGNER_OS_LOOPS, **kernel)
    monkeypatch.setattr(microsd_views, "find_sd_card_device", lambda: SD_DEV)
    view, screens = build_view(monkeypatch, view_cls)
    destination = view.run()
    return destination, screens, commands, dev


class TestAWriteMustReachTheCard(BaseTest):
    """
    dd opens of= with O_CREAT. A card pulled after it was unmounted takes its
    node with it, and dd then writes a regular file of that name instead --
    in RAM, on devtmpfs -- and exits 0, and the view said the card was
    flashed or wiped. devtmpfs does not replace a file it did not make, so
    that file went on standing in for the card: every later flash, wipe and
    Verify found it, and succeeded.
    """

    @pytest.mark.parametrize("put_back", [False, True], ids=["pulled", "put-back"])
    @pytest.mark.parametrize("view_cls,on_seedsigner_os", RAW_WRITERS)
    def test_a_write_to_a_pulled_card_is_a_failure(self, monkeypatch, tmp_path, view_cls, on_seedsigner_os,
                                                   put_back):
        destination, screens, commands, dev = run_view(
            monkeypatch, tmp_path, view_cls, on_seedsigner_os,
            pull_card=lambda cmd: any(part.startswith("of=") for part in cmd), put_back=put_back,
        )

        assert not screens.showed(SUCCESS[view_cls])
        assert screens.showed("did not reach the MicroSD card")
        # Nothing is written after the write that missed: on SeedSigner OS
        # that is the zeroing, and the image never goes anywhere.
        assert len(writes(commands)) == 1, commands
        # The file dd made is gone, so the card's node can come back.
        assert dev[SD_DEV] != FILE
        assert removed(commands) == [SD_DEV], commands
        assert destination.View_cls is MainMenuView

    @pytest.mark.parametrize("view_cls,on_seedsigner_os", RAW_WRITERS)
    def test_a_file_left_by_a_dd_that_failed_is_removed_too(self, monkeypatch, tmp_path, view_cls,
                                                            on_seedsigner_os):
        # RAM runs out long before most images do.
        destination, screens, commands, dev = run_view(
            monkeypatch, tmp_path, view_cls, on_seedsigner_os, dd_returncode=1,
            pull_card=lambda cmd: any(part.startswith("of=") for part in cmd),
        )

        assert not screens.showed(SUCCESS[view_cls])
        assert screens.showed("did not reach the MicroSD card")
        assert dev[SD_DEV] != FILE
        assert removed(commands) == [SD_DEV], commands
        assert destination.View_cls is MainMenuView

    def test_a_card_pulled_between_zeroing_and_the_image_is_not_flashed(self, monkeypatch, tmp_path):
        destination, screens, commands, dev = run_view(
            monkeypatch, tmp_path, microsd_views.ToolsMicroSDFlashView,
            pull_card=lambda cmd: "if=/tmp/img.img" in cmd,
        )

        assert not screens.showed("MicroSD Flashed")
        assert screens.showed("did not reach the MicroSD card")
        assert dev[SD_DEV] != FILE
        assert removed(commands) == [SD_DEV], commands
        assert destination.View_cls is MainMenuView

    @pytest.mark.parametrize("view_cls,on_seedsigner_os", RAW_WRITERS)
    def test_a_write_that_reached_the_card_removes_nothing(self, monkeypatch, tmp_path, view_cls, on_seedsigner_os):
        _, screens, commands, dev = run_view(monkeypatch, tmp_path, view_cls, on_seedsigner_os)

        assert screens.showed(SUCCESS[view_cls])
        assert removed(commands) == [], commands
        assert dev[SD_DEV] == "179:0"


class TestVerifyMustReadTheCard(BaseTest):
    """A file standing in for the card hashes as well as the card does."""

    def test_a_file_at_the_cards_path_is_not_hashed_as_the_card(self, monkeypatch, tmp_path):
        destination, screens, commands, dev = run_view(
            monkeypatch, tmp_path, microsd_views.ToolsMicroSDVerifyView, nodes={SD_DEV: FILE},
        )

        assert not screens.showed("Matched Checksum")
        assert "Unfamilliar Checksum" not in screens.titles
        assert screens.showed("Could not read")
        assert dev[SD_DEV] != FILE
        assert removed(commands) == [SD_DEV], commands
        assert destination.View_cls is MainMenuView

    def test_the_card_itself_is_hashed(self, monkeypatch, tmp_path):
        _, screens, commands, _ = run_view(monkeypatch, tmp_path, microsd_views.ToolsMicroSDVerifyView)

        assert "Unfamilliar Checksum" in screens.titles
        assert removed(commands) == [], commands
