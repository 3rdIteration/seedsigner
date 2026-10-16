"""Only an SD card is ever the MicroSD card: eMMC is the board's own storage."""
# Must import base before any seedsigner modules
from base import BaseTest

import os

from seedsigner.views import microsd_views


class TestOnlyAnSDCardIsEverChosen(BaseTest):
    """
    eMMC is an mmcblk device too, and on a board that has it, it is the board's
    own storage -- partitioned, so the old "first partitioned mmcblk" rule chose
    it ahead of the card in the slot. The kernel says which is which in
    device/type: "SD" for a card, "MMC" for eMMC.
    """

    def _sysfs(self, monkeypatch, layout, types):
        real_listdir = os.listdir

        def listdir(path):
            if path == "/sys/block":
                return list(layout)
            device = str(path).rsplit("/", 1)[-1]
            if str(path).startswith("/sys/block/") and device in layout:
                return layout[device]
            return real_listdir(path)

        monkeypatch.setattr(os, "listdir", listdir)
        monkeypatch.setattr(microsd_views, "_mmc_device_type", lambda d: types.get(d))

    def test_the_card_is_chosen_over_a_partitioned_emmc(self, monkeypatch):
        self._sysfs(monkeypatch,
                    {"mmcblk0": ["mmcblk0p1", "mmcblk0p2"], "mmcblk1": ["size"]},
                    {"mmcblk0": "MMC", "mmcblk1": "SD"})

        assert microsd_views.find_sd_card_device() == "/dev/mmcblk1"

    def test_emmc_alone_is_never_a_card(self, monkeypatch):
        self._sysfs(monkeypatch, {"mmcblk0": ["mmcblk0p1"]}, {"mmcblk0": "MMC"})

        assert microsd_views.find_sd_card_device() is None

    def test_a_device_that_will_not_say_what_it_is_is_not_chosen(self, monkeypatch):
        self._sysfs(monkeypatch, {"mmcblk0": ["mmcblk0p1"]}, {})

        assert microsd_views.find_sd_card_device() is None
