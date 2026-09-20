"""Capture documentation screenshots of smartcard screens against real jcardsim applets.

Opt-in: set ``SEEDSIGNER_DOCS_OUT`` (e.g. ``docs/img/guide``) to write the PNGs.
Without it pytest ignores this directory; without Java/applet sources each test skips.
"""

import sys
from unittest.mock import MagicMock

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import BaseTest

# base.py stubs pysatochip so the ordinary suite runs cardless; these need it real.
for _name in [m for m in sys.modules if m == "pysatochip" or m.startswith("pysatochip.")]:
    if isinstance(sys.modules[_name], MagicMock):
        del sys.modules[_name]

from jcardsim import why_unavailable
from real_screen_fixtures import simulated_satochip, simulated_satodime, simulated_seedkeeper
from ui_driver import Back, select

from seedsigner.hardware.buttons import HardwareButtonsConstants as K
from seedsigner.helpers import seedkeeper_utils
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import tools_views  # noqa: F401  (facade; must import before the split modules)
from seedsigner.views import password_generator_views, smartcard_views

from .capture import DocsCaptureSession


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)

# A deterministic 64-byte seed used to seed the simulated Satochip.
TEST_SEED_HEX = "00" * 32 + "11" * 32


class DocsBase(BaseTest):
    def enable_smartcard(self):
        for setting in (
            SettingsConstants.SETTING__SMARTCARD_SUPPORT,
            SettingsConstants.SETTING__SATOCHIP_SUPPORT,
            SettingsConstants.SETTING__KEYCARD_SUPPORT,
            SettingsConstants.SETTING__SPECTER_DIY_SUPPORT,
        ):
            self.settings.set_value(setting, SettingsConstants.OPTION__ENABLED)

    @staticmethod
    def import_secret(connector, label: str, secret: bytes = b"doc-secret", secret_type: str = "Password"):
        header = connector.make_header(secret_type, "Plaintext export allowed", label)
        connector.seedkeeper_import_secret(
            {"header": header, "secret_list": [len(secret)] + list(secret)}
        )


class TestSeedKeeperDocs(DocsBase):
    def test_menu_card_info_and_secrets(self, monkeypatch):
        self.enable_smartcard()
        with simulated_seedkeeper(monkeypatch) as conn:
            self.import_secret(conn, "alice-wallet")
            self.import_secret(conn, "bob-wallet")

            with DocsCaptureSession("seedkeeper", script=[Back()]) as cap:
                smartcard_views.ToolsSeedkeeperView().run()
            assert cap.saved

            with DocsCaptureSession("seedkeeper", script=[Back()]) as cap:
                smartcard_views.ToolsSeedkeeperViewSecretsView().run()
            assert cap.saved

            with DocsCaptureSession("seedkeeper", script=[Back()]) as cap:
                smartcard_views.ToolsSeedkeeperFreeSpaceView().run()
            assert cap.saved

            with DocsCaptureSession("seedkeeper", script=[Back()]) as cap:
                smartcard_views.ToolsSmartcardInfoView(card_filter=["seedkeeper"]).run()
            assert cap.saved

    def test_load_descriptor_list(self, monkeypatch):
        """The "Load MultiSig Descriptor" picker, populated the way saving writes it."""
        descriptor = (
            "wsh(sortedmulti(1,"
            "[22bde1a9/48h/1h/0h/2h]tpubDFfsBrmpj226ZYiRszYi2qK6iGvh2vkkghfGB2YiRUVY4rqqedHCFEgw12FwDkm7rUoVtq9wLTKc6BN2sxswvQeQgp7m8st4FP8WtP8go76/{0,1}/*,"
            "[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*"
            "))#3jhtf6yx"
        )
        self.enable_smartcard()
        with simulated_seedkeeper(monkeypatch) as conn:
            secret_text = list(descriptor.encode("utf-8"))
            header = conn.make_header("Descriptor", "Plaintext export allowed", "doc-wallet")
            conn.seedkeeper_import_secret(
                {"header": header, "secret_list": list(len(secret_text).to_bytes(2, "big")) + secret_text}
            )

            with DocsCaptureSession("seedkeeper", script=[Back()]) as cap:
                smartcard_views.ToolsSeedkeeperLoadDescriptorView().run()
            assert cap.saved


class TestSatochipDocs(DocsBase):
    def test_menu_card_info_and_fingerprint(self, monkeypatch):
        self.enable_smartcard()
        with simulated_satochip(monkeypatch) as conn:
            conn.card_bip32_import_seed(list(bytes.fromhex(TEST_SEED_HEX)))

            with DocsCaptureSession("satochip", script=[Back()]) as cap:
                smartcard_views.ToolsSatochipView().run()
            assert cap.saved

            with DocsCaptureSession("satochip", script=[Back()]) as cap:
                smartcard_views.ToolsSmartcardInfoView(card_filter=["satochip"]).run()
            assert cap.saved

            with DocsCaptureSession("satochip", script=[Back()]) as cap:
                smartcard_views.ToolsSmartcardViewFingerprintView(card_filter=["satochip"]).run()
            assert cap.saved


class TestSatodimeDocs(DocsBase):
    def test_slots_and_address(self, monkeypatch):
        self.enable_smartcard()
        with simulated_satodime(monkeypatch) as conn:
            seedkeeper_utils.claim_satodime_ownership(conn)
            conn.satodime_set_unlock_secret()
            conn.satodime_set_unlock_counter()
            conn.satodime_get_status()
            (_, sw1, sw2, _, _) = conn.satodime_seal_key(0, bytes(range(32)))
            assert (sw1, sw2) == (0x90, 0x00), f"seal failed: {sw1:#x} {sw2:#x}"

            with DocsCaptureSession("satodime", script=[Back()]) as cap:
                smartcard_views.ToolsSatodimeView().run()
            assert cap.saved

            # ToolsSatodimeSlotsView builds and caches the slot list as a side effect.
            with DocsCaptureSession("satodime", script=[Back()]) as cap:
                smartcard_views.ToolsSatodimeSlotsView().run()
            assert cap.saved

            with DocsCaptureSession("satodime", script=[Back()]) as cap:
                smartcard_views.ToolsSatodimeSlotMenuView(0).run()
            assert cap.saved

            with DocsCaptureSession("satodime", script=[K.KEY_PRESS]) as cap:
                smartcard_views.ToolsSatodimeViewAddressView(0).run()
            assert cap.saved


class TestPasswordToSeedKeeperDocs(DocsBase):
    def test_save_password_to_seedkeeper(self, monkeypatch):
        self.enable_smartcard()

        # The label entry is a SeedAddPassphraseScreen displayed directly by the helper;
        # stub it so the capture doesn't depend on its keyboard layout.
        class _FakeLabelScreen:
            def __init__(self, *args, **kwargs):
                pass

            def display(self):
                return {"passphrase": "docpassword"}

        monkeypatch.setattr(
            password_generator_views.seed_screens,
            "SeedAddPassphraseScreen",
            _FakeLabelScreen,
        )

        with simulated_seedkeeper(monkeypatch) as conn:
            script = select("Save to Seedkeeper") + select("Continue")
            with DocsCaptureSession("seedkeeper", script=script) as cap:
                password_generator_views.ToolsPasswordSaveView(
                    password="correct horse battery staple"
                ).run()
            assert cap.saved
            # The secret really made it onto the simulated card.
            labels = [h["label"] for h in conn.seedkeeper_list_secret_headers()]
            assert "docpassword" in labels
