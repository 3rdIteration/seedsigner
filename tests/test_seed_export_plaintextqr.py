from base import BaseTest

from seedsigner.models.seed import Seed, XprvSeed
from seedsigner.views.seed_views import SeedExportPlaintextQRView


class TestSeedExportPlaintextQRView(BaseTest):
    def test_exports_xprv_text_for_xprv_seed(self):
        xprv = "xprv9s21ZrQH143K3dzDLfeY3cMp23u5vDeFYftu5RPYZPucKc99mNEddU4w99GxdgUGcSfMpVDxhnR1XpJzZNXRN1m6xNgnzFS5MwMP6QyBRKV"
        self.controller.storage.set_pending_seed(XprvSeed(xprv))
        self.controller.storage.finalize_pending_seed()

        captured = {}
        view = SeedExportPlaintextQRView(seed=self.controller.storage.seeds[0])

        def fake_run_screen(_screen_cls, **kwargs):
            captured["encoder"] = kwargs["qr_encoder"]
            return 0

        view.run_screen = fake_run_screen
        view.run()

        assert captured["encoder"].next_part() == xprv

    def test_exports_mnemonic_text_for_bip39_seed(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        self.controller.storage.set_pending_seed(Seed(mnemonic=mnemonic.split()))
        self.controller.storage.finalize_pending_seed()

        captured = {}
        view = SeedExportPlaintextQRView(seed=self.controller.storage.seeds[0])

        def fake_run_screen(_screen_cls, **kwargs):
            captured["encoder"] = kwargs["qr_encoder"]
            return 0

        view.run_screen = fake_run_screen
        view.run()

        assert captured["encoder"].next_part() == mnemonic
