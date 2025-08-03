from base import BaseTest


class TestSatochipImportSeed(BaseTest):

    def test_init_after_seed_selection(self, monkeypatch):
        from seedsigner.views import tools_views
        from seedsigner.helpers import seedkeeper_utils
        from seedsigner.models.seed import Seed
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
        )

        seed = Seed(
            mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()
        )
        self.controller.storage.seeds = [seed]

        call_sequence = []

        def fake_run_screen(self, Screen_cls, **kwargs):
            call_sequence.append(Screen_cls)
            if Screen_cls == ButtonListScreen:
                return 0
            elif Screen_cls in [LargeIconStatusScreen, WarningScreen]:
                return 0
            return 0

        view = tools_views.ToolsSatochipImportSeedView()
        view.run_screen = fake_run_screen.__get__(view, tools_views.ToolsSatochipImportSeedView)

        def fake_init_satochip(parent, init_card_filter=None):
            # Ensure seed selection screen was shown before connecting to the card
            assert call_sequence == [ButtonListScreen]

            class MockConnector:
                def card_bip32_import_seed(self, seed_bytes):
                    pass

            return MockConnector()

        monkeypatch.setattr(seedkeeper_utils, "init_satochip", fake_init_satochip)

        destination = view.run()

        assert destination.View_cls == tools_views.MainMenuView
        # init_satochip should have been called after the seed selection screen
        assert call_sequence[0] == ButtonListScreen
