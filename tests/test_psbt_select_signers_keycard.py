from base import BaseTest

from embit.psbt import PSBT

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import psbt_views


class TestPSBTSelectSignerKeycard(BaseTest):
    def test_psbt_select_signer_shows_keycard_when_enabled(self):
        self.settings.set_value(
            SettingsConstants.SETTING__KEYCARD_SUPPORT,
            SettingsConstants.OPTION__ENABLED,
        )

        self.controller.psbt = PSBT()
        self.controller.psbt_seed = None
        self.controller.storage.seeds = []

        view = psbt_views.PSBTSelectSeedView()
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return RET_CODE__BACK_BUTTON

        view.run_screen = fake_run_screen
        view.run()

        assert psbt_views.PSBTSelectSeedView.KEYCARD in captured["button_data"]

    def test_psbt_keycard_selection_forces_keycard_backend(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__KEYCARD_SUPPORT,
            SettingsConstants.OPTION__ENABLED,
        )

        self.controller.psbt = PSBT()
        self.controller.psbt_seed = None
        self.controller.storage.seeds = []

        called = {}

        def fake_init_satochip(parent, init_card_filter=None, require_pin=True, backend_preference=None):
            _ = parent
            _ = require_pin
            called["init_card_filter"] = init_card_filter
            called["backend_preference"] = backend_preference
            return None

        from seedsigner.helpers import seedkeeper_utils
        monkeypatch.setattr(seedkeeper_utils, "init_satochip", fake_init_satochip)

        view = psbt_views.PSBTSelectSeedView()

        def fake_run_screen(screen_cls, **kwargs):
            return kwargs["button_data"].index(psbt_views.PSBTSelectSeedView.KEYCARD)

        view.run_screen = fake_run_screen
        destination = view.run()

        assert called["init_card_filter"] == ["satochip"]
        assert called["backend_preference"] == "keycard"
        assert destination.View_cls == psbt_views.PSBTSelectSeedView
