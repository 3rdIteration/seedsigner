import base  # noqa: F401 -- ensure hardware mocks
from unittest.mock import Mock

from base import BaseTest
from seedsigner.gui.screens.screen import DireWarningScreen, ErrorScreen, RET_CODE__BACK_BUTTON, WarningScreen
from seedsigner.hardware.battery_hat import BatteryHat
from seedsigner.views import seed_views, tools_views
from seedsigner.views.view import BackStackView, Destination


class TestStatusHeadlines(BaseTest):
    def test_error_screen_default_headline_is_none(self):
        assert ErrorScreen.__dataclass_fields__["status_headline"].default is None
        assert WarningScreen.__dataclass_fields__["status_headline"].default == "Privacy Leak!"
        assert DireWarningScreen.__dataclass_fields__["status_headline"].default == "Classified Info!"

    def test_seedkeeper_no_secrets_warning_omits_privacy_headline(self, monkeypatch):
        class MockConnector:
            def seedkeeper_list_secret_headers(self):
                return []

        monkeypatch.setattr(
            seed_views.seedkeeper_utils,
            "init_satochip",
            lambda *args, **kwargs: MockConnector(),
        )

        view = seed_views.SeedKeeperSelectView()
        view.run_screen = Mock(return_value=0)

        result = view.run()

        assert view.run_screen.call_count == 1
        assert view.run_screen.call_args.args[0] is WarningScreen
        assert view.run_screen.call_args.kwargs["status_headline"] is None
        assert result == Destination(BackStackView)

    def test_seedkeeper_back_button_returns_backstack(self, monkeypatch):
        """Regression test for issue #389: pressing back on "Select Secret"
        must return BackStackView without crashing on the missing `self.seed`
        attribute."""
        class MockConnector:
            def seedkeeper_list_secret_headers(self):
                return [{
                    "id": 1,
                    "label": "Test Secret",
                    "type": 48,
                    "subtype": 0,
                    "export_rights": 1,
                }]

        monkeypatch.setattr(
            seed_views.seedkeeper_utils,
            "init_satochip",
            lambda *args, **kwargs: MockConnector(),
        )

        view = seed_views.SeedKeeperSelectView()
        view.run_screen = Mock(return_value=RET_CODE__BACK_BUTTON)

        result = view.run()

        assert view.run_screen.call_count == 1
        assert result == Destination(BackStackView)

    def test_seedkeeper_error_warning_omits_privacy_headline(self, monkeypatch):
        class MockConnector:
            def seedkeeper_list_secret_headers(self):
                raise RuntimeError("Interrupted")

        monkeypatch.setattr(
            seed_views.seedkeeper_utils,
            "init_satochip",
            lambda *args, **kwargs: MockConnector(),
        )

        view = seed_views.SeedKeeperSelectView()
        view.run_screen = Mock(return_value=0)

        view.run()

        assert view.run_screen.call_args.args[0] is WarningScreen
        assert view.run_screen.call_args.kwargs["status_headline"] is None

    def test_slip39_seedkeeper_no_secrets_warning_omits_privacy_headline(self, monkeypatch):
        class MockConnector:
            def seedkeeper_list_secret_headers(self):
                return []

        monkeypatch.setattr(
            seed_views.seedkeeper_utils,
            "init_satochip",
            lambda *args, **kwargs: MockConnector(),
        )

        view = seed_views.SeedSlip39LoadFromSeedkeeperView()
        view.run_screen = Mock(return_value=0)

        view.run()

        assert view.run_screen.call_args.args[0] is WarningScreen
        assert view.run_screen.call_args.kwargs["status_headline"] is None

    def test_slip39_seedkeeper_error_warning_omits_privacy_headline(self, monkeypatch):
        class MockConnector:
            def seedkeeper_list_secret_headers(self):
                raise RuntimeError("Interrupted")

        monkeypatch.setattr(
            seed_views.seedkeeper_utils,
            "init_satochip",
            lambda *args, **kwargs: MockConnector(),
        )

        view = seed_views.SeedSlip39LoadFromSeedkeeperView()
        view.run_screen = Mock(return_value=0)

        view.run()

        assert view.run_screen.call_args.args[0] is WarningScreen
        assert view.run_screen.call_args.kwargs["status_headline"] is None

    def test_battery_calibration_missing_sd_warning_omits_privacy_headline(self, monkeypatch):
        battery_hat = Mock()
        battery_hat.is_enabled.return_value = True
        battery_hat.process_discharge_log.return_value = None
        monkeypatch.setattr(BatteryHat, "get_instance", classmethod(lambda cls: battery_hat))
        self.mock_microsd.is_inserted = False

        view = tools_views.ToolsBatteryCalibrationView()
        view.run_screen = Mock(return_value=0)

        view.run()

        assert view.run_screen.call_args.args[0] is WarningScreen
        assert view.run_screen.call_args.kwargs["status_headline"] is None
