"""
    Unit coverage for the per-applet card filtering that replaced the shared
    'Common Functions' menu + Device Filter (issue #402).

    The former Common menu let a single screen target satochip/seedkeeper/satodime via
    a controller-held filter. That is gone: each applet menu now passes an explicit
    ``card_filter`` into the shared views, and ``_applet_card_filter`` intersects it with
    whatever card types the individual function supports. These tests pin that contract
    without needing a reader or card -- routing is exercised by faking run_screen, exactly
    like test_tools_smartcard_keycard_menu.py.
"""

from base import BaseTest

from seedsigner.views import smartcard_views
from seedsigner.views.smartcard_views import _applet_card_filter


class TestAppletCardFilter:
    def test_explicit_filter_is_intersected_with_allowed(self):
        assert _applet_card_filter(["satochip"], ["satochip", "seedkeeper"]) == ["satochip"]

    def test_unsupported_applet_dropped(self):
        # Satodime is not factory-resettable; asking for it yields nothing.
        assert _applet_card_filter(["satodime"], ["satochip", "seedkeeper"]) == []

    def test_none_falls_back_to_all_allowed(self):
        assert _applet_card_filter(None, ["seedkeeper", "satodime"]) == ["seedkeeper", "satodime"]

    def test_order_and_membership_preserved(self):
        out = _applet_card_filter(["seedkeeper", "satochip"], ["satochip", "seedkeeper", "satodime"])
        assert out == ["seedkeeper", "satochip"]


class TestSharedViewsAcceptCardFilter:
    """Every formerly-Common view must take a card_filter kwarg and stash it."""

    def test_all_shared_views_construct(self):
        for cls in (
            smartcard_views.ToolsSmartcardInfoView,
            smartcard_views.ToolsSmartcardGenuineCheckView,
            smartcard_views.ToolsSatochipChangePinView,
            smartcard_views.ToolsSatochipChangeLabelView,
            smartcard_views.ToolsSatochipChangeNFCView,
            smartcard_views.ToolsCommonNdefView,
            smartcard_views.ToolsSatochipFactoryResetView,
        ):
            view = cls(card_filter=["satochip"])
            assert view.card_filter == ["satochip"]

    def test_fingerprint_view_defaults_to_satochip(self):
        view = smartcard_views.ToolsSmartcardViewFingerprintView()
        assert view.card_filter == ["satochip"]


class TestCardSettingsRouting(BaseTest):
    """Each Card Settings item routes to the shared view scoped to that applet."""

    def _route(self, menu_view, option):
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return kwargs["button_data"].index(option)

        menu_view.run_screen = fake_run_screen
        return menu_view.run()

    def test_satochip_card_settings_scopes_to_satochip(self):
        dest = self._route(
            smartcard_views.ToolsSatochipCardSettingsView(),
            smartcard_views.ToolsSatochipCardSettingsView.INFO,
        )
        assert dest.View_cls is smartcard_views.ToolsSmartcardInfoView
        assert dest.view_args["card_filter"] == ["satochip"]

    def test_seedkeeper_card_settings_scopes_to_seedkeeper(self):
        for option, target in (
            (smartcard_views.ToolsSeedkeeperCardSettingsView.INFO, smartcard_views.ToolsSmartcardInfoView),
            (smartcard_views.ToolsSeedkeeperCardSettingsView.CONFIGURE_NDEF, smartcard_views.ToolsCommonNdefView),
            (smartcard_views.ToolsSeedkeeperCardSettingsView.FACTORY_RESET, smartcard_views.ToolsSatochipFactoryResetView),
        ):
            dest = self._route(smartcard_views.ToolsSeedkeeperCardSettingsView(), option)
            assert dest.View_cls is target
            assert dest.view_args["card_filter"] == ["seedkeeper"]

    def test_satodime_card_settings_scopes_to_satodime(self):
        for option, target in (
            (smartcard_views.ToolsSatodimeCardSettingsView.INFO, smartcard_views.ToolsSmartcardInfoView),
            (smartcard_views.ToolsSatodimeCardSettingsView.GENUINE, smartcard_views.ToolsSmartcardGenuineCheckView),
            (smartcard_views.ToolsSatodimeCardSettingsView.CONFIGURE_NDEF, smartcard_views.ToolsCommonNdefView),
        ):
            dest = self._route(smartcard_views.ToolsSatodimeCardSettingsView(), option)
            assert dest.View_cls is target
            assert dest.view_args["card_filter"] == ["satodime"]

    def test_satodime_menu_offers_only_supported_settings(self):
        """Satodime has no Change PIN/Label/NFC or Factory Reset in its Card Settings."""
        captured = {}

        def capture_only(screen_cls, **kwargs):
            captured["button_data"] = kwargs["button_data"]
            return 0  # routes to INFO; the menu itself makes no connector call

        smartcard_views.ToolsSatodimeCardSettingsView().run_screen = capture_only

        menu = smartcard_views.ToolsSatodimeCardSettingsView()
        menu.run_screen = capture_only
        menu.run()

        labels = [b.button_label for b in captured["button_data"]]
        assert "Card Info" in labels
        assert "Genuine Check" in labels
        assert "Configure NDEF" in labels
        assert "Change PIN" not in labels
        assert "Factory Reset Card" not in labels
