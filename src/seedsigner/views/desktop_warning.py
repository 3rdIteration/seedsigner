from dataclasses import dataclass

from seedsigner.views.view import View, Destination
from seedsigner.gui.screens.screen import WarningScreen, ButtonOption
from seedsigner.helpers.l10n import mark_for_translation as _mft


@dataclass
class DesktopWarningView(View):
    """Warn desktop users that this build is for testing only."""

    def run(self) -> Destination:
        self.run_screen(
            WarningScreen,
            title=_mft("Desktop Mode"),
            status_headline=_mft("Not secure!"),
            text=_mft(
                "This desktop version is for testing only.\nDo NOT use with real seeds or private keys."
            ),
            button_data=[ButtonOption(_mft("I Understand"))],
        )
        return Destination(None)

