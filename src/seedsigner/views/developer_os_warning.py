from dataclasses import dataclass

from seedsigner.views.view import View, Destination
from seedsigner.gui.screens.screen import WarningScreen, ButtonOption
from seedsigner.helpers.l10n import mark_for_translation as _mft


@dataclass
class DeveloperOSWarningView(View):
    """Warn users that a developer SeedSignerOS image is running."""

    def run(self) -> Destination:
        self.run_screen(
            WarningScreen,
            title=_mft("Development Build"),
            status_headline=_mft("Not secure!"),
            text=_mft(
                "This SeedSignerOS development build is for testing only.\nDo NOT use with real seeds or private keys."
            ),
            button_data=[ButtonOption(_mft("I Understand"))],
        )
        return Destination(None)

