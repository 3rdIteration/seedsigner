from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.views.view import View, Destination
from seedsigner.gui.screens.screen import WarningScreen, ButtonOption
from seedsigner.helpers.l10n import mark_for_translation as _mft


@dataclass
class DeveloperOSWarningView(View):
    """Warn that the running image is not hardened for production use.

    Names what is actually open rather than just asserting "development build",
    so the message stays true as hardening evolves and a partially-hardened
    image says exactly what slipped. Kept terse: this is a 240x240 screen and a
    wall of text gets dismissed unread.
    """

    def run(self) -> Destination:
        from seedsigner.helpers import hardening

        exposures = hardening.open_exposures()
        if exposures:
            text = _("Open: {items}.").format(items=", ".join(exposures)) + " " + _(
                "Usually means a development build. Do not use real seeds."
            )
        else:
            # Reached via the microsd_notice.py dev marker with nothing measurably
            # open — still a dev image, but don't claim exposures we can't name.
            text = _("Development build. Do not use real seeds.")

        self.run_screen(
            WarningScreen,
            title=_mft("Unhardened Build"),
            status_headline=_mft("Not secure!"),
            text=text,
            button_data=[ButtonOption(_mft("I Understand"))],
        )
        return Destination(None)
