"""Unit tests for ``views/keycard_views.py`` helpers.

Currently exercises only the small pieces that don't need a full
controller/screen plumbing -- in particular
``_error_destination`` which must keep ``skip_current_view=True`` so
that pressing OK on a Keycard error screen does NOT bounce the user
back into the failing view (re-running the failing wait_for_card and
trapping them on the same error).
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


# Same hardware mocks the other keycard tests use.
def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
    ]:
        sys.modules.setdefault(mod, MagicMock())

_install_hw_mocks()


class TestErrorDestination(unittest.TestCase):
    def test_skip_current_view_is_true(self):
        """OK on a Keycard error screen must pop past the failing view.

        Without ``skip_current_view=True`` BackStackView returns to the
        view that originated the error; that view re-runs its
        wait_for_card and the user is stuck on the same error. This
        test pins the flag so the bug cannot regress.
        """
        from seedsigner.views.keycard_views import _error_destination, KeycardErrorView

        dest = _error_destination("Card not reachable", "no card detected")

        self.assertIs(dest.View_cls, KeycardErrorView)
        self.assertTrue(dest.skip_current_view)
        self.assertEqual(dest.view_args["title"], "Card not reachable")
        self.assertEqual(dest.view_args["message"], "no card detected")


if __name__ == "__main__":
    unittest.main()
