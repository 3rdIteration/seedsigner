# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest

from seedsigner.controller import Controller
from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.views import psbt_views


class TestLeavingThePSBTFlow(BaseTest):
    """
    Every way out of the signing flow has to drop what that psbt accumulated.
    The card's account xpub and the raised retry timeout are the two that were
    left behind: the next psbt then began with another transaction's timeout,
    or holding an xpub for a card the user had walked away from.
    """

    def test_a_refusal_drops_the_card_state_and_the_retry_timeout(self, monkeypatch):
        controller = Controller.get_instance()
        controller.psbt_sign_with_satochip = True
        controller.psbt_card_keys = {"root": object()}
        psbt_views.bump_retry_timeout(controller, 5.0)

        view = psbt_views.PSBTRefusalView(code="UNREACHABLE_CHANGE_PATH", message="nope")
        monkeypatch.setattr(view, "run_screen", lambda *a, **kw: 0)

        view.run()

        assert controller.psbt_sign_with_satochip is False
        assert controller.psbt_card_keys is None
        assert psbt_views.signing_timeout(controller, 2.0) == 2.0

    def test_backing_out_of_finalize_drops_the_retry_timeout(self, monkeypatch):
        """
        BACK from the approval screen abandons this signing attempt, so the
        timeout it raised does not belong to whatever is reviewed next. The
        card's key data stays: BACK returns to the review, and rebuilding the
        review's parser needs it.
        """
        from test_psbt_mixed_account_paths import NETWORK, mixed_account_psbt
        from psbt_testing_util import PSBTTestData
        from seedsigner.models.psbt_parser import PSBTParser

        controller = Controller.get_instance()
        controller.psbt = mixed_account_psbt()
        controller.psbt_parser = PSBTParser(
            controller.psbt, seed=PSBTTestData.seed, network=NETWORK
        )
        card_keys = {"root": object()}
        controller.psbt_card_keys = card_keys
        psbt_views.bump_retry_timeout(controller, 5.0)

        view = psbt_views.PSBTFinalizeView()
        monkeypatch.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)

        destination = view.run()

        assert destination.View_cls.__name__ == "BackStackView"
        assert psbt_views.signing_timeout(controller, 2.0) == 2.0
        assert controller.psbt_card_keys is card_keys
