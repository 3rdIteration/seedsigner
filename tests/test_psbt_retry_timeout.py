# pylint: disable=missing-function-docstring
from types import SimpleNamespace

# Must import base before any seedsigner modules
from base import BaseTest

from seedsigner.views.psbt_views import (
    RETRY_TIMEOUT_STEP,
    bump_retry_timeout,
    clear_retry_timeout,
    signing_timeout,
)


class TestRetryTimeout(BaseTest):
    """Each retry must raise the timeout that was actually used."""

    def test_first_attempt_uses_the_setting(self):
        controller = SimpleNamespace()

        assert signing_timeout(controller, 2.0) == 2.0

    def test_a_retry_uses_the_raised_value(self):
        controller = SimpleNamespace()

        used = signing_timeout(controller, 2.0)
        bump_retry_timeout(controller, used)
        assert signing_timeout(controller, 2.0) == 2.0 + RETRY_TIMEOUT_STEP

    def test_retries_keep_climbing(self):
        controller = SimpleNamespace()
        seen = []
        for _ in range(3):
            used = signing_timeout(controller, 2.0)
            seen.append(used)
            bump_retry_timeout(controller, used)

        assert seen == [2.0, 2.0 + RETRY_TIMEOUT_STEP, 2.0 + 2 * RETRY_TIMEOUT_STEP]

    def test_a_finished_flow_starts_from_the_setting_again(self):
        controller = SimpleNamespace()
        bump_retry_timeout(controller, signing_timeout(controller, 2.0))

        clear_retry_timeout(controller)

        assert signing_timeout(controller, 2.0) == 2.0


class TestFinalizeRetriesClimb(BaseTest):
    """
    The helpers above only help if PSBTFinalizeView uses them: each "Retry
    (higher timeout)" has to hand the card more time than the attempt that
    just expired, and the screen has to quote the timeout that expired.
    """

    def test_each_retry_gives_the_card_a_longer_timeout(self, monkeypatch):
        from embit import script
        from embit.ec import PrivateKey
        from embit.psbt import PSBT
        from embit.transaction import Transaction, TransactionInput, TransactionOutput

        from seedsigner.helpers import satochip_signer, seedkeeper_utils
        from seedsigner.helpers.satochip_signer import SignResult
        from seedsigner.models.settings import SettingsConstants
        from seedsigner.views import psbt_views

        spk = script.p2wpkh(PrivateKey(b"\x01" * 32).get_public_key())
        prev = Transaction(vin=[TransactionInput(b"\x11" * 32, 0)], vout=[TransactionOutput(100_000, spk)])
        psbt = PSBT(Transaction(vin=[TransactionInput(prev.txid(), 0)], vout=[TransactionOutput(90_000, spk)]))
        psbt.inputs[0].witness_utxo = prev.vout[0]
        self.controller.psbt = psbt
        self.controller.psbt_parser = None
        self.controller.psbt_sign_with_satochip = True

        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *args, **kwargs: SimpleNamespace())
        timeouts = []

        def card_that_times_out(psbt, connector, timeout=None):
            timeouts.append(timeout)
            return SignResult(signed_count=0, timed_out=True)

        monkeypatch.setattr(satochip_signer, "sign_psbt_with_satochip", card_that_times_out)

        quoted = []
        for _ in range(3):
            view = psbt_views.PSBTFinalizeView()

            def run_screen(screen_cls, **kwargs):
                if "text" in kwargs:
                    quoted.append(kwargs["text"])
                # Approve, then "Retry (higher timeout)" when it times out
                return 0

            monkeypatch.setattr(view, "run_screen", run_screen)
            assert view.run().View_cls is psbt_views.PSBTFinalizeView

        setting = self.settings.get_value(SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT)
        assert timeouts == [setting, setting + RETRY_TIMEOUT_STEP, setting + 2 * RETRY_TIMEOUT_STEP]
        assert f"timed out at {timeouts[-1]}s" in quoted[-1]


class TestPSBTFlowStateIsResetTogether(BaseTest):
    """
    The card's key data and the raised retry timeout are psbt-flow state, so
    they belong with the rest of it. Leaving them behind meant the next psbt
    started from another transaction's timeout, or with a card whose xpub the
    user had walked away from -- and Home, the wipe and start-up each cleared
    their own subset of the same list.
    """

    def test_resetting_the_flow_clears_the_card_keys_and_retry_timeout(self):
        from seedsigner.controller import Controller
        from seedsigner.views.psbt_views import bump_retry_timeout, signing_timeout

        controller = Controller.get_instance()
        controller.psbt_sign_with_satochip = True
        controller.psbt_card_keys = {"root": object()}
        bump_retry_timeout(controller, 5.0)

        controller.reset_psbt_flow_state()

        assert controller.psbt is None
        assert controller.psbt_parser is None
        assert controller.psbt_seed is None
        assert controller.psbt_sign_with_satochip is False
        assert controller.psbt_card_keys is None
        assert signing_timeout(controller, 2.0) == 2.0
