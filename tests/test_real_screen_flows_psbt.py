"""
    Real-screen flow tests for PSBT signing.

    tests/test_flows_psbt.py already covers this routing thoroughly -- but with
    View.run_screen() mocked, so not one PSBT Screen is ever constructed. These are the
    screens that do the heaviest layout and text-fitting work in the app: the overview
    diagram, the input/output maths, per-address detail pages, change verification. A
    separate StubRenderer harness exists (tests/test_psbt_refusal_screens.py) precisely
    because that layout is a live risk, and it can only check screens in isolation.

    Here the whole flow runs with real Screens and scripted button input. Only the
    initial camera decode is mocked -- ScanView deliberately exposes `self.decoder` for
    exactly this (scan_views.py:99) -- and once controller.psbt is populated the rest of
    the flow needs no hardware at all.
"""

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest
from ui_driver import Back, UISession, select

from seedsigner.models.settings import SettingsConstants
from seedsigner.views import psbt_views, scan_views, seed_views
from seedsigner.views.view import MainMenuView


# A regtest single-sig P2WPKH PSBT: 2 inputs, 4 outputs (1 external + 3 change),
# 272 sat fee. Same vector as tests/test_flows_psbt.py, which documents it in full.
PSBT_2IN_4OUT = (
    "cHNidP8BANgCAAAAAsTXZs3fz/dmGb6M80+jjvJZdYya+cw5bT/dGuhZFdSlAAAAAAD9////qo6xg/UZ"
    "AvUkcbse1F+C9zbP/FeZNjThx7SCIn6eMCgBAAAAAP3///8EQOIBAAAAAAAWABSkZPM7kLcTRE2En1t3"
    "3/0RCHgMjQXYnnYAAAAAFgAUKMaPRKXdY4m8iKrE9j+rycskJU1A4gEAAAAAABYAFPYc9wiHRrYKAZYL"
    "LztREAwpPBIwipVcAwAAAAAWABSiFuiJIa4NrxLUBVQNS0NIun6DDtoRAABPAQQ1h88DBcQGZIAAAAA+"
    "0J+jlNL3dpWwlnBi8Dx+Ipg4e6uvB3HdjzFPX7r9CAOOlAIxgII+/xCcj+XoEenKH7wj5s5wlu7Q7CCZ"
    "WFLGLhA5Su0UVAAAgAEAAIAAAACAAAEA7QIAAAAEE6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1U"
    "cQ0BAAAAAP3///8TqeNf9+e+fuFuQohFzHM1gU5J9sJ015ad3sV7/VRxDQMAAAAA/f///xOp41/3575+"
    "4W5CiEXMczWBTkn2wnTXlp3exXv9VHENBAAAAAD9////E6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7F"
    "e/1UcQ0GAAAAAP3///8CUnheAwAAAAAWABRCfygPJ+Fjsx4BknYvvm3A3qKn2xJ/XQcAAAAAF6kU1I4T"
    "Ast5nAj15ey7vwe5cM3OFq+HlhEAAAEBH1J4XgMAAAAAFgAUQn8oDyfhY7MeAZJ2L75twN6ip9sBAwQB"
    "AAAAIgYCo7sfm78RQY3B5n0ac/QF8VtMAzFnci+h5D1MtpgRY7oYOUrtFFQAAIABAACAAAAAgAEAAAAG"
    "AAAAAAEAcQIAAAABxY7wh0nsfJQfzWrD/9rN9BYsM+iOmPaO6I0ANFgO/PcAAAAAAP3///8CptiUAAAA"
    "AAAWABRIm4HhQY/TzOjeWSPRrbuJo9MlW826oHYAAAAAFgAU0z+0L2QSLGtyQTn8FhbCpcI7jbliAQAA"
    "AQEfzbqgdgAAAAAWABTTP7QvZBIsa3JBOfwWFsKlwjuNuQEDBAEAAAAiBgITHmebEANk81CraV4xZIpq"
    "kNjjw0tIvezl1Ism1NRH3Rg5Su0UVAAAgAEAAIAAAACAAQAAAAAAAAAAIgICuTT7WnuiUTpObjWnZFHz"
    "IeEvW9PTB+1LLVFNQJVFeIIYOUrtFFQAAIABAACAAAAAgAEAAAAHAAAAACICAk8f3hpc5C35chgSg+Pe"
    "2zZ9IhHREd4aKW2+yAMRIFeqGDlK7RRUAACAAQAAgAAAAIABAAAACQAAAAAAIgIDjt1CjvrnMMnjbmTN"
    "KUAYoKEDRbmKjNjbq+6Ppqj3bqQYOUrtFFQAAIABAACAAAAAgAEAAAAIAAAAAA=="
)

# The SeedQR for the key that signs the PSBT above, and the mnemonic it encodes
# (four digits per word, each an index into the BIP-39 wordlist).
SEEDQR_FOR_PSBT = "080115060387063104071857067618681125136207731354"
MNEMONIC_FOR_PSBT = (
    "goddess rough corn exclude cream trial fee trumpet million prevent gaze power"
).split()


def load_psbt(view):
    view.decoder.add_data(PSBT_2IN_4OUT)


def load_seedqr(view):
    view.decoder.add_data(SEEDQR_FOR_PSBT)


def record_sig_count(into: list):
    """
    A `before_run` hook that snapshots how many inputs are signed.

    PSBTFinalizeView signs `controller.psbt` in place, so sampling this on the
    following View is what proves the flow actually signed rather than merely
    reaching the QR screen.
    """
    def hook(view):
        from seedsigner.models.psbt_parser import PSBTParser

        into.append(PSBTParser.sig_count(view.controller.psbt))

    return hook


class PSBTFlowTest(FlowTest):
    """Shared setup: regtest, and a seed already loaded unless a test says otherwise."""

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST
        )

    def load_signing_seed(self):
        """The seed the test PSBT is signed with, already in storage."""
        from seedsigner.models.seed import Seed

        seed = Seed(mnemonic=MNEMONIC_FOR_PSBT)
        self.controller.storage.set_pending_seed(seed)
        return self.controller.storage.finalize_pending_seed()



class TestPSBTSigningFlow(PSBTFlowTest):
    """Scan → select seed → review → approve → signed QR, all on real Screens."""

    def review_steps(self) -> list:
        """The review chain: overview, maths, one external address, three changes."""
        return [
            FlowStep(psbt_views.PSBTOverviewView, real_screens=True),
            FlowStep(psbt_views.PSBTMathView, real_screens=True),
            FlowStep(psbt_views.PSBTAddressDetailsView, real_screens=True),
            FlowStep(psbt_views.PSBTChangeDetailsView, real_screens=True),
            FlowStep(psbt_views.PSBTChangeDetailsView, real_screens=True),
            FlowStep(psbt_views.PSBTChangeDetailsView, real_screens=True),
        ]

    def review_script(self) -> list:
        return (
            select(0)  # PSBTOverviewView: continue
            + select(0)  # PSBTMathView: continue
            + select(0)  # PSBTAddressDetailsView: next
            + select(psbt_views.PSBTChangeDetailsView.NEXT)
            + select(psbt_views.PSBTChangeDetailsView.NEXT)
            + select(psbt_views.PSBTChangeDetailsView.NEXT)
        )

    def test_scan_psbt_then_scan_seed_and_sign(self):
        """The full first-time path: no seed loaded, so the flow scans one."""
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        signatures = []
        session = UISession(script=(
            select(psbt_views.PSBTSelectSeedView.SCAN_SEED)
            + select(seed_views.SeedFinalizeView.FINALIZE)
            + self.review_script()
            + select(psbt_views.PSBTFinalizeView.APPROVE_PSBT)
            + [K.KEY_PRESS]  # any click dismisses the signed-PSBT QR
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
                FlowStep(scan_views.ScanView, before_run=load_psbt),
                FlowStep(psbt_views.PSBTSelectSeedView, real_screens=True),
                FlowStep(scan_views.ScanSeedQRView, before_run=load_seedqr),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            ] + self.review_steps() + [
                FlowStep(psbt_views.PSBTFinalizeView, real_screens=True),
                FlowStep(
                    psbt_views.PSBTSignedQRDisplayView,
                    real_screens=True,
                    before_run=record_sig_count(signatures),
                ),
                FlowStep(MainMenuView),
            ],
            ui_session=session,
        )

        # The scanned seed really was loaded, and both inputs really were signed.
        assert len(self.controller.storage.seeds) == 1
        assert self.controller.storage.seeds[0].mnemonic_list == MNEMONIC_FOR_PSBT
        assert signatures == [2], f"expected both inputs signed, got {signatures}"
        assert session.renderer.frames, "the real PSBT Screens never rendered"

    def test_scan_psbt_with_seed_already_loaded(self):
        """The common repeat path: pick the loaded seed off the list."""
        from seedsigner.hardware.buttons import HardwareButtonsConstants as K

        seed = self.load_signing_seed()

        signatures = []
        session = UISession(script=(
            select(0)  # the one loaded seed, listed above the scan/type options
            + self.review_script()
            + select(psbt_views.PSBTFinalizeView.APPROVE_PSBT)
            + [K.KEY_PRESS]
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
                FlowStep(scan_views.ScanView, before_run=load_psbt),
                FlowStep(psbt_views.PSBTSelectSeedView, real_screens=True),
            ] + self.review_steps() + [
                FlowStep(psbt_views.PSBTFinalizeView, real_screens=True),
                FlowStep(
                    psbt_views.PSBTSignedQRDisplayView,
                    real_screens=True,
                    before_run=record_sig_count(signatures),
                ),
                FlowStep(MainMenuView),
            ],
            ui_session=session,
        )

        assert self.controller.storage.seeds == [seed]
        assert signatures == [2], f"expected both inputs signed, got {signatures}"

    def test_back_out_of_the_review_chain(self):
        """
        BACK must walk back up the review chain rather than stranding the user.

        The change-detail pages are re-entered with different view_args, so this also
        exercises the Controller's back-stack handling of repeated Views.
        """
        self.load_signing_seed()

        session = UISession(script=(
            select(0)      # select the loaded seed
            + select(0)    # overview: continue
            + select(0)    # maths: continue
            + [Back()]     # back out of the first address detail page
            + select(0)    # maths again: continue
            + select(0)    # address details again
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
                FlowStep(scan_views.ScanView, before_run=load_psbt),
                FlowStep(psbt_views.PSBTSelectSeedView, real_screens=True),
                FlowStep(psbt_views.PSBTOverviewView, real_screens=True),
                FlowStep(psbt_views.PSBTMathView, real_screens=True),
                FlowStep(psbt_views.PSBTAddressDetailsView, real_screens=True),
                FlowStep(psbt_views.PSBTMathView, real_screens=True),
                FlowStep(psbt_views.PSBTAddressDetailsView, real_screens=True),
                FlowStep(psbt_views.PSBTChangeDetailsView),
            ],
            ui_session=session,
        )


def force_parser(**attrs):
    """
    A `before_run` hook that shapes the parsed PSBT to select a review branch.

    PSBTOverviewView routes on three properties of the parse -- outstanding risk
    warnings, a policy it cannot represent, and change of zero -- and the corpus in
    tests/data/psbt_test_suite does not contain a vector that lands on any of them
    without being refused earlier. Whether a given transaction *produces* those
    properties is the parser's business and is covered by its own tests; what was
    untested is the three Views they select, which had never been constructed. Setting
    the attribute directly drives the real routing decision through the real View.

    Safe because PSBTOverviewView builds the parser in __init__, so `before_run` runs
    after it exists and before run() reads it.
    """
    def hook(view):
        for name, value in attrs.items():
            setattr(view.controller.psbt_parser, name, value)

    return hook



class TestPSBTReviewBranches(PSBTFlowTest):
    """
    The three branches out of the overview that are not the happy path.

    All were mocked-only before: the Views existed, were routed to, and had never been
    rendered. On a signing device the refusal paths deserve at least as much attention
    as the approval path.
    """

    def scan_to_overview(self, before_run=None) -> list:
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt),
            FlowStep(psbt_views.PSBTSelectSeedView, real_screens=True),
            FlowStep(psbt_views.PSBTOverviewView, real_screens=True, before_run=before_run),
        ]

    def test_outstanding_risk_warning_is_shown(self):
        """
        A risk the parser flagged must reach the user before any approval screen.

        HIGH_FEE rather than RBF: RBF is in RiskWarning.INFORMATIONAL, which the
        overview deliberately does not interrupt for -- it is shown on the approval
        screen instead.
        """
        from seedsigner.models.psbt_parser import RiskWarning

        self.load_signing_seed()
        session = UISession(script=select(0) + select(0) + select(0))

        self.run_sequence(
            self.scan_to_overview(force_parser(risk_warnings={RiskWarning.HIGH_FEE})) + [
                FlowStep(psbt_views.PSBTRiskWarningView, real_screens=True),
            ],
            ui_session=session,
        )
        assert session.renderer.frames

    def test_unsupported_script_type_warning(self):
        """
        A policy the parser cannot represent (legacy multisig, p2pkh) skips the maths
        screen entirely, so the user is told rather than shown a blank breakdown.
        """
        self.load_signing_seed()
        session = UISession(script=select(0) + select(0) + select(0))

        self.run_sequence(
            self.scan_to_overview(force_parser(policy=None)) + [
                FlowStep(psbt_views.PSBTUnsupportedScriptTypeWarningView, real_screens=True),
            ],
            ui_session=session,
        )

    def test_no_change_warning(self):
        """Sweeping a whole balance means no change output; the user is warned."""
        self.load_signing_seed()
        session = UISession(script=select(0) + select(0) + select(0))

        self.run_sequence(
            self.scan_to_overview(force_parser(change_amount=0)) + [
                FlowStep(psbt_views.PSBTNoChangeWarningView, real_screens=True),
            ],
            ui_session=session,
        )



class TestPSBTOpReturn(PSBTFlowTest):
    """A PSBT carrying an OP_RETURN payload shows it before approval."""

    # 2 inputs / 2 outputs, one of which is an OP_RETURN carrying readable text.
    OP_RETURN_PSBT = (
        "cHNidP8BAIYCAAAAATpQ10o+gKdZ8ThpKsbfHiHYn3NhvUrQ5DvW0ZWX8jKLAAAAAAD9////AujC"
        "9QUAAAAAFgAUY61+2BcXt+tsWoxV1nVw20kVb1UAAAAAAAAAACtqTChDaGFuY2VsbG9yIG9uIHRo"
        "ZSBicmluayBvZiB0aGlyZCBiYWlsb3V0aQAAAE8BBDWHzwNXmUmVgAAAANRFa7R5gYD84Wbha3d1"
        "QnjgfYPOBw87on6cXS32WoyqAsPFtPxB7PRTdbujUnBPUVDh9YUBtwrl4nc0OcRNGvIyEA+4gv9U"
        "AACAAQAAgAAAAIAAAQB0AgAAAAGNFK/1X0fP5q+nu5XX7Tk2VRa0EL+jkGI9CHiJvsjZCgAAAAAA"
        "/f///wKMw/UFAAAAABYAFIpZMNnUU6cQt8Q0YpZ0pnvsSA5fAAAAAAAAAAAZakwWYml0Y29pbiBp"
        "cyBmcmVlIHNwZWVjaGgAAAABAR+Mw/UFAAAAABYAFIpZMNnUU6cQt8Q0YpZ0pnvsSA5fAQMEAQAA"
        "ACIGAvxDI0eNI1oQ2AU69R7A0jf+hUdilWCgrWHgdzkqlaXMGA+4gv9UAACAAQAAgAAAAIAAAAAA"
        "AQAAAAAiAgK9qKtzGWyiRrpmupdA99NVLriz3GQy6cENbyD19sfl/hgPuIL/VAAAgAEAAIAAAACA"
        "AAAAAAIAAAAAAA=="
    )
    OP_RETURN_SEEDQR = "114006021552133507590698063102151531110102551496"

    def test_op_return_payload_is_shown_before_approval(self):
        def load_op_return(view):
            view.decoder.add_data(self.OP_RETURN_PSBT)

        def load_seed(view):
            view.decoder.add_data(self.OP_RETURN_SEEDQR)

        self.settings.set_value(
            SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET
        )

        session = UISession(script=(
            select(psbt_views.PSBTSelectSeedView.SCAN_SEED)
            + select(seed_views.SeedFinalizeView.FINALIZE)
            + select(0)          # overview
            + select(0)          # maths
            + select(psbt_views.PSBTChangeDetailsView.NEXT)
            + select(0)          # the OP_RETURN payload
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
                FlowStep(scan_views.ScanView, before_run=load_op_return),
                FlowStep(psbt_views.PSBTSelectSeedView, real_screens=True),
                FlowStep(scan_views.ScanSeedQRView, before_run=load_seed),
                FlowStep(seed_views.SeedFinalizeView, real_screens=True),
                FlowStep(seed_views.SeedOptionsView, is_redirect=True),
                FlowStep(psbt_views.PSBTOverviewView, real_screens=True),
                FlowStep(psbt_views.PSBTMathView, real_screens=True),
                FlowStep(psbt_views.PSBTChangeDetailsView, real_screens=True),
                FlowStep(psbt_views.PSBTOpReturnView, real_screens=True),
                FlowStep(psbt_views.PSBTFinalizeView),
            ],
            ui_session=session,
        )



class TestPSBTAlternativeSigners(PSBTFlowTest):
    """
    Signing with a bare key rather than a seed.

    `PSBTWIFEntryView` and `PSBTBIP38EntryView` were among the views never named in any
    test at all, despite being two of the ways a user can reach the signing flow.
    """

    def build_single_key_psbt(self, priv):
        """A one-input PSBT that `priv` alone can sign."""
        import base64

        from embit import psbt, script
        from embit.transaction import Transaction, TransactionInput, TransactionOutput

        spk = script.p2wpkh(priv.get_public_key())
        tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = TransactionOutput(1000, spk)
        return base64.b64encode(p.serialize()).decode()

    def test_typed_wif_key_reaches_the_overview(self):
        import os

        from embit import ec

        from seedsigner.gui.screens.seed_screens import SeedAddPassphraseScreen
        from ui_driver import plan_text_entry_script

        self.settings.set_value(
            SettingsConstants.SETTING__WIF_KEYS, SettingsConstants.OPTION__ENABLED
        )
        self.settings.set_value(
            SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET
        )

        priv = ec.PrivateKey(os.urandom(32))
        psbt_b64 = self.build_single_key_psbt(priv)

        def load(view):
            view.decoder.add_data(psbt_b64)

        wif_script = plan_text_entry_script(
            SeedAddPassphraseScreen, priv.wif(), passphrase="", title="WIF"
        )
        session = UISession(script=(
            select(psbt_views.PSBTSelectSeedView.TYPE_WIF) + wif_script
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
                FlowStep(scan_views.ScanView, before_run=load),
                FlowStep(psbt_views.PSBTSelectSeedView, real_screens=True),
                FlowStep(psbt_views.PSBTWIFEntryView, real_screens=True),
                FlowStep(psbt_views.PSBTOverviewView),
            ],
            ui_session=session,
        )

    def test_typed_bip38_key_asks_for_its_passphrase(self):
        """
        A BIP38 key is encrypted, so entry is two screens: the key, then the passphrase
        that unlocks it. Neither View had ever been constructed.
        """
        import base64

        from seedsigner.gui.screens.seed_screens import SeedAddPassphraseScreen
        from seedsigner.models.bip38 import BIP38Key
        from ui_driver import plan_text_entry_script

        self.settings.set_value(
            SettingsConstants.SETTING__BIP38_KEYS, SettingsConstants.OPTION__ENABLED
        )
        self.settings.set_value(
            SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET
        )

        encrypted = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"
        passphrase = "TestingOneTwoThree"
        priv = BIP38Key(encrypted).decrypt(passphrase).privkey
        psbt_b64 = self.build_single_key_psbt(priv)

        def load(view):
            view.decoder.add_data(psbt_b64)

        key_script = plan_text_entry_script(
            SeedAddPassphraseScreen, encrypted, passphrase="", title="BIP38"
        )
        pass_script = plan_text_entry_script(
            SeedAddPassphraseScreen, passphrase, passphrase="", title="Passphrase"
        )
        session = UISession(script=(
            select(psbt_views.PSBTSelectSeedView.TYPE_BIP38) + key_script + pass_script
        ))

        self.run_sequence(
            [
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
                FlowStep(scan_views.ScanView, before_run=load),
                FlowStep(psbt_views.PSBTSelectSeedView, real_screens=True),
                FlowStep(psbt_views.PSBTBIP38EntryView, real_screens=True),
                FlowStep(psbt_views.PSBTBIP38PassphraseView, real_screens=True),
                FlowStep(psbt_views.PSBTOverviewView),
            ],
            ui_session=session,
        )
