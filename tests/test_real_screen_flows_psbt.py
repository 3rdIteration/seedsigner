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
