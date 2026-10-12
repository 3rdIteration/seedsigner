"""
Independent re-verification of embit's results with libwally-core (`wallycore`).

Every safety decision SeedSigner makes -- the seed's fingerprint and xpubs, the
addresses it shows, which psbt outputs are change, what the signature commits
to -- is computed by embit. A bug in embit, or a difference between the
prebuilt secp256k1 on the device and the one tests ran against, would make the
screens describe one thing while the signer authorises another, and nothing
else in the stack would notice.

This package recomputes those results with a second, independently written
implementation and refuses on any disagreement. To keep the two genuinely
independent, nothing in this package imports embit: callers pull plain values
(bytes, ints, strings) out of their embit objects and hand them over, and every
comparison is against what wally derives on its own.

On a SeedSigner device the check is mandatory; a missing `wallycore` is itself a
refusal. On the desktop dev profile a missing `wallycore` only logs a warning,
so the emulator keeps working without it. When it is installed it always runs.
"""
import logging
import os

logger = logging.getLogger(__name__)


try:
    import wallycore as _wally
except ImportError:  # pragma: no cover - exercised by patching in tests
    _wally = None



class CrossCheckError(Exception):
    """
    embit and libwally disagree, or libwally is required but missing.

    `code` names the kind of disagreement (see `CrossCheckCode`); `detail` names
    the specific field, for the log and the error screen.
    """
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail



class CrossCheckCode:
    UNAVAILABLE = "CROSSCHECK_UNAVAILABLE"
    SEED = "CROSSCHECK_SEED"
    PARSE = "CROSSCHECK_PARSE"
    MISMATCH = "CROSSCHECK_MISMATCH"
    CHANGE = "CROSSCHECK_CHANGE"
    SWAPPED = "CROSSCHECK_SWAPPED"
    SIGNATURE = "CROSSCHECK_SIGNATURE"
    DESCRIPTOR = "CROSSCHECK_DESCRIPTOR"
    ADDRESS = "CROSSCHECK_ADDRESS"



# Overrides the runtime-profile decision; "1" forces the check to be mandatory,
# "0" lets a desktop build run without wallycore. Tests use it to exercise both.
REQUIRE_ENV_VAR = "SEEDSIGNER_REQUIRE_WALLY"


def crosscheck_required() -> bool:
    override = os.environ.get(REQUIRE_ENV_VAR)
    if override is not None:
        return override == "1"

    # Settings is imported lazily: it probes hardware at import time.
    from seedsigner.models.settings import Settings
    return getattr(Settings, "RUNTIME_PROFILE", "desktop") != "desktop"


def wally_available() -> bool:
    return _wally is not None


def get_wally():
    """
    The wallycore module, or None when the check may be skipped.

    Raises CrossCheckError when the check is mandatory but wallycore is missing.
    """
    if _wally is not None:
        return _wally

    if crosscheck_required():
        raise CrossCheckError(
            CrossCheckCode.UNAVAILABLE,
            "libwally is required on this device but could not be loaded",
        )

    logger.warning("wallycore not installed; skipping libwally cross-check")
    return None



# SettingsConstants network values ("M"/"T"/"R"). Spelled out here rather than
# imported so this package stays free of settings/embit imports.
NETWORK_MAINNET = "M"
NETWORK_TESTNET = "T"
NETWORK_REGTEST = "R"


def wally_network(network: str) -> int:
    w = _wally
    return {
        NETWORK_MAINNET: w.WALLY_NETWORK_BITCOIN_MAINNET,
        NETWORK_TESTNET: w.WALLY_NETWORK_BITCOIN_TESTNET,
        NETWORK_REGTEST: w.WALLY_NETWORK_BITCOIN_REGTEST,
    }[network]


def bech32_hrp(network: str) -> str:
    return {NETWORK_MAINNET: "bc", NETWORK_TESTNET: "tb", NETWORK_REGTEST: "bcrt"}[network]


def bip32_versions(network: str) -> tuple[int, int]:
    """(private, public) BIP32 version ints for the network's plain xprv/xpub."""
    w = _wally
    if network == NETWORK_MAINNET:
        return w.BIP32_VER_MAIN_PRIVATE, w.BIP32_VER_MAIN_PUBLIC
    return w.BIP32_VER_TEST_PRIVATE, w.BIP32_VER_TEST_PUBLIC
