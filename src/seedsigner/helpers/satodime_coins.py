"""
    Deposit addresses and private-key formats for the coins a Satodime keyslot can hold.

    A Satodime slot records only a SLIP-44 coin code; the network (mainnet/testnet) is a
    display choice the wallet makes, exactly as the official apps do. This module mirrors
    ``Toporin/Javacryptotools`` -- the library Satodime-Android and Satodime-Desktop use --
    so a slot reads the same here as it does on the phone. Where the two could differ, the
    Java behaviour wins; the comments name the class each rule comes from.

    Supported set matches the official app exactly. ``Utils.kt`` maps SLIP-44 to a coin
    class and falls through to ``UnsupportedCoin`` for everything else, so BTC, LTC, BCH,
    ETH, POL and XCP are supported and the remaining codes in ``Constants.java`` (DOGE,
    DASH, ETC, RBTC, BSC) are not. We report those as unsupported rather than guessing an
    address format the official app would never show.

    Signing stays Bitcoin-only. These addresses and keys are for viewing and for exporting
    an unsealed key into another wallet.
"""

import logging
from dataclasses import dataclass, field
from typing import Callable

from embit import base58, ec, script
from embit.networks import NETWORKS

logger = logging.getLogger(__name__)


# SLIP-44 codes, hardened, as Javacryptotools' Constants.java writes them.
SLIP44_BTC = 0x80000000
SLIP44_LTC = 0x80000002
SLIP44_XCP = 0x80000009
SLIP44_ETH = 0x8000003C
SLIP44_BCH = 0x80000091
SLIP44_POL = 0x800003C6


# --------------------------------------------------------------------------- CashAddr
# BCH's address encoding. Same 32-character alphabet as bech32 but a different checksum
# generator and layout, so bech32 code cannot be reused. Ported from CashAddress.java.
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CASHADDR_GENERATOR = (
    0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470,
)


def _convert_bits(data, from_bits: int, to_bits: int, pad: bool = True):
    """Regroup a byte string into `to_bits`-wide values (BIP-173's convertbits)."""
    acc = 0
    bits = 0
    out = []
    maxv = (1 << to_bits) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            raise ValueError("invalid value for convert_bits")
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise ValueError("invalid padding in convert_bits")
    return out


def _cashaddr_polymod(values) -> int:
    chk = 1
    for value in values:
        top = chk >> 35
        chk = ((chk & 0x07FFFFFFFF) << 5) ^ value
        for i, generator in enumerate(_CASHADDR_GENERATOR):
            if (top >> i) & 1:
                chk ^= generator
    return chk ^ 1


def encode_cashaddr(prefix: str, payload: bytes) -> str:
    """Encode a CashAddr for `payload` (version byte + hash), including the prefix."""
    payload5 = _convert_bits(payload, 8, 5)
    # Checksum covers the prefix's low 5 bits, a separator zero, the payload and
    # eight zero placeholders.
    prefix5 = [ord(c) & 0x1F for c in prefix]
    checksum = _cashaddr_polymod(prefix5 + [0] + payload5 + [0] * 8)
    checksum5 = [(checksum >> (5 * (7 - i))) & 0x1F for i in range(8)]
    body = "".join(_CHARSET[d] for d in payload5 + checksum5)
    return f"{prefix}:{body}"


def _bch_address(pub: ec.PublicKey, params: dict) -> str:
    """BCH P2PKH as CashAddr (BitcoinCash.pubToAddress)."""
    from embit import hashes

    # version byte: address type (0 = P2PKH) << 3 | size bits (0 = 160-bit hash)
    payload = bytes([0x00]) + hashes.hash160(pub.sec())
    return encode_cashaddr(params["cashaddr_prefix"], payload)


# -------------------------------------------------------------------------------- EVM
def _keccak256(data: bytes) -> bytes:
    """Legacy Keccak-256, not NIST SHA3-256: the two use different padding.

    Javacryptotools uses BouncyCastle's ``Keccak.Digest256``; pycryptodomex's ``keccak``
    module is the matching primitive. ``hashlib.sha3_256`` is NOT interchangeable.
    """
    from Cryptodome.Hash import keccak

    return keccak.new(digest_bits=256).update(data).digest()


def _evm_address(pub: ec.PublicKey, params: dict) -> str:
    """An EVM address: last 20 bytes of keccak256 over the uncompressed pubkey's X||Y.

    Returned in EIP-55 mixed case (Ethereum.toChecksumAddress). That is the same address
    as the lowercase form ``pubToAddress`` returns -- capitalisation carries a typo check
    and nothing else -- and every wallet accepts either.
    """
    uncompressed = ec.PublicKey(pub._point, compressed=False)
    xy = uncompressed.sec()[1:]  # drop the 0x04 prefix
    address = _keccak256(xy)[-20:].hex()

    digest = _keccak256(address.encode()).hex()
    checksummed = "".join(
        c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(address)
    )
    return "0x" + checksummed


# ---------------------------------------------------------------------- Bitcoin-likes
def _bitcoin_like_network(params: dict) -> dict:
    """An embit network dict built from the coin's Javacryptotools parameters."""
    net = dict(NETWORKS["main"])
    net.update({
        "name": params["name"],
        "p2pkh": bytes([params["magicbyte"]]),
        "p2sh": bytes([params["script_magicbyte"]]),
        "bech32": params["segwit_hrp"],
        "wif": bytes([params["wif_prefix"]]),
    })
    return net


def _segwit_address(pub: ec.PublicKey, params: dict) -> str:
    """BaseCoin.pubToAddress returns segwit whenever the coin supports it."""
    return script.p2wpkh(pub).address(network=_bitcoin_like_network(params))


def _legacy_address(pub: ec.PublicKey, params: dict) -> str:
    """...and falls back to base58 P2PKH when it does not."""
    return script.p2pkh(pub).address(network=_bitcoin_like_network(params))


# ------------------------------------------------------------------------------ Specs
@dataclass(frozen=True)
class CoinSpec:
    slip44: int
    symbol: str
    display_name: str
    address_fn: Callable
    # WIF for the bitcoin-likes; EVM keys are shown as raw hex, which is what every
    # EVM wallet's "import private key" field expects.
    privkey_is_wif: bool
    mainnet: dict
    testnet: dict

    def params(self, is_testnet: bool) -> dict:
        return self.testnet if is_testnet else self.mainnet

    def address(self, pub: ec.PublicKey, is_testnet: bool = False) -> str:
        return self.address_fn(pub, self.params(is_testnet))

    def privkey(self, secret: bytes, is_testnet: bool = False) -> str:
        """The private key in the form this chain's wallets import."""
        if not self.privkey_is_wif:
            return "0x" + bytes(secret).hex()
        params = self.params(is_testnet)
        # BaseCoin.encodePrivkey: version || key || 0x01 (compressed), base58check.
        return base58.encode_check(bytes([params["wif_prefix"]]) + bytes(secret) + b"\x01")


def _btc_params(testnet: bool) -> dict:
    if testnet:
        return dict(name="Bitcoin Testnet", magicbyte=111, script_magicbyte=196,
                    segwit_hrp="tb", wif_prefix=0xEF)
    return dict(name="Bitcoin", magicbyte=0, script_magicbyte=5,
                segwit_hrp="bc", wif_prefix=0x80)


COINS: dict[int, CoinSpec] = {
    SLIP44_BTC: CoinSpec(
        slip44=SLIP44_BTC, symbol="BTC", display_name="Bitcoin",
        address_fn=_segwit_address, privkey_is_wif=True,
        mainnet=_btc_params(False), testnet=_btc_params(True),
    ),
    SLIP44_LTC: CoinSpec(
        slip44=SLIP44_LTC, symbol="LTC", display_name="Litecoin",
        address_fn=_segwit_address, privkey_is_wif=True,
        mainnet=dict(name="Litecoin", magicbyte=48, script_magicbyte=50,
                     segwit_hrp="ltc", wif_prefix=0xB0),
        testnet=dict(name="Litecoin Testnet", magicbyte=111, script_magicbyte=58,
                     segwit_hrp="tltc", wif_prefix=0xEF),
    ),
    # BitcoinCash.java sets segwit_supported = false and overrides pubToAddress with
    # CashAddr, so BCH is neither bech32 nor base58 on screen.
    SLIP44_BCH: CoinSpec(
        slip44=SLIP44_BCH, symbol="BCH", display_name="Bitcoin Cash",
        address_fn=_bch_address, privkey_is_wif=True,
        mainnet=dict(name="Bitcoin Cash", magicbyte=0, script_magicbyte=5,
                     segwit_hrp="bc", wif_prefix=0x80, cashaddr_prefix="bitcoincash"),
        testnet=dict(name="Bitcoin Cash Testnet", magicbyte=111, script_magicbyte=196,
                     segwit_hrp="tb", wif_prefix=0xEF, cashaddr_prefix="bchtest"),
    ),
    # Counterparty rides on Bitcoin and sets segwit_supported = false, so its deposit
    # address is a legacy base58 P2PKH one with Bitcoin's version bytes.
    SLIP44_XCP: CoinSpec(
        slip44=SLIP44_XCP, symbol="XCP", display_name="Counterparty",
        address_fn=_legacy_address, privkey_is_wif=True,
        mainnet=_btc_params(False), testnet=_btc_params(True),
    ),
    SLIP44_ETH: CoinSpec(
        slip44=SLIP44_ETH, symbol="ETH", display_name="Ethereum",
        address_fn=_evm_address, privkey_is_wif=False,
        mainnet=_btc_params(False), testnet=_btc_params(True),
    ),
    # Polygon extends Ethereum: same derivation, same address, different chain.
    SLIP44_POL: CoinSpec(
        slip44=SLIP44_POL, symbol="POL", display_name="Polygon",
        address_fn=_evm_address, privkey_is_wif=False,
        mainnet=_btc_params(False), testnet=_btc_params(True),
    ),
}


# Offered when sealing a slot, in the order the menu shows them.
SEALABLE_COINS = [COINS[s] for s in (SLIP44_BTC, SLIP44_LTC, SLIP44_BCH, SLIP44_ETH,
                                     SLIP44_POL, SLIP44_XCP)]


def coin_for_slip44(slip44: int) -> CoinSpec | None:
    """The coin a keyslot holds, or None when the official app would not show it either.

    A slot sealed before SeedSigner wrote this metadata reads back as 0; it can only be
    one this app sealed, and this app sealed Bitcoin.
    """
    if not slip44:
        return COINS[SLIP44_BTC]
    return COINS.get(slip44)


def slip44_bytes(slip44: int) -> list:
    """The 4-byte big-endian form the SET_KEYSLOT_STATUS APDU carries."""
    return list(int(slip44).to_bytes(4, "big"))
