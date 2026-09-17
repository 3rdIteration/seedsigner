"""
    Per-coin address and private-key formats for Satodime keyslots.

    A Satodime slot can be sealed for any of the coins the official apps support, and a
    deposit address in the wrong format is worse than no address: the key still controls
    the funds, but the owner's wallet for that chain never shows them. So every format
    here is pinned to a vector from outside this repo -- the EIP-55 spec, the CashAddr
    spec, or the parameters in Toporin/Javacryptotools, which is the library
    Satodime-Android and Satodime-Desktop actually use.

    Supported set is deliberately the app's: Utils.kt maps SLIP-44 to a coin class and
    falls through to UnsupportedCoin, so BTC/LTC/BCH/ETH/POL/XCP are in and the other
    codes listed in Constants.java are not.
"""

import pytest
from embit import base58, ec

from seedsigner.helpers import satodime_coins as sc


# The key sealed into slot 0 of a real Satodime by the official Android app, and the
# address that app displayed for it. Cross-checked on hardware.
CARD_PUBKEY = "03de296020fbf9a119db36a513a572ea4936a5729f5a3deb21a9b8c0928c9db8f0"
CARD_BTC_ADDRESS = "bc1qapd47as9kw384u5pkd4jvvj5pn8ds3s876k048"


def pub(hexstr=CARD_PUBKEY):
    return ec.PublicKey.parse(bytes.fromhex(hexstr))


class TestCashAddr:
    """BCH's own encoding: same alphabet as bech32, different checksum generator."""

    def test_matches_the_cashaddr_spec_vector(self):
        # The example pairing from the CashAddr specification.
        legacy = "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
        expected = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"

        hash160 = base58.decode_check(legacy)[1:]
        # version byte 0 = P2PKH with a 160-bit hash
        assert sc.encode_cashaddr("bitcoincash", bytes([0]) + hash160) == expected

    def test_prefix_is_part_of_the_checksum(self):
        """Changing the prefix must change the body, or testnet/mainnet would collide."""
        payload = bytes([0]) + bytes(range(20))
        main = sc.encode_cashaddr("bitcoincash", payload)
        test = sc.encode_cashaddr("bchtest", payload)
        assert main.split(":")[1] != test.split(":")[1]


class TestEvmAddresses:
    """keccak-256, not SHA3-256, and EIP-55 mixed case on the way out."""

    # The four vectors given in EIP-55 itself.
    EIP55_VECTORS = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ]

    @pytest.mark.parametrize("address", EIP55_VECTORS)
    def test_checksum_reproduces_the_eip55_vectors(self, address):
        lowered = address.lower().replace("0x", "")
        digest = sc._keccak256(lowered.encode()).hex()
        got = "0x" + "".join(
            c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(lowered)
        )
        assert got == address

    def test_keccak_is_not_sha3(self):
        """hashlib.sha3_256 pads differently; swapping them silently breaks every address."""
        import hashlib

        assert sc._keccak256(b"") != hashlib.sha3_256(b"").digest()
        assert sc._keccak256(b"").hex().startswith("c5d2460186f7")

    def test_known_private_key_maps_to_its_known_address(self):
        priv = ec.PrivateKey(bytes(31) + bytes([1]))
        address = sc.COINS[sc.SLIP44_ETH].address(priv.get_public_key())
        assert address.lower() == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"

    def test_polygon_shares_ethereums_derivation(self):
        """Polygon.java extends Ethereum: one address, two chains."""
        assert (
            sc.COINS[sc.SLIP44_POL].address(pub())
            == sc.COINS[sc.SLIP44_ETH].address(pub())
        )


class TestAddressFormatPerCoin:
    """Each coin's format, as Javacryptotools derives it."""

    def test_btc_is_bech32_and_matches_the_android_app(self):
        assert sc.COINS[sc.SLIP44_BTC].address(pub()) == CARD_BTC_ADDRESS

    def test_ltc_is_bech32_under_its_own_hrp(self):
        """Litecoin sets segwit_supported = true with segwit_hrp = 'ltc'."""
        address = sc.COINS[sc.SLIP44_LTC].address(pub())
        assert address.startswith("ltc1q")
        # Same witness program as BTC -- only the human-readable part differs.
        assert address[5:-6] == CARD_BTC_ADDRESS[4:-6]

    def test_bch_is_cashaddr_not_base58(self):
        """BitcoinCash overrides pubToAddress; it is neither bech32 nor legacy base58."""
        address = sc.COINS[sc.SLIP44_BCH].address(pub())
        assert address.startswith("bitcoincash:q")

    def test_xcp_is_legacy_base58(self):
        """Counterparty sets segwit_supported = false and rides Bitcoin's version bytes."""
        address = sc.COINS[sc.SLIP44_XCP].address(pub())
        assert address.startswith("1")
        assert base58.decode_check(address)[0] == 0x00

    def test_every_supported_coin_produces_a_distinct_address_family(self):
        prefixes = {c.symbol: c.address(pub())[:4] for c in sc.SEALABLE_COINS}
        # ETH and POL are the one intentional pair that collides.
        assert prefixes["ETH"] == prefixes["POL"]
        others = {k: v for k, v in prefixes.items() if k != "POL"}
        assert len(set(others.values())) == len(others), prefixes

    @pytest.mark.parametrize("coin", sc.SEALABLE_COINS, ids=lambda c: c.symbol)
    def test_testnet_differs_from_mainnet(self, coin):
        main = coin.address(pub(), is_testnet=False)
        test = coin.address(pub(), is_testnet=True)
        if coin.slip44 in (sc.SLIP44_ETH, sc.SLIP44_POL):
            # EVM addresses carry no network byte at all.
            assert main == test
        else:
            assert main != test


class TestPrivateKeyFormats:
    """The string a user pastes into the wallet for that chain."""

    SECRET = bytes(range(1, 33))

    def test_bitcoin_likes_are_compressed_wif(self):
        wif = sc.COINS[sc.SLIP44_BTC].privkey(self.SECRET)
        assert wif.startswith("K") or wif.startswith("L")
        decoded = base58.decode_check(wif)
        assert decoded[0] == 0x80
        assert decoded[1:33] == self.SECRET
        assert decoded[33] == 0x01, "compressed flag"

    def test_litecoin_uses_its_own_wif_version(self):
        decoded = base58.decode_check(sc.COINS[sc.SLIP44_LTC].privkey(self.SECRET))
        assert decoded[0] == 0xB0

    def test_testnet_wif_uses_the_testnet_version(self):
        decoded = base58.decode_check(
            sc.COINS[sc.SLIP44_BTC].privkey(self.SECRET, is_testnet=True))
        assert decoded[0] == 0xEF

    @pytest.mark.parametrize("slip44", [sc.SLIP44_ETH, sc.SLIP44_POL])
    def test_evm_keys_are_raw_hex(self, slip44):
        """An EVM wallet's import field takes hex; a WIF there is simply rejected."""
        key = sc.COINS[slip44].privkey(self.SECRET)
        assert key == "0x" + self.SECRET.hex()

    def test_the_wif_round_trips_through_embit(self):
        wif = sc.COINS[sc.SLIP44_BTC].privkey(self.SECRET)
        assert ec.PrivateKey.from_wif(wif).secret == self.SECRET


class TestCoinLookup:
    """What a keyslot's slip44 resolves to."""

    def test_known_coins_resolve(self):
        for slip44 in (sc.SLIP44_BTC, sc.SLIP44_LTC, sc.SLIP44_BCH,
                       sc.SLIP44_ETH, sc.SLIP44_POL, sc.SLIP44_XCP):
            assert sc.coin_for_slip44(slip44) is not None

    def test_an_untagged_slot_is_bitcoin(self):
        """Slots SeedSigner sealed before it wrote this metadata read back as 0."""
        assert sc.coin_for_slip44(0) is sc.COINS[sc.SLIP44_BTC]

    @pytest.mark.parametrize("slip44,name", [
        (0x80000003, "DOGE"), (0x80000005, "DASH"),
        (0x8000003D, "ETC"), (0x80000089, "RBTC"), (0x80000207, "BSC"),
    ])
    def test_coins_the_official_app_does_not_support_resolve_to_nothing(self, slip44, name):
        """
        Constants.java lists these, but Utils.kt has no branch for them so the app
        shows UnsupportedCoin. Guessing a format here would invite a deposit to an
        address the owner's wallet never derives.
        """
        assert sc.coin_for_slip44(slip44) is None, name

    def test_slip44_bytes_are_big_endian_and_four_wide(self):
        assert sc.slip44_bytes(sc.SLIP44_BTC) == [0x80, 0x00, 0x00, 0x00]
        assert sc.slip44_bytes(sc.SLIP44_ETH) == [0x80, 0x00, 0x00, 0x3C]
        assert sc.slip44_bytes(sc.SLIP44_POL) == [0x80, 0x00, 0x03, 0xC6]

    def test_sealable_set_matches_the_official_app(self):
        assert {c.symbol for c in sc.SEALABLE_COINS} == {
            "BTC", "LTC", "BCH", "ETH", "POL", "XCP"}

    def test_we_carry_our_own_symbols_because_pysatochip_is_incomplete(self):
        """
        Why this module holds the symbols instead of reading key_slip44_txt off the
        card: pysatochip's label table has no entry for Polygon, so a POL slot reads
        back as "Unknown code [128, 0, 3, 198]". Confirmed on hardware -- the card
        stores 0x800003C6 correctly, only the label lookup is missing.
        """
        from pysatochip.CardDataParser import DICT_SLIP44_BY_CODE

        assert sc.SLIP44_POL not in DICT_SLIP44_BY_CODE
        assert sc.COINS[sc.SLIP44_POL].symbol == "POL"
