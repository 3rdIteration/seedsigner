"""Mnemonic-text QR decoding and signmessage QR robustness.

Regression cover for the keycard-only refactor:

* ``SEED__MNEMONIC`` / ``SEED__FOUR_LETTER_MNEMONIC`` QRs must decode and
  validate via embit. (A legacy ``Seed`` shim with no constructor used to
  make every mnemonic-text QR return INVALID, silently breaking the
  Keycard import flow's "mnemonic QR" source.)
* ``SignMessageQrDecoder`` must reject malformed payloads — scanned input
  is untrusted per CLAUDE.md — instead of raising ``IndexError``.
* Wordlist-copy safety invariant from CLAUDE.md: wiping a decoded phrase
  must never corrupt the shared global BIP-39 wordlist.
"""

import pytest
from embit import bip39

from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus


MNEMONIC_12 = ("abandon " * 11 + "about").strip()
MNEMONIC_24 = ("abandon " * 23 + "art").strip()


def _decode(payload: bytes):
    d = DecodeQR()
    status = d.add_data(payload)
    return d, status


class TestMnemonicTextQr:
    def test_12_word_mnemonic_decodes(self):
        d, status = _decode(MNEMONIC_12.encode())
        assert status == DecodeQRStatus.COMPLETE
        assert d.is_seed
        assert d.get_seed_phrase() == MNEMONIC_12.split()

    def test_24_word_mnemonic_decodes(self):
        d, status = _decode(MNEMONIC_24.encode())
        assert status == DecodeQRStatus.COMPLETE
        assert d.get_seed_phrase() == MNEMONIC_24.split()

    def test_15_word_mnemonic_decodes(self):
        mnemonic = bip39.mnemonic_from_bytes(b"\x11" * 20)
        assert len(mnemonic.split()) == 15
        d, status = _decode(mnemonic.encode())
        assert status == DecodeQRStatus.COMPLETE
        assert d.get_seed_phrase() == mnemonic.split()

    def test_bad_checksum_is_invalid(self):
        d, status = _decode(("abandon " * 12).strip().encode())
        assert status == DecodeQRStatus.INVALID
        assert not d.is_complete

    def test_uppercase_and_whitespace_normalised(self):
        d, status = _decode(("  " + MNEMONIC_12.upper() + "  ").encode())
        assert status == DecodeQRStatus.COMPLETE
        assert d.get_seed_phrase() == MNEMONIC_12.split()


class TestFourLetterMnemonicQr:
    def test_four_letter_mnemonic_decodes_to_full_words(self):
        d, status = _decode(("aban " * 11 + "abou").strip().encode())
        assert status == DecodeQRStatus.COMPLETE
        assert d.get_seed_phrase() == MNEMONIC_12.split()

    def test_four_letter_bad_checksum_is_invalid(self):
        d, status = _decode(("aban " * 12).strip().encode())
        assert status == DecodeQRStatus.INVALID

    def test_decoded_words_are_independent_wordlist_copies(self):
        # CLAUDE.md rule: words looked up from bip39.WORDLIST must be
        # stored as fresh allocations ("".join), never direct references.
        d, status = _decode(("aban " * 11 + "abou").strip().encode())
        assert status == DecodeQRStatus.COMPLETE
        for w in d.get_seed_phrase():
            idx = bip39.WORDLIST.index(w)
            assert w is not bip39.WORDLIST[idx]


class TestStandardSeedQr:
    def test_numeric_seedqr_decodes(self):
        # 12 words as 4-digit wordlist indices: 11x "abandon" (0) + "about" (3).
        d, status = _decode(("0000" * 11 + "0003").encode())
        assert status == DecodeQRStatus.COMPLETE
        assert d.get_seed_phrase() == MNEMONIC_12.split()

    def test_wordlist_survives_wiping_a_decoded_phrase(self):
        from seedsigner.helpers.secure_delete import wipe_list

        d, status = _decode(("0000" * 11 + "0003").encode())
        assert status == DecodeQRStatus.COMPLETE
        phrase = d.get_seed_phrase()
        wipe_list(phrase)
        assert bip39.WORDLIST[0] == "abandon"
        assert bip39.WORDLIST[3] == "about"


class TestSignMessageQr:
    def test_valid_signmessage_decodes(self):
        d, status = _decode(b"signmessage m/84h/0h/0h/0/0 ascii:hello world")
        assert status == DecodeQRStatus.COMPLETE
        assert d.is_sign_message
        data = d.get_qr_data()
        assert data["derivation_path"] == "m/84'/0'/0'/0/0"
        assert data["message"] == "hello world"

    @pytest.mark.parametrize("payload", [
        b"signmessage",
        b"signmessage m/84h/0h/0h/0/0",
        b"signmessage m/84h/0h/0h/0/0 ascii",
        b"signmessage m/84h/0h/0h/0/0 ascii:",
    ])
    def test_malformed_signmessage_is_invalid_not_crash(self, payload):
        # Used to raise IndexError on fewer than 3 space-separated parts.
        d, status = _decode(payload)
        assert status == DecodeQRStatus.INVALID
        assert not d.is_complete

    def test_unsupported_format_is_invalid(self):
        d, status = _decode(b"signmessage m/84h/0h/0h/0/0 base64:aGVsbG8=")
        assert status == DecodeQRStatus.INVALID
