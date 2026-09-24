from embit import bip39

from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.encode_qr import CompactSeedQrEncoder, SeedQrEncoder
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


ENTROPY = b"\x00" * 16
MNEMONIC_WORDS = bip39.mnemonic_from_bytes(ENTROPY).split()
CANONICAL_PASSPHRASE = " ".join(MNEMONIC_WORDS)


def test_plaintext_passphrase_qr_remains_unchanged():
    """Ordinary UTF-8 TextQR passphrases must retain their exact contents."""
    passphrase = "Correct horse  battery staple!"

    decoder = DecodeQR(is_passphrase=True)
    status = decoder.add_data(passphrase.encode("utf-8"))

    assert status == DecodeQRStatus.COMPLETE
    assert decoder.get_passphrase() == passphrase


def test_standard_seedqr_decodes_as_canonical_passphrase():
    """Standard SeedQR should become lowercase words separated by one space."""
    payload = SeedQrEncoder(mnemonic=MNEMONIC_WORDS).next_part()

    decoder = DecodeQR(is_passphrase=True)
    status = decoder.add_data(payload)

    assert status == DecodeQRStatus.COMPLETE
    passphrase = decoder.get_passphrase()
    assert passphrase == CANONICAL_PASSPHRASE
    assert passphrase.split() == MNEMONIC_WORDS


def test_compact_seedqr_decodes_as_canonical_passphrase():
    """CompactSeedQR should become lowercase words separated by one space."""
    Settings.get_instance().set_value(
        SettingsConstants.SETTING__AMBIGUOUS_QR,
        SettingsConstants.AMBIGUOUS_QR_COMPACT,
        save=False,
    )
    payload = CompactSeedQrEncoder(mnemonic=MNEMONIC_WORDS).next_part()

    decoder = DecodeQR(is_passphrase=True)
    status = decoder.add_data(payload)

    assert status == DecodeQRStatus.COMPLETE
    passphrase = decoder.get_passphrase()
    assert passphrase == CANONICAL_PASSPHRASE
    assert passphrase.split() == MNEMONIC_WORDS


def test_standard_and_compact_seedqr_produce_identical_passphrases():
    """Both SeedQR encodings must reconstruct the exact same passphrase."""
    Settings.get_instance().set_value(
        SettingsConstants.SETTING__AMBIGUOUS_QR,
        SettingsConstants.AMBIGUOUS_QR_COMPACT,
        save=False,
    )

    standard_payload = SeedQrEncoder(mnemonic=MNEMONIC_WORDS).next_part()
    compact_payload = CompactSeedQrEncoder(mnemonic=MNEMONIC_WORDS).next_part()

    standard_decoder = DecodeQR(is_passphrase=True)
    compact_decoder = DecodeQR(is_passphrase=True)

    assert standard_decoder.add_data(standard_payload) == DecodeQRStatus.COMPLETE
    assert compact_decoder.add_data(compact_payload) == DecodeQRStatus.COMPLETE

    standard_passphrase = standard_decoder.get_passphrase()
    compact_passphrase = compact_decoder.get_passphrase()

    assert standard_passphrase == CANONICAL_PASSPHRASE
    assert compact_passphrase == CANONICAL_PASSPHRASE
    assert standard_passphrase.split() == MNEMONIC_WORDS
    assert compact_passphrase.split() == MNEMONIC_WORDS
    assert standard_passphrase == compact_passphrase


def test_invalid_binary_payload_is_not_accepted_as_passphrase():
    """Unrecognized binary data must remain invalid."""
    decoder = DecodeQR(is_passphrase=True)
    status = decoder.add_data(b"\xff\xfe\xfd\xfc")

    assert status == DecodeQRStatus.INVALID
    assert decoder.is_complete is False


def test_malformed_standard_seedqr_is_rejected_as_invalid():
    """SeedQR-shaped data with an invalid word index must not become a passphrase."""
    payload = b"000000000000000000000000000000000000000000009999"

    decoder = DecodeQR(is_passphrase=True)
    status = decoder.add_data(payload)

    assert status == DecodeQRStatus.INVALID
    assert decoder.is_invalid is True
    assert decoder.is_complete is False
    assert decoder.get_passphrase() is None
