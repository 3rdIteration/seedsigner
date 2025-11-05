import binascii
import os

from types import SimpleNamespace
from urtypes.crypto import PSBT as UR_PSBT

from seedsigner.helpers import kef
from seedsigner.helpers.datum import (
    DATUM_ADDRESS,
    DATUM_DESCRIPTOR,
    DATUM_PSBT,
    DATUM_XPUB,
    analyze_contents,
    convert_encoding,
    detect_encodings,
    identify_datum,
    unwrap_kef_envelope,
    urobj_to_data,
)


def test_detect_encodings_hex():
    encodings = detect_encodings("deadbeef")
    assert "hex" in encodings
    assert "utf8" in encodings


def test_detect_encodings_base32():
    data = "MFRGGZDFMZTWQ2LK"
    encodings = detect_encodings(data)
    assert 32 in encodings


def test_convert_encoding_hex_roundtrip():
    original = b"hello world"
    encoded = convert_encoding(original, "hex")
    assert encoded == binascii.hexlify(original).decode()
    decoded = convert_encoding(encoded, "hex")
    assert decoded == original


def test_convert_encoding_utf8_roundtrip():
    text = "SeedSigner"
    data = convert_encoding(text, "utf8")
    assert isinstance(data, bytes)
    assert convert_encoding(data, "utf8") == text


def test_identify_datum_types():
    assert identify_datum(b"psbt\xff\x01") == DATUM_PSBT

    xpub = (
        "xpub661MyMwAqRbcF75hXVh8AyTzw9uQWGWpZ6YG1ChcxrFAuoRE2R3pNu3yqYgnSUZXoqBYwygJyBEt"
        "QtdgQXVc3k5ufADG7n2AFDzy83H8dH7"
    )
    assert identify_datum(xpub, [58]) == DATUM_XPUB

    descriptor = (
        "wpkh([d34db33f/84h/0h/0h]xpub661MyMwAqRbcF75hXVh8AyTzw9uQWGWpZ6YG1ChcxrFAuoRE2R3p"
        "Nu3yqYgnSUZXoqBYwygJyBEtQtdgQXVc3k5ufADG7n2AFDzy83H8dH7/0/*)"
    )
    assert identify_datum(descriptor, [58]) == DATUM_DESCRIPTOR

    address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    encodings = detect_encodings(address)
    assert identify_datum(address, encodings) == DATUM_ADDRESS


def test_analyze_contents_sensitivity():
    mnemonic = " ".join(["zoo"] * 12)
    analysis = analyze_contents(mnemonic)
    assert analysis.sensitive

    entropy = bytes([200] * 16)
    analysis_bytes = analyze_contents(entropy)
    assert analysis_bytes.sensitive


def test_urobj_to_data_psbt():
    sample = b"psbt\xff\x01\x02"
    ur_obj = SimpleNamespace(type="crypto-psbt", cbor=UR_PSBT(sample).to_cbor())
    extracted = urobj_to_data(ur_obj)
    assert extracted == sample


def test_unwrap_kef_envelope_roundtrip():
    payload = b"hello datum"
    label = b"label"
    iterations = 10000
    mode_name = "AES-CBC"

    version = kef.suggest_versions(payload, mode_name)[0]
    cipher = kef.Cipher("secret", label, iterations)
    iv_len = kef.MODE_IVS.get(kef.MODE_NUMBERS[mode_name], 0)
    iv = os.urandom(iv_len) if iv_len else b""
    ciphertext = cipher.encrypt(payload, version, iv=iv)
    envelope = kef.wrap(label, version, iterations, ciphertext)

    metadata, ciphertext_out = unwrap_kef_envelope(envelope)
    assert metadata.label == label
    assert metadata.iterations == iterations
    assert metadata.version == version

    cipher2 = kef.Cipher("secret", metadata.label, metadata.iterations)
    assert cipher2.decrypt(ciphertext_out, metadata.version) == payload
