import pytest
import random
import os

from embit import bip39
from seedsigner.helpers import mnemonic_generation


def test_dice_rolls():
    """ Given random dice rolls, the resulting mnemonic should be valid. """
    for length, rolls in mnemonic_generation.DICE_ROLLS_REQUIRED.items():
        dice_rolls = ''.join(str(random.randint(1, 6)) for _ in range(rolls))
        mnemonic = mnemonic_generation.generate_mnemonic_from_dice(dice_rolls)
        assert len(mnemonic) == length
        assert bip39.mnemonic_is_valid(" ".join(mnemonic))


def test_calculate_checksum_input_type():
    """
        Given a partial mnemonic, the calculated checksum should yield a
        valid complete mnemonic.

        calculate_checksum should accept the mnemonic as:
        * a list of strings
        * string: "A B C", "A, B, C", "A,B,C"
    """

    def _try_all_input_formats(partial_mnemonic: str):
        mnemonic = mnemonic_generation.calculate_checksum(partial_mnemonic.split(" "))
        assert bip39.mnemonic_is_valid(" ".join(mnemonic))

        mnemonic = mnemonic_generation.calculate_checksum(partial_mnemonic.replace(" ", ","))
        assert bip39.mnemonic_is_valid(" ".join(mnemonic))

        mnemonic = mnemonic_generation.calculate_checksum(partial_mnemonic.replace(" ", ", "))
        assert bip39.mnemonic_is_valid(" ".join(mnemonic))

        mnemonic = mnemonic_generation.calculate_checksum(partial_mnemonic)
        assert bip39.mnemonic_is_valid(" ".join(mnemonic))

    entropy_map = {
        12: "3350f6ac9eeb07d2c6209932808aa7f6",
        15: "000102030405060708090a0b0c0d0e0f10111213",
        18: "000102030405060708090a0b0c0d0e0f1011121314151617",
        21: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
        24: "5bf41629fce815c3570955e8f45422abd7e2234141bd4d7ec63b741043b98cad",
    }

    for entropy in entropy_map.values():
        full = mnemonic_generation.generate_mnemonic_from_bytes(bytes.fromhex(entropy))
        partial = " ".join(full[:-1])
        _try_all_input_formats(partial)


def test_calculate_checksum_invalid_mnemonics():
    """
        Should raise an Exception on a mnemonic that is invalid due to length or using invalid words.
    """
    with pytest.raises(Exception) as e:
        # Mnemonic is too short: 10 words instead of 11
        partial_mnemonic = "abandon " * 9 + "about"
        mnemonic_generation.calculate_checksum(partial_mnemonic)
    assert "12, 15, 18, 21, or 24-word" in str(e)

    with pytest.raises(Exception) as e:
        # Valid mnemonic but unsupported length (16 words)
        mnemonic = "abandon " * 15 + "about"
        mnemonic_generation.calculate_checksum(mnemonic)
    assert "12, 15, 18, 21, or 24-word" in str(e)

    with pytest.raises(Exception) as e:
        # Mnemonic is too short: 22 words instead of 23
        partial_mnemonic = "abandon " * 21 + "about"
        mnemonic_generation.calculate_checksum(partial_mnemonic)
    assert "12, 15, 18, 21, or 24-word" in str(e)

    with pytest.raises(ValueError) as e:
        # Invalid BIP-39 word
        partial_mnemonic = "foobar " * 11 + "about"
        mnemonic_generation.calculate_checksum(partial_mnemonic)
    assert "not in the dictionary" in str(e)


def test_calculate_checksum_with_default_final_word():
    """ 11-word and 23-word mnemonics use word `0000` as a temp final word to complete
        the mnemonic.
    """
    partial_mnemonic = "crawl focus rescue cable view pledge rather dinner cousin unfair day"
    mnemonic1 = mnemonic_generation.calculate_checksum(partial_mnemonic)

    partial_mnemonic += " abandon"
    mnemonic2 = mnemonic_generation.calculate_checksum(partial_mnemonic)
    assert mnemonic1 == mnemonic2

    partial_mnemonic = "bubble father debate ankle injury fence mesh evolve section wet coyote violin pyramid flower rent arrow round clutch myth safe base skin mobile"
    mnemonic1 = mnemonic_generation.calculate_checksum(partial_mnemonic)

    partial_mnemonic += " abandon"
    mnemonic2 = mnemonic_generation.calculate_checksum(partial_mnemonic)
    assert mnemonic1 == mnemonic2


def test_calculate_checksum_uses_configured_wordlist(monkeypatch):
    from seedsigner.models.settings_definition import SettingsConstants

    called = {}

    def fake_get_wordlist(code):
        called.setdefault("get_wordlist", []).append(code)
        return ["abandon"] * 2048

    def fake_mnemonic_to_bytes(_mnemonic, ignore_checksum, wordlist):
        assert ignore_checksum is True
        called["to_bytes_wordlist"] = wordlist
        return b"\x00" * 16

    def fake_mnemonic_from_bytes(entropy, wordlist):
        called["from_bytes_entropy_len"] = len(entropy)
        called["from_bytes_wordlist"] = wordlist
        return "abandon " * 11 + "about"

    monkeypatch.setattr(mnemonic_generation, "_get_wordlist", fake_get_wordlist)
    monkeypatch.setattr(mnemonic_generation.bip39, "mnemonic_to_bytes", fake_mnemonic_to_bytes)
    monkeypatch.setattr(mnemonic_generation.bip39, "mnemonic_from_bytes", fake_mnemonic_from_bytes)

    mnemonic_generation.calculate_checksum(
        "abandon " * 11 + "abandon",
        wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
    )

    assert called["get_wordlist"] == [SettingsConstants.WORDLIST_LANGUAGE__ENGLISH, SettingsConstants.WORDLIST_LANGUAGE__ENGLISH]
    assert called["from_bytes_entropy_len"] == 16

def test_generate_mnemonic_from_bytes():
    """
        Should generate a valid BIP-39 mnemonic from entropy bytes
    """
    # From iancoleman.io
    entropy = "3350f6ac9eeb07d2c6209932808aa7f6"
    expected_mnemonic = "crew marble private differ race truly blush basket crater affair prepare unique".split()
    mnemonic = mnemonic_generation.generate_mnemonic_from_bytes(bytes.fromhex(entropy))
    assert mnemonic == expected_mnemonic

    entropy = "5bf41629fce815c3570955e8f45422abd7e2234141bd4d7ec63b741043b98cad"
    expected_mnemonic = "fossil pass media what life ticket found click trophy pencil anger fish lawsuit balance agree dash estate wage mom trial aerobic system crawl review".split()
    mnemonic = mnemonic_generation.generate_mnemonic_from_bytes(bytes.fromhex(entropy))
    assert mnemonic == expected_mnemonic

    # Additional supported lengths
    entropy = "000102030405060708090a0b0c0d0e0f10111213"  # 20 bytes -> 15 words
    mnemonic = mnemonic_generation.generate_mnemonic_from_bytes(bytes.fromhex(entropy))
    assert len(mnemonic) == 15
    assert bip39.mnemonic_is_valid(" ".join(mnemonic))

    entropy = "000102030405060708090a0b0c0d0e0f1011121314151617"  # 24 bytes -> 18 words
    mnemonic = mnemonic_generation.generate_mnemonic_from_bytes(bytes.fromhex(entropy))
    assert len(mnemonic) == 18
    assert bip39.mnemonic_is_valid(" ".join(mnemonic))

    entropy = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b"  # 28 bytes -> 21 words
    mnemonic = mnemonic_generation.generate_mnemonic_from_bytes(bytes.fromhex(entropy))
    assert len(mnemonic) == 21
    assert bip39.mnemonic_is_valid(" ".join(mnemonic))


def test_verify_against_coldcard_sample():
    """ https://coldcard.com/docs/verifying-dice-roll-math """
    dice_rolls = "123456"
    expected = "mirror reject rookie talk pudding throw happy era myth already payment own sentence push head sting video explain letter bomb casual hotel rather garment"

    mnemonic = mnemonic_generation.generate_mnemonic_from_dice(dice_rolls)
    actual = " ".join(mnemonic)
    assert bip39.mnemonic_is_valid(actual)
    assert actual == expected


def test_entropy_checks():
    assert mnemonic_generation.dice_entropy_is_sufficient("123456" * 10)
    assert not mnemonic_generation.dice_entropy_is_sufficient("1" * 50)

    assert mnemonic_generation.byte_entropy_is_sufficient(os.urandom(16))
    assert not mnemonic_generation.byte_entropy_is_sufficient(b"\x00" * 16)


def test_known_dice_rolls():
    """ Given 99 known dice rolls, the resulting mnemonic should be valid and match the expected. """
    dice_rolls = "522222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555"
    expected = "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin sister pony end debate task silk empty curious"

    mnemonic = mnemonic_generation.generate_mnemonic_from_dice(dice_rolls)
    actual = " ".join(mnemonic)
    assert bip39.mnemonic_is_valid(actual)
    assert actual == expected

    dice_rolls = "222222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555"
    expected = "garden uphold level clog sword globe armor issue two cute scorpion improve verb artwork blind tail raw butter combine move produce foil feature wave"

    mnemonic = mnemonic_generation.generate_mnemonic_from_dice(dice_rolls)
    actual = " ".join(mnemonic)
    assert bip39.mnemonic_is_valid(actual)
    assert actual == expected

    dice_rolls = "222222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555556"
    expected = "lizard broken love tired depend eyebrow excess lonely advance father various cram ignore panic feed plunge miss regret boring unique galaxy fan detail fly"

    mnemonic = mnemonic_generation.generate_mnemonic_from_dice(dice_rolls)
    actual = " ".join(mnemonic)
    assert bip39.mnemonic_is_valid(actual)
    assert actual == expected


def test_50_dice_rolls():
    """ 50 dice roll input should yield the same 12-word mnemonic as iancoleman.io/bip39 """
    # Check "Show entropy details", paste in dice_rolls sequence, click "Hex", select "Mnemonic Length" as "12 Words"
    dice_rolls = "12345612345612345612345612345612345612345612345612"
    expected = "unveil nice picture region tragic fault cream strike tourist control recipe tourist"
    mnemonic = mnemonic_generation.generate_mnemonic_from_dice(dice_rolls)
    actual = " ".join(mnemonic)
    assert bip39.mnemonic_is_valid(actual)
    assert actual == expected

    dice_rolls = "11111111111111111111111111111111111111111111111111"
    expected = "diet glad hat rural panther lawsuit act drop gallery urge where fit"
    mnemonic = mnemonic_generation.generate_mnemonic_from_dice(dice_rolls)
    actual = " ".join(mnemonic)
    assert bip39.mnemonic_is_valid(actual)
    assert actual == expected

    dice_rolls = "66666666666666666666666666666666666666666666666666"
    expected = "senior morning song proud recycle toy search apple trigger lend vibrant arrest"
    mnemonic = mnemonic_generation.generate_mnemonic_from_dice(dice_rolls)
    actual = " ".join(mnemonic)
    assert bip39.mnemonic_is_valid(actual)
    assert actual == expected


def test_calculate_checksum_does_not_corrupt_wordlist():
    """Regression test: calculate_checksum must not inject a direct reference
    to bip39.WORDLIST[0] into the caller's mnemonic list."""
    from seedsigner.helpers.secure_delete import wipe_list

    original_first_word = bip39.WORDLIST[0]
    assert original_first_word == "abandon"

    # 11-word partial mnemonic; calculate_checksum appends wordlist[0]
    # ("abandon") as a temp final word before computing the real checksum.
    partial = "crawl focus rescue cable view differ race truly blush basket crater".split()
    result = mnemonic_generation.calculate_checksum(partial)
    assert bip39.mnemonic_is_valid(" ".join(result))

    # The input list was modified in-place (11 words -> 12); wipe it
    assert len(partial) == 12
    wipe_list(partial)

    # The global wordlist must still be intact
    assert bip39.WORDLIST[0] == "abandon"
    assert repr(bip39.WORDLIST[0]) == "'abandon'"


def _assert_wordlist_intact():
    """Helper: verify a sampling of bip39.WORDLIST entries are uncorrupted."""
    assert bip39.WORDLIST[0] == "abandon"
    assert bip39.WORDLIST[3] == "about"
    assert bip39.WORDLIST[2047] == "zoo"
    # repr check catches zeroed-out buffers that still have len > 0
    assert repr(bip39.WORDLIST[0]) == "'abandon'"


def test_generate_mnemonic_from_bytes_does_not_corrupt_wordlist():
    """Wiping a mnemonic returned by generate_mnemonic_from_bytes must not
    corrupt bip39.WORDLIST."""
    from seedsigner.helpers.secure_delete import wipe_list

    _assert_wordlist_intact()
    mnemonic = mnemonic_generation.generate_mnemonic_from_bytes(b"\x00" * 16)
    assert bip39.mnemonic_is_valid(" ".join(mnemonic))
    wipe_list(mnemonic)
    _assert_wordlist_intact()


def test_generate_mnemonic_from_dice_does_not_corrupt_wordlist():
    """Wiping a mnemonic returned by generate_mnemonic_from_dice must not
    corrupt bip39.WORDLIST."""
    from seedsigner.helpers.secure_delete import wipe_list

    _assert_wordlist_intact()
    dice_rolls = "1" * mnemonic_generation.DICE_ROLLS_REQUIRED[24]
    mnemonic = mnemonic_generation.generate_mnemonic_from_dice(dice_rolls)
    assert bip39.mnemonic_is_valid(" ".join(mnemonic))
    wipe_list(mnemonic)
    _assert_wordlist_intact()


def test_generate_mnemonic_from_coin_flips_does_not_corrupt_wordlist():
    """Wiping a mnemonic returned by generate_mnemonic_from_coin_flips must not
    corrupt bip39.WORDLIST."""
    from seedsigner.helpers.secure_delete import wipe_list

    _assert_wordlist_intact()
    coin_flips = "0" * 128
    mnemonic = mnemonic_generation.generate_mnemonic_from_coin_flips(coin_flips)
    assert bip39.mnemonic_is_valid(" ".join(mnemonic))
    wipe_list(mnemonic)
    _assert_wordlist_intact()


def test_get_partial_final_word_does_not_corrupt_wordlist():
    """Wiping the result of get_partial_final_word must not corrupt
    bip39.WORDLIST."""
    from seedsigner.helpers.secure_delete import wipe_string

    _assert_wordlist_intact()
    word = mnemonic_generation.get_partial_final_word("0000000")
    wipe_string(word)
    _assert_wordlist_intact()
