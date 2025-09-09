import hashlib
import unicodedata
from collections import Counter
import math

from embit import bip39
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.models.seed import Seed

"""
    This is SeedSigner's internal mnemonic generation utility.
     
    It can also be run as an independently-executable CLI to facilitate external
    verification of SeedSigner's results for a given input entropy.

    see: docs/dice_verification.md (the "Command Line Tool" section).
"""

# Supported mnemonic word lengths
SUPPORTED_WORD_LENGTHS = [12, 15, 18, 21, 24]

# Dice roll counts required to generate sufficient entropy for each
# supported mnemonic length. Each dice roll provides ~2.585 bits of
# entropy which we round up to the next whole roll.
DICE_ROLLS_REQUIRED = {
    12: 50,
    15: 62,
    18: 75,
    21: 87,
    24: 99,
}

# Number of entropy bytes needed for each mnemonic length
ENTROPY_BYTES_REQUIRED = {
    12: 16,
    15: 20,
    18: 24,
    21: 28,
    24: 32,
    20: 16,  # SLIP39 compatibility
    33: 32,  # SLIP39 compatibility
}

# Reverse lookup from dice roll count to mnemonic length
ROLL_COUNT_TO_LENGTH = {v: k for k, v in DICE_ROLLS_REQUIRED.items()}

# Backwards-compatible constants
DICE__NUM_ROLLS__12WORD = DICE_ROLLS_REQUIRED[12]
DICE__NUM_ROLLS__24WORD = DICE_ROLLS_REQUIRED[24]



def calculate_checksum(mnemonic: list | str, wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> list[str]:
    """
        Provide 12- or 24-word mnemonic, returns complete mnemonic w/checksum as a list.

        Mnemonic may be a list of words or a string of words separated by spaces or commas.

        If 11- or 23-words are provided, append word `0000` to end of list as temp final
        word.
    """
    if type(mnemonic) == str:
        import re
        # split on commas or spaces
        mnemonic = re.findall(r'[^,\s]+', mnemonic)

    if len(mnemonic) in [11, 14, 17, 20, 23]:
        temp_final_word = Seed.get_wordlist(wordlist_language_code)[0]
        mnemonic.append(temp_final_word)

    if len(mnemonic) not in SUPPORTED_WORD_LENGTHS:
        raise Exception("Pass in a 12, 15, 18, 21, or 24-word mnemonic")
    
    # Work on a copy of the input list
    mnemonic_copy = mnemonic.copy()

    # Convert the resulting mnemonic to bytes, but we `ignore_checksum` validation
    # because we assume it's incorrect since we either let the user select their own
    # final word OR we injected the 0000 word from the wordlist.
    mnemonic_bytes = bip39.mnemonic_to_bytes(unicodedata.normalize("NFKD", " ".join(mnemonic_copy)), ignore_checksum=True, wordlist=Seed.get_wordlist(wordlist_language_code))

    # This function will convert the bytes back into a mnemonic, but it will also
    # calculate the proper checksum bits while doing so. For a 12-word seed it will just
    # overwrite the last 4 bits from the above result with the checksum; for a 24-word
    # seed it'll overwrite the last 8 bits.
    return bip39.mnemonic_from_bytes(mnemonic_bytes).split()



def generate_mnemonic_from_bytes(entropy_bytes, wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> list[str]:
    return bip39.mnemonic_from_bytes(entropy_bytes, wordlist=Seed.get_wordlist(wordlist_language_code)).split()



def generate_mnemonic_from_dice(roll_data: str, wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> list[str]:
    """
        Takes a string of dice rolls and returns a mnemonic of the appropriate length.

        Uses the iancoleman.io/bip39 and bitcoiner.guide/seed "Base 10" or "Hex" mode approach:
        * dice rolls are treated as string data.
        * hashed via SHA256.

        Important note: This method is NOT compatible with iancoleman's "Dice" mode.
    """
    entropy_bytes = hashlib.sha256(roll_data.encode()).digest()

    word_length = ROLL_COUNT_TO_LENGTH.get(len(roll_data), 24)

    entropy_bytes = entropy_bytes[:ENTROPY_BYTES_REQUIRED[word_length]]

    # Return as a list
    return bip39.mnemonic_from_bytes(entropy_bytes, wordlist=Seed.get_wordlist(wordlist_language_code)).split()


def generate_bytes_from_dice(roll_data: str) -> bytes:
    """Return entropy bytes from dice rolls without converting to mnemonic."""
    entropy_bytes = hashlib.sha256(roll_data.encode()).digest()
    word_length = ROLL_COUNT_TO_LENGTH.get(len(roll_data), 24)
    entropy_bytes = entropy_bytes[:ENTROPY_BYTES_REQUIRED[word_length]]
    return entropy_bytes



def generate_mnemonic_from_coin_flips(coin_flips: str, wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> list[str]:
    """
        Takes a string of binary digits and returns a mnemonic of the appropriate length.

        Uses the iancoleman.io/bip39 and bitcoiner.guide/seed "Binary" mode approach:
        * binary digit stream is treated as string data.
        * hashed via SHA256.
    """
    entropy_bytes = hashlib.sha256(coin_flips.encode()).digest()

    length_map = {
        128: 12,
        160: 15,
        192: 18,
        224: 21,
        256: 24,
    }
    word_length = length_map.get(len(coin_flips))
    if word_length is None:
        raise Exception("Unsupported number of coin flips")

    entropy_bytes = entropy_bytes[:ENTROPY_BYTES_REQUIRED[word_length]]

    # Return as a list
    return bip39.mnemonic_from_bytes(entropy_bytes, wordlist=Seed.get_wordlist(wordlist_language_code)).split()



def get_partial_final_word(coin_flips: str, wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> str:
    """ Look up the partial final word for the given coin flips.
        7 coin flips: 0101010 + **** where the final 4 bits will be replaced with the checksum
        3 coin flips: 010 + ******** where the final 8 bits will be replaced with the checksum
    """
    binary_string = coin_flips + "0" * (11 - len(coin_flips))
    wordlist_index = int(binary_string, 2)

    return Seed.get_wordlist(wordlist_language_code)[wordlist_index]



# Note: This currently isn't being used since we're now chaining hashed bytes for the
#   image-based entropy and aren't just ingesting a single image.
def generate_mnemonic_from_image(image, wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> list[str]:
    import hashlib
    hash = hashlib.sha256(image.tobytes())

    # Return as a list
    return bip39.mnemonic_from_bytes(hash.digest(), wordlist=Seed.get_wordlist(wordlist_language_code)).split()


def _shannon_entropy(data: bytes | str) -> float:
    """Return the Shannon entropy of the provided data."""
    if isinstance(data, str):
        data = data.encode()
    counts = Counter(data)
    length = len(data)
    shannon_entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return shannon_entropy


def dice_entropy_is_sufficient(roll_data: str, threshold: float = 2.0) -> bool:
    """Simple randomness check for dice roll input."""
    return _shannon_entropy(roll_data) >= threshold


def byte_entropy_is_sufficient(data: bytes, threshold: float = 3.5) -> bool:
    """Simple randomness check for byte data."""
    return _shannon_entropy(data) >= threshold
