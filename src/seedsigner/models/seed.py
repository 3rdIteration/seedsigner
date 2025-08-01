import logging
import unicodedata
import hashlib
import hmac

from binascii import hexlify
from embit import bip39, bip32, bip85
import shamir_mnemonic
from embit.networks import NETWORKS
from typing import List

from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)


class InvalidSeedException(Exception):
    pass



class Seed:
    def __init__(self,
                 mnemonic: List[str] = None,
                 passphrase: str = "",
                 wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> None:
        self._wordlist_language_code = wordlist_language_code

        if not mnemonic:
            raise Exception("Must initialize a Seed with a mnemonic List[str]")
        self._mnemonic: List[str] = unicodedata.normalize("NFKD", " ".join(mnemonic).strip()).split()

        self._passphrase: str = ""
        self.set_passphrase(passphrase, regenerate_seed=False)

        self.seed_bytes: bytes = None
        self.master_secret: bytes | None = None
        self._generate_seed()


    @staticmethod
    def get_wordlist(wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> List[str]:
        # TODO: Support other BIP-39 wordlist languages!
        if wordlist_language_code == SettingsConstants.WORDLIST_LANGUAGE__ENGLISH:
            return bip39.WORDLIST
        else:
            raise Exception(f"Unrecognized wordlist_language_code {wordlist_language_code}")


    def _generate_seed(self):
        try:
            self.seed_bytes = bip39.mnemonic_to_seed(self.mnemonic_str, password=self._passphrase, wordlist=self.wordlist)
        except Exception as e:
            logger.info(repr(e), exc_info=True)
            raise InvalidSeedException(repr(e))


    @property
    def mnemonic_str(self) -> str:
        return " ".join(self._mnemonic)
    

    @property
    def mnemonic_list(self) -> List[str]:
        return self._mnemonic


    @property 
    def wordlist_language_code(self) -> str:
        return self._wordlist_language_code


    @property
    def mnemonic_display_str(self) -> str:
        return unicodedata.normalize("NFC", " ".join(self._mnemonic))
    

    @property
    def mnemonic_display_list(self) -> List[str]:
        return unicodedata.normalize("NFC", " ".join(self._mnemonic)).split()


    @property
    def has_passphrase(self):
        return self._passphrase != ""


    @property
    def passphrase(self):
        return self._passphrase
        

    @property
    def passphrase_display(self):
        return unicodedata.normalize("NFC", self._passphrase)


    def set_passphrase(self, passphrase: str, regenerate_seed: bool = True):
        import re
        if passphrase:
            passphrase_save = passphrase
            passphrase = re.sub(r"\\(?!u)", r"\\\\", passphrase)
            try:
                passphrase = bytes(passphrase, encoding="raw_unicode_escape").decode("unicode_escape")
            except UnicodeDecodeError:
                passphrase = passphrase_save
            self._passphrase = unicodedata.normalize("NFKD", passphrase)
        else:
            # Passphrase must always have a string value, even if it's just the empty
            # string.
            self._passphrase = ""

        if regenerate_seed:
            # Regenerate the internal seed since passphrase changes the result
            self._generate_seed()


    @property
    def wordlist(self) -> List[str]:
        return Seed.get_wordlist(self.wordlist_language_code)


    def set_wordlist_language_code(self, language_code: str):
        # TODO: Support other BIP-39 wordlist languages!
        raise Exception("Not yet implemented!")


    @property
    def script_override(self) -> str:
        return None


    def derivation_override(self, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        return None


    def detect_version(self, derivation_path: str, network: str = SettingsConstants.MAINNET, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
        return bip32.detect_version(derivation_path, default="xpub", network=embit_network)


    @property
    def passphrase_label(self) -> str:
        return SettingsConstants.LABEL__BIP39_PASSPHRASE


    @property
    def seedqr_supported(self) -> bool:
        return True


    @property
    def bip85_supported(self) -> bool:
        return True


    def get_fingerprint(self, network: str = SettingsConstants.MAINNET) -> str:
        root = bip32.HDKey.from_seed(self.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"])
        return hexlify(root.child(0).fingerprint).decode('utf-8')


    def get_xpub(self, wallet_path: str = '/', network: str = SettingsConstants.MAINNET):
        # Import here to avoid slow startup times; takes 1.35s to import the first time
        from seedsigner.helpers import embit_utils
        return embit_utils.get_xpub(seed_bytes=self.seed_bytes, derivation_path=wallet_path, embit_network=SettingsConstants.map_network_to_embit(network))


    def get_bip85_child_mnemonic(self, bip85_index: int, bip85_num_words: int, network: str = SettingsConstants.MAINNET):
        """Derives the seed's nth BIP-85 child mnemonic"""
        root = bip32.HDKey.from_seed(self.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"])

        # TODO: Support other BIP-39 wordlist languages!
        return bip85.derive_mnemonic(root, bip85_num_words, bip85_index)
        

    ### override operators    
    def __eq__(self, other):
        if isinstance(other, Seed):
            return self.seed_bytes == other.seed_bytes
        return False



class ElectrumSeed(Seed):

    def _generate_seed(self):
        if len(self._mnemonic) != 12:
            raise InvalidSeedException(f"Unsupported Electrum seed length: {len(self._mnemonic)}")

        s = hmac.digest(b"Seed version", self.mnemonic_str.encode('utf8'), hashlib.sha512).hex()
        prefix = s[0:3]

        # only support Electrum Segwit version for now
        if SettingsConstants.ELECTRUM_SEED_SEGWIT == prefix:
            self.seed_bytes=hashlib.pbkdf2_hmac('sha512', self.mnemonic_str.encode('utf-8'), b'electrum' + self._passphrase.encode('utf-8'), iterations = SettingsConstants.ELECTRUM_PBKDF2_ROUNDS)

        else:
            raise InvalidSeedException(f"Unsupported Electrum seed format: {prefix}")


    def set_passphrase(self, passphrase: str, regenerate_seed: bool = True):
        import re
        if passphrase:
            passphrase_save = passphrase
            passphrase = re.sub(r"\\(?!u)", r"\\\\", passphrase)
            try:
                passphrase = bytes(passphrase, encoding="raw_unicode_escape").decode("unicode_escape")
            except UnicodeDecodeError:
                passphrase = passphrase_save
            self._passphrase = ElectrumSeed.normalize_electrum_passphrase(passphrase)
        else:
            # Passphrase must always have a string value, even if it's just the empty
            # string.
            self._passphrase = ""

        if regenerate_seed:
            # Regenerate the internal seed since passphrase changes the result
            self._generate_seed()


    @staticmethod
    def normalize_electrum_passphrase(passphrase : str) -> str:
        passphrase = unicodedata.normalize('NFKD', passphrase)
        # lower
        passphrase = passphrase.lower()
        # normalize whitespaces
        passphrase = u' '.join(passphrase.split())
        return passphrase


    @property
    def script_override(self) -> str:
        return SettingsConstants.NATIVE_SEGWIT


    def derivation_override(self, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        return "m/0h" if sig_type == SettingsConstants.SINGLE_SIG else "m/1h"


    def detect_version(self, derivation_path: str, network: str = SettingsConstants.MAINNET, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
        return embit_network["zpub"] if sig_type == SettingsConstants.SINGLE_SIG else embit_network["Zpub"]


    @property
    def passphrase_label(self) -> str:
        return SettingsConstants.LABEL__CUSTOM_EXTENSION


    @property
    def seedqr_supported(self) -> bool:
        return False


    @property
    def bip85_supported(self) -> bool:
        return False


class Slip39Seed(Seed):
    """Seed derived from SLIP-39 mnemonic shares."""

    def __init__(self, mnemonics: List[str], slip39_passphrase: str = "") -> None:
        self._wordlist_language_code = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH
        if not mnemonics:
            raise Exception("Must provide at least one SLIP-39 share")
        self._shares: List[str] = [unicodedata.normalize("NFKD", m.strip()) for m in mnemonics]

        first_share = shamir_mnemonic.Share.from_mnemonic(self._shares[0])
        self.extendable: bool = first_share.extendable
        self._member_threshold: int = first_share.member_threshold
        self._group_threshold: int = first_share.group_threshold

        # Passphrase used to decrypt the shares
        self._slip39_passphrase: str = unicodedata.normalize("NFKD", slip39_passphrase) if slip39_passphrase else ""

        self.seed_bytes: bytes = None
        self.master_secret: bytes | None = None
        self._initial_master_secret: bytes | None = None
        self._creation_passphrase: str = self._slip39_passphrase
        self._generate_seed()

    def _generate_seed(self):
        try:
            try:
                secret = shamir_mnemonic.combine_mnemonics(
                    self._shares, self._slip39_passphrase.encode("utf-8")
                )
            except Exception as e:
                if "Wrong number of mnemonics" not in str(e):
                    raise
                groups: dict[int, list[str]] = {}
                for share in self._shares:
                    s = shamir_mnemonic.Share.from_mnemonic(share)
                    grp = groups.setdefault(s.group_index, [])
                    if len(grp) < self._member_threshold:
                        grp.append(share)
                    if (
                        len(groups) >= self._group_threshold
                        and all(len(v) >= self._member_threshold for v in groups.values())
                    ):
                        break

                combine_list: list[str] = []
                for grp_index in sorted(groups.keys())[: self._group_threshold]:
                    combine_list.extend(groups[grp_index][: self._member_threshold])

                secret = shamir_mnemonic.combine_mnemonics(
                    combine_list, self._slip39_passphrase.encode("utf-8")
                )

            self.master_secret = secret
            if self._initial_master_secret is None:
                self._initial_master_secret = secret
            self.seed_bytes = secret
        except Exception as e:
            logger.info(repr(e), exc_info=True)
            raise InvalidSeedException(repr(e))

    # Expose shares as the mnemonic list/str for compatibility
    @property
    def mnemonic_list(self) -> List[str]:
        return list(self._shares)

    @property
    def mnemonic_str(self) -> str:
        return "\n".join(self._shares)

    def set_slip39_passphrase(self, passphrase: str, regenerate_seed: bool = True):
        """Set or update the passphrase used to decrypt the SLIP-39 shares."""
        self._slip39_passphrase = unicodedata.normalize("NFKD", passphrase) if passphrase else ""
        if regenerate_seed:
            self._generate_seed()

    @property
    def has_passphrase(self) -> bool:
        return self._slip39_passphrase != ""

    @property
    def passphrase(self) -> str:
        return self._slip39_passphrase

    @property
    def passphrase_display(self) -> str:
        return unicodedata.normalize("NFC", self._slip39_passphrase)

    @property
    def passphrase_label(self) -> str:
        return "SLIP-39 Passphrase"

    @property
    def seedqr_supported(self) -> bool:
        return False

    @property
    def bip85_supported(self) -> bool:
        return False

    def regenerate_shares(self, threshold: int, num_shares: int) -> List[str]:
        """Generate new SLIP-39 shares preserving the original identifier and
        master secret extracted before any passphrase changes."""
        if not self.extendable:
            raise InvalidSeedException("This SLIP-39 seed is not extendable")

        first_share = shamir_mnemonic.Share.from_mnemonic(self._shares[0])
        ems = shamir_mnemonic.shamir.EncryptedMasterSecret.from_master_secret(
            self._initial_master_secret,
            self._creation_passphrase.encode("utf-8"),
            first_share.identifier,
            True,
            first_share.iteration_exponent,
        )

        shares_objs = shamir_mnemonic.shamir.split_ems(
            first_share.group_threshold,
            [(threshold, num_shares)],
            ems,
        )[0]
        shares = [s.mnemonic() for s in shares_objs]

        self._shares = shares
        self._member_threshold = threshold
        return shares
