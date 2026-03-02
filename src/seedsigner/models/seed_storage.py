from typing import List
from seedsigner.helpers.secure_delete import wipe_bytes, wipe_list
from seedsigner.models.seed import Seed, ElectrumSeed, Slip39Seed, InvalidSeedException
from seedsigner.models.settings_definition import SettingsConstants



class SeedStorage:
    def __init__(self) -> None:
        self.seeds: List[Seed] = []
        self.pending_seed: Seed = None
        self._pending_mnemonic: List[str] = []
        self._pending_is_electrum: bool = False
        self._pending_is_aezeed: bool = False
        self._pending_is_slip39: bool = False
        self._pending_slip39_share: List[str] = []
        self._pending_slip39_shares: List[List[str]] = []
        self._slip39_share_length: int | None = None
        self._slip39_first_share = None


    def set_pending_seed(self, seed: Seed):
        self.pending_seed = seed


    def get_pending_seed(self) -> Seed:
        return self.pending_seed


    def finalize_pending_seed(self) -> int:
        # Finally store the pending seed and return its index
        if self.pending_seed in self.seeds:
            index = self.seeds.index(self.pending_seed)
        else:
            self.seeds.append(self.pending_seed)
            index = len(self.seeds) - 1
        self.pending_seed = None
        return index


    def clear_pending_seed(self):
        if self.pending_seed is not None:
            self.pending_seed.wipe()
        self.pending_seed = None


    def validate_mnemonic(self, mnemonic: List[str]) -> bool:
        try:
            Seed(mnemonic=mnemonic)
        except InvalidSeedException as e:
            return False
        
        return True


    def num_seeds(self):
        return len(self.seeds)
    

    @property
    def pending_mnemonic(self) -> List[str]:
        # Always return a copy so that the internal List can't be altered
        return list(self._pending_mnemonic)


    @property
    def pending_mnemonic_length(self) -> int:
        return len(self._pending_mnemonic)


    def init_pending_mnemonic(self, num_words:int = 12, is_electrum:bool = False, is_aezeed:bool = False):
        self._pending_mnemonic = [None] * num_words
        self._pending_is_electrum = is_electrum
        self._pending_is_aezeed = is_aezeed


    def update_pending_mnemonic(self, word: str, index: int):
        """
        Replaces the nth word in the pending mnemonic.

        * may specify a negative `index` (e.g. -1 is the last word).
        """
        if index >= len(self._pending_mnemonic):
            raise Exception(f"index {index} is too high")
        self._pending_mnemonic[index] = word
    

    def get_pending_mnemonic_word(self, index: int) -> str:
        if index < len(self._pending_mnemonic):
            return self._pending_mnemonic[index]
        return None
    

    def get_pending_mnemonic_fingerprint(
        self,
        network: str = SettingsConstants.MAINNET,
        wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
    ) -> str:
        try:
            if self._pending_is_electrum:
                seed = ElectrumSeed(self._pending_mnemonic)
            elif self._pending_is_aezeed:
                return None
            else:
                seed = Seed(self._pending_mnemonic, wordlist_language_code=wordlist_language_code)
            return seed.get_fingerprint(network)
        except InvalidSeedException:
            return None


    def convert_pending_mnemonic_to_pending_seed(
        self,
        wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
    ):
        if self._pending_is_electrum:
            self.pending_seed = ElectrumSeed(self._pending_mnemonic)
        elif self._pending_is_aezeed:
            raise InvalidSeedException("Aezeed decoding is not yet supported")
        else:
            self.pending_seed = Seed(self._pending_mnemonic, wordlist_language_code=wordlist_language_code)
        self.discard_pending_mnemonic()
    

    def discard_pending_mnemonic(self):
        wipe_list(self._pending_mnemonic)
        self._pending_mnemonic = []
        self._pending_is_electrum = False
        self._pending_is_aezeed = False

    """Slip39 share handling"""

    def init_pending_slip39_share(self, num_words: int | None = None):
        if num_words is None:
            num_words = self._slip39_share_length or 33
        self._pending_slip39_share = [None] * num_words
        self._slip39_share_length = num_words
        self._pending_is_slip39 = True

    def update_pending_slip39_share(self, word: str, index: int):
        if index >= len(self._pending_slip39_share):
            raise Exception(f"index {index} is too high")
        self._pending_slip39_share[index] = word

    def get_pending_slip39_word(self, index: int) -> str:
        if index < len(self._pending_slip39_share):
            return self._pending_slip39_share[index]
        return None

    @property
    def pending_slip39_share_length(self) -> int:
        return len(self._pending_slip39_share)

    def finalize_current_slip39_share(self):
        mnemonic = " ".join(self._pending_slip39_share)
        from shamir_mnemonic import Share as Slip39Share
        try:
            share_obj = Slip39Share.from_mnemonic(mnemonic)
        except Exception:
            self._pending_slip39_share = []
            raise InvalidSeedException("Invalid SLIP-39 share")

        if self._slip39_first_share is None:
            self._slip39_first_share = share_obj

        self._pending_slip39_shares.append(list(self._pending_slip39_share))
        self._pending_slip39_share = []

    def add_slip39_share_mnemonic(self, mnemonic: str):
        """Add a share mnemonic directly."""
        from shamir_mnemonic import Share as Slip39Share
        try:
            share_obj = Slip39Share.from_mnemonic(mnemonic)
        except Exception:
            raise InvalidSeedException("Invalid SLIP-39 share")
        if self._slip39_first_share is None:
            self._slip39_first_share = share_obj
        self._pending_slip39_shares.append(mnemonic.split())
        self._slip39_share_length = len(mnemonic.split())
        self._pending_is_slip39 = True

    def convert_pending_slip39_shares_to_pending_seed(self, passphrase: str = ""):
        mnemonics = [" ".join(share) for share in self._pending_slip39_shares]
        self.pending_seed = Slip39Seed(
            mnemonics=mnemonics,
            slip39_passphrase=passphrase,
        )
        self.discard_pending_slip39_shares()

    def discard_pending_slip39_shares(self):
        wipe_list(self._pending_slip39_share)
        for share in self._pending_slip39_shares:
            wipe_list(share)
        self._pending_slip39_share = []
        self._pending_slip39_shares = []
        self._pending_is_slip39 = False
        self._slip39_share_length = None
        self._slip39_first_share = None

    @property
    def slip39_shares_entered(self) -> int:
        return len(self._pending_slip39_shares)

    @property
    def slip39_total_needed(self) -> int | None:
        if self._slip39_first_share is None:
            return None
        g = self._slip39_first_share.group_threshold
        m = self._slip39_first_share.member_threshold
        return m * g if g > 1 else m
