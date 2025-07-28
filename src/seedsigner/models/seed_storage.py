from typing import List
from seedsigner.models.seed import Seed, ElectrumSeed, Slip39Seed, InvalidSeedException
from seedsigner.models.settings_definition import SettingsConstants



class SeedStorage:
    def __init__(self) -> None:
        self.seeds: List[Seed] = []
        self.pending_seed: Seed = None
        self._pending_mnemonic: List[str] = []
        self._pending_is_electrum: bool = False
        self._pending_is_slip39: bool = False
        self._pending_slip39_share: List[str] = []
        self._pending_slip39_shares: List[List[str]] = []


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


    def init_pending_mnemonic(self, num_words:int = 12, is_electrum:bool = False):
        self._pending_mnemonic = [None] * num_words
        self._pending_is_electrum = is_electrum


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
    

    def get_pending_mnemonic_fingerprint(self, network: str = SettingsConstants.MAINNET) -> str:
        try:
            if self._pending_is_electrum:
                seed = ElectrumSeed(self._pending_mnemonic)
            else:
                seed = Seed(self._pending_mnemonic)
            return seed.get_fingerprint(network)
        except InvalidSeedException:
            return None


    def convert_pending_mnemonic_to_pending_seed(self):
        if self._pending_is_electrum:
            self.pending_seed = ElectrumSeed(self._pending_mnemonic)
        else:
            self.pending_seed = Seed(self._pending_mnemonic)
        self.discard_pending_mnemonic()
    

    def discard_pending_mnemonic(self):
        self._pending_mnemonic = []
        self._pending_is_electrum = False

    """Slip39 share handling"""

    def init_pending_slip39_share(self, num_words: int = 33):
        self._pending_slip39_share = [None] * num_words
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
        self._pending_slip39_shares.append(list(self._pending_slip39_share))
        self._pending_slip39_share = []

    def convert_pending_slip39_shares_to_pending_seed(self, passphrase: str = ""):
        mnemonics = [" ".join(share) for share in self._pending_slip39_shares]
        self.pending_seed = Slip39Seed(mnemonics=mnemonics, passphrase=passphrase)
        self.discard_pending_slip39_shares()

    def discard_pending_slip39_shares(self):
        self._pending_slip39_share = []
        self._pending_slip39_shares = []
        self._pending_is_slip39 = False
