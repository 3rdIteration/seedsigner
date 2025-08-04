import binascii
from binascii import hexlify

from embit import ec, hashes

from seedsigner.models.seed import InvalidSeedException
from seedsigner.models.settings import SettingsConstants


class WIFKey:
    """Container for a single WIF-encoded private key."""

    def __init__(self, wif: str):
        try:
            self.privkey = ec.PrivateKey.from_wif(wif)
        except Exception as e:
            raise InvalidSeedException("Invalid WIF") from e
        self.wif = wif

    def get_fingerprint(self, network: str = SettingsConstants.MAINNET) -> str:
        """Return BIP32-style fingerprint for the key's public key."""
        pub = self.privkey.get_public_key()
        fp = hashes.hash160(pub.sec())[:4]
        return hexlify(fp).decode()
