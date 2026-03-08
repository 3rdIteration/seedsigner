import hashlib

from Crypto.Cipher import AES
from embit import base58, ec, hashes

from seedsigner.models.seed import InvalidSeedException
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.wif import WIFKey


class BIP38Key:
    """Container for a BIP38 encrypted private key."""

    def __init__(self, encrypted: str):
        self.encrypted = encrypted
        try:
            data = base58.decode_check(encrypted)
        except Exception as e:
            raise InvalidSeedException("Invalid BIP38") from e

        if len(data) != 39 or data[0] != 0x01 or data[1] != 0x42:
            raise InvalidSeedException("Invalid BIP38")

        flagbyte = data[2]
        self.compressed = bool(flagbyte & 0x20)
        self.address_hash = data[3:7]
        self.encrypted_half1 = data[7:23]
        self.encrypted_half2 = data[23:39]

    def decrypt(self, passphrase: str, network: str = SettingsConstants.MAINNET) -> WIFKey:
        """Decrypt the BIP38 key using the given passphrase."""

        derived = hashlib.scrypt(
            passphrase.encode("utf-8"),
            salt=self.address_hash,
            n=16384,
            r=8,
            p=8,
            dklen=64,
        )
        derivedhalf1 = derived[:32]
        derivedhalf2 = derived[32:]

        aes = AES.new(derivedhalf2, AES.MODE_ECB)
        decrypted_half1 = aes.decrypt(self.encrypted_half1)
        decrypted_half2 = aes.decrypt(self.encrypted_half2)

        priv = bytearray(32)
        for i in range(16):
            priv[i] = decrypted_half1[i] ^ derivedhalf1[i]
            priv[i + 16] = decrypted_half2[i] ^ derivedhalf1[i + 16]
        priv = bytes(priv)

        pub = ec.PrivateKey(priv).get_public_key()
        if not self.compressed:
            pub.compressed = False
        prefix = b"\x00" if network == SettingsConstants.MAINNET else b"\x6f"
        h160 = hashes.hash160(pub.sec())
        addr = base58.encode_check(prefix + h160)
        if hashes.double_sha256(addr.encode("ascii"))[:4] != self.address_hash:
            raise InvalidSeedException("Invalid passphrase")

        wif_prefix = b"\x80" if network == SettingsConstants.MAINNET else b"\xef"
        wif_bytes = wif_prefix + priv + (b"\x01" if self.compressed else b"")
        wif = base58.encode_check(wif_bytes)
        return WIFKey(wif)

