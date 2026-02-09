from seedsigner.models.encryption import EncryptedQRCode
from seedsigner.helpers.secure_delete import wipe_string

class EncryptedQR:
    def __init__(self, encrypted_qr: EncryptedQRCode=None, public_data: str=None):
        self._encrypted_qr: EncryptedQRCode = encrypted_qr
        self._public_data: str = public_data
        self._encryption_key: str = None


    @property
    def encrypted_qr(self) -> EncryptedQRCode:
        return self._encrypted_qr


    @property
    def public_data(self) -> str:
        return self._public_data


    @property
    def encryption_key(self) -> str:
        return self._encryption_key


    def set_encryption_key(self, encryption_key: str):
        self._encryption_key = encryption_key


    def wipe(self):
        wipe_string(self._encryption_key)
        self._encryption_key = None


class EncryptedQRStorage:
    def __init__(self):
        self._encryptedqr: EncryptedQR = None


    @property
    def encryptedqr(self) -> EncryptedQR:
        return self._encryptedqr


    def set_encryptedqr(self, encryptedqr: EncryptedQR):
        self._encryptedqr = encryptedqr


    def clear_encryptedqr(self):
        if self._encryptedqr:
            self._encryptedqr.wipe()
        self._encryptedqr = None


