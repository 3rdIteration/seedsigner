from seedsigner.models.encryption import EncryptedQRCode

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



class EncryptedQRStorage:
    def __init__(self):
        self._encryptedqr: EncryptedQR = None


    @property
    def encryptedqr(self) -> EncryptedQR:
        return self._encryptedqr


    def set_encryptedqr(self, encryptedqr: EncryptedQR):
        self._encryptedqr = encryptedqr


    def clear_encryptedqr(self):
        self._encryptedqr = None


