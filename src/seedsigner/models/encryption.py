# The MIT License (MIT)

# Copyright (c) 2021-2025 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import time
import hashlib
from embit import bip39
from seedsigner.helpers import kef
from seedsigner.models.settings import Settings, SettingsConstants

QR_CODE_ITER_MULTIPLE = 10000



class EncryptedQRCode:
    """Creates and decrypts encrypted mnemonic QR codes"""

    def __init__(self) -> None:
        self.settings = Settings.get_instance()
        self.mnemonic_id = None
        self.version = None
        self.iterations = self.settings.get_value(SettingsConstants.SETTING__ENCRYPTION_ITER) * QR_CODE_ITER_MULTIPLE
        max_delta = self.iterations // 10
        self.iterations += int(time.time() * 1000) % max_delta
        self.encrypted_data = None

    def create(self, key, mnemonic_id, mnemonic, i_vector=None):
        """encrypted mnemonic QR codes"""
        mode_name = self.settings.get_value(SettingsConstants.SETTING__ENCRYPTION_MODE)
        encryptor = kef.Cipher(key, mnemonic_id, self.iterations)
        bytes_to_encrypt = bip39.mnemonic_to_bytes(mnemonic)
        self.version = kef.suggest_versions(bytes_to_encrypt, mode_name)[0]
        bytes_encrypted = encryptor.encrypt(bytes_to_encrypt, self.version, i_vector)
        return kef.wrap(mnemonic_id, self.version, self.iterations, bytes_encrypted)

    def public_data(self, data):
        """Parse and returns encrypted mnemonic QR codes public data"""
        try:
            (self.mnemonic_id, self.version, self.iterations, self.encrypted_data) = (
                kef.unwrap(data)
            )
            version_name = kef.VERSIONS[self.version]["name"]
        except:
            return None

        try:
            displayable_id = self.mnemonic_id.decode()
        except UnicodeDecodeError:
            displayable_id = repr(self.mnemonic_id)  # id_ could be any bytes
        return "\n".join(
            [
                "Encrypted QR Code:",
                "ID: " + displayable_id,
                "Version: " + version_name,
                "PBKDF2 iter.: " + str(self.iterations),
            ]
        )

    def decrypt(self, key):
        """Decrypts encrypted mnemonic QR codes"""
        decryptor = kef.Cipher(key, self.mnemonic_id, self.iterations)
        decrypted_data = decryptor.decrypt(self.encrypted_data, self.version)
        return decrypted_data
