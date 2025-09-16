import pytest
from embit import bip39

from seedsigner.helpers import kef
from seedsigner.models.encryption import EncryptedQRCode
from seedsigner.models.settings_definition import SettingsConstants

from base import BaseTest


ITERATIONS = 1000
TEST_KEY = "test key"
TEST_MNEMONIC_ID = "test ID"
TEST_WORDS = "crush inherit small egg include title slogan mom remain blouse boost bonus"

ECB_ENTROPY = b"\x1b&ew\xe6\x84\xc5\xb0\x9c\x89\xf5$\xb5\xca\x10Aa\x90\xaae\t\x19\xdb\xd9\x9e\xc7C\x16a~%C"
CBC_ENTROPY = b"@\x8c\xf9\xb8\xd8\xd9\xe2\xbdo\xb5\xd1\xa1?\xb0\x10O\xd4\xc8\xfd()\xa0\xc2\xaf\xb5\x1d\x06\xdc\xfb\x80\x1cn"
CTR_ENTROPY = b"\xecT\xea4l\xaa\x1e\xd0l\xb3\\\x96\xc4\xef#\"\x8a&\xa2\xe0\x99lq\xd0`\x8e\xc2\xbaI\xce#\x16"
GCM_ENTROPY = b"\x06\xef\x92\xe3\xbb\xb6\xc8\xdauWu\xa0\xa9\x00\xa4<E\\\x8e\x103\xdd\x95\xf8]6CE\xf3\xdc\xae}"

ECB_ENCRYPTED_WORDS = (
    b"\xd4\xd5y\xe6]'\xcb\xdb\xe4\x15^\xac\xe0\xc9\xc3\xbc9i\x89e\t\xa3~l\xbf\x98l\xe9\x92\xa9\xe1=3V\xb3\xb1]\xfb|\x13\xf4K_\xdb\xa7d\x92p\x8a-\xbfr\xb5`"
    b"\xaf\xe5\xc4\xfeP Z\x12\xfbbQ9G'\xael\x9d*F\xafn4\t\x7fE\xb2K\xc1\xbaB\xfa\xb7J6\xefu\x95\xa9\x9c\xe8\x14\x88"
)
CBC_ENCRYPTED_WORDS = (
    b"OR\xa1\x93l>2q \x9e\x9dd\x05\x9e\xd7\x8e\x92\xdaXV%+\xdb\x12\x85\xa6\x0c\xc8\xee\xc1>h\xd4i\xc1!r\x8d\x97\xd4\xb1V\x0c/\x18D\xff\x99\xd8a\xb8\x85\x81(\x08\xca\x07\xc8\xe0(\x04\xf5\xe1\xf0\xfd\xd9\xd4>E\xdf\x8aV\xb4\x19`\x10\xeaF\x03\x01\x16\x9e\x07&+|\xcb\x15"
    b"as\x92y\xa1>\xd0\xc8\xca\xb0YX\x08\xda>\xf0\xca6=\xc9cR\xb5j"
)

ECB_ENCRYPTED_QR = b"\x07test ID\x05\x00\x00\n*\xe1\x9d\xc5\x82\xc1\x19\x9b\xb7&\xf2?\x03\xc7o\xf6R>#"
CBC_ENCRYPTED_QR = b"\x07test ID\n\x00\x00\nOR\xa1\x93l>2q \x9e\x9dd\x05\x9e\xd7\x8e\x01\x03`u_\xd7\xab/N\xbc@\x19\xcc\n\"\xc5C\xfa\x96\x90"
GCM_ENCRYPTED_QR = b"\x07test ID\x14\x00\x00\nOR\xa1\x93l>2q \x9e\x9dd\xbf\xb7vo]]\x8aO\x90\x8e\x86\xe784L\x02]\x8f\xedT"

ECB_QR_PUBLIC_DATA = "Encrypted QR Code:\nID: test ID\nVersion: AES-ECB\nPBKDF2 iter.: 100000"
CBC_QR_PUBLIC_DATA = "Encrypted QR Code:\nID: test ID\nVersion: AES-CBC\nPBKDF2 iter.: 100000"
GCM_QR_PUBLIC_DATA = "Encrypted QR Code:\nID: test ID\nVersion: AES-GCM\nPBKDF2 iter.: 100000"

I_VECTOR = b"OR\xa1\x93l>2q \x9e\x9dd\x05\x9e\xd7\x8e"

KEF_ENVELOPE_ECB = b"\x08KEFecbID\x05\x00\x00\n\xb8\xd9>\xc1\xcf\xf6\xc04P\x02\xa2Z\xea-Ev\xe7\x16f\xbf\x1dY\xdfiP\x19W\xa2\xb0\xe5;\xbbP\xf4\xf7"
KEF_ENVELOPE_CBC = b"\x08KEFcbcID\n\x00\x00\nOR\xa1\x93l>2q \x9e\x9dd\x05\x9e\xd7\x8el\x84S\xe8\x8d\x82\xc0\xe2\x1baX{\xf6gaR#$:~nJS\xcdM.$?\x99\x00\xcc\xe3\xa5\xea\xb5\xa2"
KEF_ENVELOPE_CTR = b"\x08KEFctrID\x0f\x00\x00\ni$\x05\xdcn\xa8\xbf\x1f,\xe2xyb\xd3\xf6\xcc7\x88\xfbF=\x9e\xfdi\xb7\xbb\x1aMXey\x1a\xa1\xc12Q\xab\nAn]\xe8\xa2\xa9\xe8X\x1c\x0c"
KEF_ENVELOPE_GCM = b"\x08KEFgcmID\x14\x00\x00\nOR\xa1\x93l>2q \x9e\x9dd\xbf\xa3\x0c?\xd7\xfa\xff,%\x8d\xf3\xee\x88\x81N\x08\xd3\xb7\xd0[&\x1df\x01\x0b\xac\xd6\xb6\xc5\x17\x80\xf8\x1c\x7f\x92W"


def test_cipher_encrypt_vectors():
    cipher = kef.Cipher(TEST_KEY, TEST_MNEMONIC_ID, ITERATIONS)
    plaintext = TEST_WORDS.encode()

    encrypted_ecb = cipher.encrypt(plaintext, 0)
    assert encrypted_ecb == ECB_ENCRYPTED_WORDS
    assert cipher.decrypt(encrypted_ecb, 0) == plaintext

    encrypted_cbc = cipher.encrypt(plaintext, 1, I_VECTOR)
    assert encrypted_cbc == CBC_ENCRYPTED_WORDS
    assert cipher.decrypt(encrypted_cbc, 1) == plaintext


@pytest.mark.parametrize(
    "envelope, expected_id, expected_version, expected_plain",
    [
        (KEF_ENVELOPE_ECB, b"KEFecbID", 5, ECB_ENTROPY),
        (KEF_ENVELOPE_CBC, b"KEFcbcID", 10, CBC_ENTROPY),
        (KEF_ENVELOPE_CTR, b"KEFctrID", 15, CTR_ENTROPY),
        (KEF_ENVELOPE_GCM, b"KEFgcmID", 20, GCM_ENTROPY),
    ],
)
def test_kef_wrap_unwrap_roundtrip(envelope, expected_id, expected_version, expected_plain):
    id_bytes, version, iterations, payload = kef.unwrap(envelope)
    assert id_bytes == expected_id
    assert version == expected_version
    assert iterations == 100000

    cipher = kef.Cipher(TEST_KEY, id_bytes, iterations)
    decrypted = cipher.decrypt(payload, version)
    assert decrypted == expected_plain

    iv_len = kef.MODE_IVS.get(kef.VERSIONS[version]["mode"], 0)
    if iv_len:
        iv = payload[:iv_len]
        reencrypted = cipher.encrypt(expected_plain, version, iv)
    else:
        reencrypted = cipher.encrypt(expected_plain, version)
    assert reencrypted == payload

    assert kef.wrap(id_bytes, version, iterations, payload) == envelope


class TestEncryptedQRCodeVectors(BaseTest):
    def setup_method(self):
        super().setup_method()
        self.settings.set_value(
            SettingsConstants.SETTING__ENCRYPTION_ITER, 10, save=False
        )

    def test_create_ecb_encrypted_qr(self):
        self.settings.set_value(
            SettingsConstants.SETTING__ENCRYPTION_MODE,
            SettingsConstants.ENCRYPTION_MODE_ECB,
            save=False,
        )
        encrypted_qr = EncryptedQRCode()
        qr_data = encrypted_qr.create(TEST_KEY, TEST_MNEMONIC_ID, TEST_WORDS)
        assert qr_data == ECB_ENCRYPTED_QR

    def test_create_cbc_encrypted_qr(self):
        self.settings.set_value(
            SettingsConstants.SETTING__ENCRYPTION_MODE,
            SettingsConstants.ENCRYPTION_MODE_CBC,
            save=False,
        )
        encrypted_qr = EncryptedQRCode()
        qr_data = encrypted_qr.create(
            TEST_KEY, TEST_MNEMONIC_ID, TEST_WORDS, I_VECTOR
        )
        assert qr_data == CBC_ENCRYPTED_QR

    def test_create_gcm_encrypted_qr(self):
        self.settings.set_value(
            SettingsConstants.SETTING__ENCRYPTION_MODE,
            SettingsConstants.ENCRYPTION_MODE_GCM,
            save=False,
        )
        encrypted_qr = EncryptedQRCode()
        qr_data = encrypted_qr.create(
            TEST_KEY, TEST_MNEMONIC_ID, TEST_WORDS, I_VECTOR[:12]
        )
        assert qr_data == GCM_ENCRYPTED_QR

    def test_decode_ecb_encrypted_qr(self):
        encrypted_qr = EncryptedQRCode()
        public_data = encrypted_qr.public_data(ECB_ENCRYPTED_QR)
        assert public_data == ECB_QR_PUBLIC_DATA

        mnemonic = bip39.mnemonic_from_bytes(encrypted_qr.decrypt(TEST_KEY))
        assert mnemonic == TEST_WORDS

    def test_decode_cbc_encrypted_qr(self):
        encrypted_qr = EncryptedQRCode()
        public_data = encrypted_qr.public_data(CBC_ENCRYPTED_QR)
        assert public_data == CBC_QR_PUBLIC_DATA

        mnemonic = bip39.mnemonic_from_bytes(encrypted_qr.decrypt(TEST_KEY))
        assert mnemonic == TEST_WORDS

    def test_decode_gcm_encrypted_qr(self):
        encrypted_qr = EncryptedQRCode()
        public_data = encrypted_qr.public_data(GCM_ENCRYPTED_QR)
        assert public_data == GCM_QR_PUBLIC_DATA

        mnemonic = bip39.mnemonic_from_bytes(encrypted_qr.decrypt(TEST_KEY))
        assert mnemonic == TEST_WORDS
