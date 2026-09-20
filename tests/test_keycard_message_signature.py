# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest

from embit.ec import PrivateKey, PublicKey
from embit.util import secp256k1

from seedsigner.helpers import keycard_connector


KEY = PrivateKey(bytes([11]) * 32)
DIGEST = bytes(range(32))


def recover_pubkey(compact: bytes, digest: bytes) -> PublicKey:
    """Recover the signer from a 65-byte compact signature, as a verifier would."""
    header = compact[0]
    recid = (header - 27) & 0x03
    recsig = secp256k1.ecdsa_recoverable_signature_parse_compact(compact[1:], recid)
    return PublicKey(secp256k1.ecdsa_recover(recsig, digest))


class TestCompactSignature:
    """A compact signature must let a verifier recover the signing pubkey."""

    def test_recovery_id_is_found_for_a_real_signature(self):
        der = KEY.sign(DIGEST).serialize()

        compact = keycard_connector.compact_signature_for(der, DIGEST, KEY.get_public_key())

        assert compact is not None
        assert len(compact) == 65
        assert recover_pubkey(compact, DIGEST).sec() == KEY.get_public_key().sec()

    def test_a_signature_from_another_key_is_refused(self):
        other = PrivateKey(bytes([12]) * 32)
        der = other.sign(DIGEST).serialize()

        assert keycard_connector.compact_signature_for(der, DIGEST, KEY.get_public_key()) is None

    def test_garbage_is_refused(self):
        assert keycard_connector.compact_signature_for(b"\x00" * 70, DIGEST, KEY.get_public_key()) is None


class DummySig:
    def __init__(self, der, compact=None, public_key=None):
        self.signature_der = der
        self.signature = compact
        self.public_key = public_key


class DummyCard:
    def __init__(self, sig):
        self._sig = sig

    def sign(self, digest):
        return self._sig

    def sign_with_path(self, digest, path):
        return self._sig


class TestCardSignMessage:
    """No signature is better than a fake one reported as success."""

    def _connector(self, sig):
        conn = object.__new__(keycard_connector.KeycardSatochipConnector)
        conn._card = DummyCard(sig)
        conn._last_path = None
        conn._ensure_secure_channel = lambda: None
        return conn

    def test_a_missing_compact_signature_is_reconstructed(self):
        der = KEY.sign(DIGEST).serialize()
        conn = self._connector(DummySig(der, compact=None))

        _der, sw1, sw2, compact = conn.card_sign_message(0x00, KEY.get_public_key(), DIGEST)

        assert (sw1, sw2) == (0x90, 0x00)
        assert recover_pubkey(compact, DIGEST).sec() == KEY.get_public_key().sec()

    def test_an_unusable_signature_is_reported_as_failure(self):
        conn = self._connector(DummySig(b"\x30\x06\x02\x01\x01\x02\x01\x01", compact=None))

        _der, sw1, sw2, compact = conn.card_sign_message(0x00, KEY.get_public_key(), DIGEST)

        assert (sw1, sw2) != (0x90, 0x00)
        assert not compact


class CompatPubkey:
    """The shape the Keycard connector actually hands around: no .sec()."""

    def __init__(self, sec: bytes):
        self._sec = sec

    def get_public_key_bytes(self, compressed: bool = True) -> bytes:
        return self._sec


class TestPubkeyShapes:
    """Every caller's pubkey shape must work, or real signing returns 6F00."""

    def test_compat_pubkey_object(self):
        der = KEY.sign(DIGEST).serialize()

        compact = keycard_connector.compact_signature_for(
            der, DIGEST, CompatPubkey(KEY.get_public_key().sec())
        )

        assert compact is not None
        assert recover_pubkey(compact, DIGEST).sec() == KEY.get_public_key().sec()

    def test_raw_sec_bytes(self):
        der = KEY.sign(DIGEST).serialize()

        compact = keycard_connector.compact_signature_for(
            der, DIGEST, KEY.get_public_key().sec()
        )

        assert compact is not None


class TestSignMessageWithoutACallerPubkey:
    """
    With no pubkey from the caller, the key the card names in its SIGN response
    is the one to recover against. Asking the card for it again is a second
    round trip inside what the benchmark times.
    """

    def test_pubkey_none_uses_the_key_in_the_sign_response(self):
        der = KEY.sign(DIGEST).serialize()
        # The SIGN response carries the key uncompressed
        named = PublicKey.parse(KEY.get_public_key().sec())
        named.compressed = False
        uncompressed = named.sec()
        assert len(uncompressed) == 65
        conn = object.__new__(keycard_connector.KeycardSatochipConnector)
        conn._card = DummyCard(DummySig(der, compact=None, public_key=uncompressed))
        conn._last_path = "m/84'/0'/0'/0/0"
        conn._ensure_secure_channel = lambda: None

        def no_card_request(path):
            raise AssertionError("asked the card for a key it had already named")

        conn.card_bip32_get_extendedkey = no_card_request

        _der, sw1, sw2, compact = conn.card_sign_message(0xFF, None, DIGEST)

        assert (sw1, sw2) == (0x90, 0x00)
        assert recover_pubkey(compact, DIGEST).sec() == KEY.get_public_key().sec()


class RecordingKeycard:
    """keycard-py's shape: signature is r||s, 64 bytes, never 65."""

    def __init__(self, ops):
        self.ops = ops

    def sign_with_path(self, digest, path):
        self.ops.append("SIGN")
        der = KEY.sign(digest).serialize()
        return DummySig(der, compact=bytes(64))

    def sign(self, digest):
        return self.sign_with_path(digest, None)


class TestTheBenchmarkTimesOnlyTheSignature(BaseTest):
    """A benchmark sample must be the one signature it claims to time."""

    def test_one_sample_is_one_card_operation(self, monkeypatch):
        from seedsigner.views import smartcard_views
        from seedsigner.views.smartcard_views import ToolsKeycardBenchmarkMessageSignView

        ops = []
        conn = object.__new__(keycard_connector.KeycardSatochipConnector)
        conn._card = RecordingKeycard(ops)
        conn._last_path = None
        conn._ensure_secure_channel = lambda: None

        def derive(path):
            ops.append("DERIVE")
            return CompatPubkey(KEY.get_public_key().sec()), b"\x00" * 32

        conn.card_bip32_get_extendedkey = derive
        sign_message = conn.card_sign_message

        def timed_sign_message(*args):
            ops.append("[")
            try:
                return sign_message(*args)
            finally:
                ops.append("]")

        conn.card_sign_message = timed_sign_message
        monkeypatch.setattr(ToolsKeycardBenchmarkMessageSignView, "NUM_SAMPLES", 2)
        monkeypatch.setattr(
            smartcard_views.seedkeeper_utils, "init_satochip", lambda *a, **kw: conn
        )
        texts = []
        view = ToolsKeycardBenchmarkMessageSignView()
        monkeypatch.setattr(
            view, "run_screen", lambda screen, **kw: texts.append(kw.get("text")), raising=False
        )

        view.run()

        # The view derives the key it verifies against before starting the clock
        assert ops == ["DERIVE", "[", "SIGN", "]"] * 2
        assert texts[-1].startswith("Min:"), texts
