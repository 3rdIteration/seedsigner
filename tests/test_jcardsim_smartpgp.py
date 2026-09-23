"""
    SmartPGP as real applet bytecode in jcardsim, driven by SeedSigner's real
    smartpgp client (``seedsigner.helpers.smartpgp.commands`` -- the same APDUs used
    against a physical card).

    The spec is pinned to ``v1.23.2.0-javacard-3.0.4``, not the repo's default 3.1
    branch: jcardsim implements the JavaCard 3.0.x API and has neither
    NamedParameterSpec nor XECKey, which the 3.1 sources import. The build also applies
    SmartPGP's own ``rsa-4096.patch`` (via AppletSpec.source_edits): a single constant
    bump of the transient buffer from 0x3B0 to 0x730 so a full RSA-4096 CRT key import
    -- 1819 chained PUT DATA bytes -- fits. Without it, importing keys above 2048 bits
    fails with SW=6581 (memory failure).

    Two jcardsim divergences from real hardware matter here:

    * **PSO sign must be sent as a case-4 APDU with Le.** jcardsim's ``setOutgoing()``
      returns the command's Le field, which is 0 for a case-3 APDU; the JCRE spec says
      it should return 256. SmartPGP's output path treats "Le == 0" as "send everything
      at once", so an RSA signature longer than its 260-byte short APDU buffer overflows
      with an ArrayIndexOutOfBoundsException (surfaced as SW=6F00). Sending the command
      with a Le byte present makes it chunk the response and return SW=61XX, which is
      exactly what real cards do for oversized responses -- the client then collects the
      rest with GET RESPONSE (INS 0xC0). See ``pso_sign_sha256``.

    * **PIN lockout is terminal.** A wrong PIN returns SW=6982; after three failures the
      reference data is blocked and even the correct PIN fails for the life of the card
      (this SmartPGP version implements no unblock command). Every test gets a fresh
      simulated card, so the lockout test below cannot poison anything else.

    Signing is verified off-card with ``cryptography``: the on-card PKCS#1 v1.5 signature
    must validate against the public key that was imported into it.
"""

import hashlib

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401

from jcardsim import JCardSimUnavailable, open_card, resolve_applet, why_unavailable


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)

# Factory defaults from the applet's Constants.java.
USER_PIN = "123456"
ADMIN_PIN = "12345678"

# DER DigestInfo header for SHA-256; PSO sign takes [header][digest], not the message.
DSI_SHA256 = bytes.fromhex("3031300D060960864801650304020105000420")


@pytest.fixture
def smartpgp():
    try:
        card = open_card("smartpgp")
    except JCardSimUnavailable as exc:
        pytest.skip(str(exc))
    with card:
        yield card


def select(card) -> None:
    """SELECT via SeedSigner's own APDU (6-byte AID prefix, case-4S)."""
    from seedsigner.helpers.smartpgp import commands

    _, sw1, sw2 = commands.select_applet(card)
    assert (sw1, sw2) == (0x90, 0x00), "SELECT failed"


def verify_user_pin_sign_mode(card, pin: str = USER_PIN) -> tuple[int, int]:
    """VERIFY in signature mode (P2=81).

    commands.py only ships the decrypt-mode VERIFY (P2=82); PSO sign requires the user
    PIN to have been verified in signing mode.
    """
    data = [ord(c) for c in pin]
    _, sw1, sw2 = card.transmit([0x00, 0x20, 0x00, 0x81, len(data)] + data)
    return (sw1, sw2)


def pso_sign_sha256(card, message: bytes) -> tuple[bytes, int, int]:
    """PSO sign the SHA-256 digest of ``message`` with the signature key.

    Sent as a case-4S APDU with Le=0x00 and chained via GET RESPONSE -- see the module
    docstring for why a plain case-3 command overflows jcardsim's short APDU buffer.
    """
    digest_in = DSI_SHA256 + hashlib.sha256(message).digest()
    data, sw1, sw2 = card.transmit(
        [0x00, 0x2A, 0x9E, 0x9A, len(digest_in)] + list(digest_in) + [0x00])
    sig = bytes(data)
    while sw1 == 0x61:
        data, sw1, sw2 = card.transmit([0x00, 0xC0, 0x00, 0x00])
        sig += bytes(data)
    return sig, sw1, sw2


def rsa_crt_components(bits: int):
    """Generate an RSA key off-card and return (public_key, [(tag, value), ...]).

    The component tags are the OpenPGP card DOs SmartPGP's PUT DATA expects for a CRT-
    form RSA private key; ``cryptography``'s public key is returned so the test can
    verify on-card signatures off-card.
    """
    import pgpy
    from cryptography.hazmat.primitives.asymmetric import rsa
    from pgpy.constants import PubKeyAlgorithm

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, bits)
    km = key._key.keymaterial
    public_key = rsa.RSAPublicNumbers(int(km.e), int(km.n)).public_key()

    n = int(km.n); e = int(km.e); d = int(km.d)
    p = int(km.p); q = int(km.q)
    half = (n.bit_length() + 7) // 8 // 2
    dp = d % (p - 1); dq = d % (q - 1); qinv = pow(q, -1, p)
    exp_len = max(1, (e.bit_length() + 7) // 8)
    return public_key, [
        (0x91, e.to_bytes(exp_len, "big")),       # exponent
        (0x92, p.to_bytes(half, "big")),          # prime1
        (0x93, q.to_bytes(half, "big")),          # prime2
        (0x94, qinv.to_bytes(half, "big")),       # coefficient
        (0x95, dp.to_bytes(half, "big")),         # exponent1
        (0x96, dq.to_bytes(half, "big")),         # exponent2
        (0x97, n.to_bytes(half * 2, "big")),      # modulus
    ]


def import_rsa_key(card, bits: int, monkeypatch):
    """Run SeedSigner's real import flow; returns the off-card public key.

    Wraps commands._raw_send_apdu to record every status word, because switch_crypto()
    and put_key_components() print their SWs but return None.
    """
    from seedsigner.helpers.smartpgp import commands

    select(card)
    _, sw1, sw2 = commands.verif_admin_pin(card, ADMIN_PIN)
    assert (sw1, sw2) == (0x90, 0x00), "admin PIN verify failed"

    public_key, components = rsa_crt_components(bits)

    status_words: list[tuple[str, int, int]] = []
    real_send = commands._raw_send_apdu

    def spy(connection, text, apdu):
        result = real_send(connection, text, apdu)
        status_words.append((text, result[1], result[2]))
        return result

    monkeypatch.setattr(commands, "_raw_send_apdu", spy)
    commands.switch_crypto(card, f"rsa{bits}", "sig")
    commands.put_key_components(card, "sig", components)

    failures = [(text, sw1, sw2) for text, sw1, sw2 in status_words if (sw1, sw2) != (0x90, 0x00)]
    assert not failures, f"non-9000 during RSA-{bits} import: {failures}"
    return public_key


class TestSmartPGPBasics:

    def test_applet_compiles(self):
        """The 3.0.4 sources (with the rsa-4096 buffer bump) build against jc304_kit."""
        try:
            spec, classes = resolve_applet("smartpgp")
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        assert (classes / "fr/anssi/smartpgp/SmartPGPApplet.class").is_file()

    def test_select(self, smartpgp):
        select(smartpgp)


class TestSmartPGPPins:

    def test_verify_user_pin_both_modes(self, smartpgp):
        from seedsigner.helpers.smartpgp import commands

        select(smartpgp)
        assert verify_user_pin_sign_mode(smartpgp) == (0x90, 0x00)
        # SeedSigner's own helper verifies in decrypt mode.
        _, sw1, sw2 = commands.verif_user_pin(smartpgp, USER_PIN)
        assert (sw1, sw2) == (0x90, 0x00)

    def test_verify_admin_pin(self, smartpgp):
        from seedsigner.helpers.smartpgp import commands

        select(smartpgp)
        _, sw1, sw2 = commands.verif_admin_pin(smartpgp, ADMIN_PIN)
        assert (sw1, sw2) == (0x90, 0x00)

    def test_wrong_pin_rejected(self, smartpgp):
        select(smartpgp)
        assert verify_user_pin_sign_mode(smartpgp, "999999") == (0x69, 0x82)

    def test_three_failures_lock_the_pin_for_good(self, smartpgp):
        """
        Documents the lockout: after three wrong attempts even the correct PIN fails,
        and this SmartPGP version has no unblock command to recover from it.
        """
        select(smartpgp)
        for _ in range(3):
            assert verify_user_pin_sign_mode(smartpgp, "999999") == (0x69, 0x82)
        assert verify_user_pin_sign_mode(smartpgp) == (0x69, 0x82), \
            "correct PIN should be rejected once the reference data is blocked"


class TestSmartPGPSigning:
    """
    Import an off-card-generated RSA key through SeedSigner's real client code and sign
    on-card; the signature is verified off-card with ``cryptography``.

    2048 bits exercises the unpatched buffer size (922 PUT DATA bytes fit in 0x3B0);
    4096 bits only works because source_edits applied SmartPGP's rsa-4096.patch, and its
    512-byte signature is what forces the GET RESPONSE chaining in pso_sign_sha256.
    """

    @pytest.mark.parametrize("bits", [2048, 4096])
    def test_import_and_sign(self, smartpgp, bits, monkeypatch):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        public_key = import_rsa_key(smartpgp, bits, monkeypatch)
        assert verify_user_pin_sign_mode(smartpgp) == (0x90, 0x00), \
            "PSO sign requires the user PIN verified in signing mode"

        message = b"SeedSigner jcardsim SmartPGP test message"
        sig, sw1, sw2 = pso_sign_sha256(smartpgp, message)
        assert (sw1, sw2) == (0x90, 0x00), f"PSO sign failed: {sw1:02X}{sw2:02X}"
        assert len(sig) == bits // 8

        public_key.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
