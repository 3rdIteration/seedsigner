import struct
import base64
from hashlib import sha1, sha256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from embit.ec import PrivateKey

POLY = 0x1864CFB
INIT = 0xB704CE

def crc24(data: bytes) -> int:
    crc = INIT
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= POLY
    return crc & 0xFFFFFF

def mpi(n: int) -> bytes:
    bitlen = n.bit_length()
    bytelen = (bitlen + 7) // 8
    return struct.pack('>H', bitlen) + n.to_bytes(bytelen, 'big')

def write_packet(tag: int, body: bytes) -> bytes:
    if len(body) < 192:
        hdr = bytes([0xC0 | tag, len(body)])
    elif len(body) < 8384:
        l = len(body) - 192
        hdr = bytes([0xC0 | tag, 192 + (l >> 8), l & 0xFF])
    else:
        hdr = bytes([0xC0 | tag, 255]) + struct.pack('>I', len(body))
    return hdr + body

def rsa_public_key_packet(rsa_key, created: int) -> bytes:
    body = b'\x04' + struct.pack('>I', created) + b'\x01'
    body += mpi(rsa_key.n) + mpi(rsa_key.e)
    return write_packet(6, body)


def rsa_secret_key_packet(rsa_key, created: int) -> bytes:
    body = b'\x04' + struct.pack('>I', created) + b'\x01'
    body += mpi(rsa_key.n) + mpi(rsa_key.e)
    body += mpi(rsa_key.d) + mpi(rsa_key.p) + mpi(rsa_key.q)
    u = pow(rsa_key.p, -1, rsa_key.q)
    body += mpi(u)
    chk = sum(body[6:]) % 65536
    body += struct.pack('>H', chk)
    return write_packet(5, body)

def uid_packet(name: str, email: str) -> bytes:
    uid = f"{name} <{email}>".encode()
    return write_packet(13, uid)

def subpacket(subtype: int, data: bytes) -> bytes:
    l = len(data) + 1
    return bytes([l, subtype]) + data

def rsa_signature_packet(pubkey_pkt: bytes, uid_pkt: bytes, rsa_key, created: int, keyflags: int) -> bytes:
    sig_type = 0x13
    pk_alg = 1
    hash_alg = 8  # SHA256
    hashed_subs = b''.join([
        subpacket(2, struct.pack('>I', created)),
        subpacket(27, bytes([keyflags])),
        subpacket(11, b'\x09'),
        subpacket(21, b'\x08'),
        subpacket(22, b'\x02'),
        subpacket(30, b'\x01'),
    ])
    pubkey_body = pubkey_pkt[pubkey_pkt[0] & 0x3F + 1:]
    fingerprint = sha1(pubkey_body).digest()
    hashed_subs += subpacket(33, b'\x04' + fingerprint)
    hashed_len = struct.pack('>H', len(hashed_subs))
    keyid = fingerprint[-8:]
    unhashed_subs = subpacket(16, keyid)
    unhashed_len = struct.pack('>H', len(unhashed_subs))
    sig_head = bytes([4, sig_type, pk_alg, hash_alg])
    to_hash = b'\x99' + struct.pack('>H', len(pubkey_body)) + pubkey_body
    uid_body = uid_pkt[uid_pkt[0] & 0x3F + 1:]
    to_hash += b'\xb4' + struct.pack('>I', len(uid_body)) + uid_body
    hashed_part = sig_head + hashed_len + hashed_subs
    trailer = bytes([4, 0xFF]) + struct.pack('>I', len(hashed_part))
    h = SHA256.new(to_hash + hashed_part + trailer)
    sig = pkcs1_15.new(rsa_key).sign(h)
    return write_packet(2, sig_head + hashed_len + hashed_subs + unhashed_len + unhashed_subs + h.digest()[:2] + mpi(int.from_bytes(sig, 'big')))

def armor(data: bytes) -> str:
    b64 = base64.b64encode(data).decode()
    crc = base64.b64encode(crc24(data).to_bytes(3, 'big')).decode()
    wrapped = '\n'.join([b64[i:i+64] for i in range(0, len(b64), 64)])
    return '-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n' + wrapped + f"\n={crc}\n-----END PGP PRIVATE KEY BLOCK-----\n"


def build_rsa_key(rsa_key, name: str, email: str, created: int, keyflags: int) -> str:
    pub = rsa_public_key_packet(rsa_key, created)
    sec = rsa_secret_key_packet(rsa_key, created)
    uid = uid_packet(name, email)
    sig = rsa_signature_packet(pub, uid, rsa_key, created, keyflags)
    return armor(sec + uid + sig)


SECP256K1_OID = b"\x2b\x81\x04\x00\x0a"


def secp256k1_public_key_packet(key: PrivateKey, created: int) -> bytes:
    point = key.get_public_key().sec(compressed=False)
    body = b"\x04" + struct.pack(">I", created) + b"\x13"
    body += bytes([len(SECP256K1_OID)]) + SECP256K1_OID
    body += bytes([len(point)]) + point
    return write_packet(6, body)


def secp256k1_secret_key_packet(key: PrivateKey, created: int) -> bytes:
    point = key.get_public_key().sec(compressed=False)
    body = b"\x04" + struct.pack(">I", created) + b"\x13"
    body += bytes([len(SECP256K1_OID)]) + SECP256K1_OID
    body += bytes([len(point)]) + point
    body += b"\x00"  # no encryption
    secret = mpi(int.from_bytes(key.secret, "big"))
    body += secret
    chk = sum(secret) % 65536
    body += struct.pack(">H", chk)
    return write_packet(5, body)


def secp256k1_signature_packet(pubkey_pkt: bytes, uid_pkt: bytes, key: PrivateKey, created: int, keyflags: int) -> bytes:
    sig_type = 0x13
    pk_alg = 19
    hash_alg = 8  # SHA256
    hashed_subs = b"".join([
        subpacket(2, struct.pack(">I", created)),
        subpacket(27, bytes([keyflags])),
        subpacket(11, b"\x09"),
        subpacket(21, b"\x08"),
        subpacket(22, b"\x02"),
        subpacket(30, b"\x01"),
    ])
    pubkey_body = pubkey_pkt[pubkey_pkt[0] & 0x3F + 1:]
    fingerprint = sha1(pubkey_body).digest()
    hashed_subs += subpacket(33, b"\x04" + fingerprint)
    hashed_len = struct.pack(">H", len(hashed_subs))
    keyid = fingerprint[-8:]
    unhashed_subs = subpacket(16, keyid)
    unhashed_len = struct.pack(">H", len(unhashed_subs))
    sig_head = bytes([4, sig_type, pk_alg, hash_alg])
    to_hash = b"\x99" + struct.pack(">H", len(pubkey_body)) + pubkey_body
    uid_body = uid_pkt[uid_pkt[0] & 0x3F + 1:]
    to_hash += b"\xb4" + struct.pack(">I", len(uid_body)) + uid_body
    hashed_part = sig_head + hashed_len + hashed_subs
    trailer = bytes([4, 0xFF]) + struct.pack(">I", len(hashed_part))
    digest = sha256(to_hash + hashed_part + trailer).digest()
    sig = key.sign(digest)._sig
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    return write_packet(
        2,
        sig_head
        + hashed_len
        + hashed_subs
        + unhashed_len
        + unhashed_subs
        + digest[:2]
        + mpi(r)
        + mpi(s),
    )


def build_secp256k1_key(key: PrivateKey, name: str, email: str, created: int, keyflags: int) -> str:
    pub = secp256k1_public_key_packet(key, created)
    sec = secp256k1_secret_key_packet(key, created)
    uid = uid_packet(name, email)
    sig = secp256k1_signature_packet(pub, uid, key, created, keyflags)
    return armor(sec + uid + sig)


# backwards compatibility
def build_key(*args, **kwargs):  # pragma: no cover - legacy alias
    return build_rsa_key(*args, **kwargs)
