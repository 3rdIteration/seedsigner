import struct
import base64
from hashlib import sha1, sha256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256

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

def public_key_packet(rsa_key, created: int) -> bytes:
    body = b'\x04' + struct.pack('>I', created) + b'\x01'
    body += mpi(rsa_key.n) + mpi(rsa_key.e)
    return write_packet(6, body)

def secret_key_packet(rsa_key, created: int) -> bytes:
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

def signature_packet(pubkey_pkt: bytes, uid_pkt: bytes, rsa_key, created: int, keyflags: int) -> bytes:
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

def build_key(rsa_key, name: str, email: str, created: int, keyflags: int) -> str:
    pub = public_key_packet(rsa_key, created)
    sec = secret_key_packet(rsa_key, created)
    uid = uid_packet(name, email)
    sig = signature_packet(pub, uid, rsa_key, created, keyflags)
    return armor(sec + uid + sig)
