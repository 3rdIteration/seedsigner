#!/usr/bin/env python3
"""minisign.py - minisign signing/verification in pure Python.

The rootfs tier of air-gapped signing, and the third of the three signature
formats in this boot chain (rkloader.py does the Rockchip loader/idblock,
fitsign.py the U-Boot FITs). Nothing here is reverse-engineered: minisign's
format is published, and this is a re-implementation so that signing and
verification no longer need the vendored x86-64 `minisign-host` binary.

Why re-implement it:

  * The build signs the rootfs with an x86-64 binary, which pins that step to
    the build host. A pure-Python signer runs anywhere, including on a
    SeedSigner acting as the signing appliance.
  * A BIP85-derived key never has to be written to disk. `keygen --entropy`
    turns 32 bytes of BIP85 entropy into the Ed25519 keypair directly, so the
    rootfs key is reproducible from the seed and need not be stored at all.

FORMATS (all base64 bodies, one per line after a comment line):

  public key   sig_alg[2]="Ed" | key_id[8] | public_key[32]
  secret key   sig_alg[2] | kdf_alg[2] | cksum_alg[2] | kdf_salt[32] |
               opslimit[8 LE] | memlimit[8 LE] |
               XOR(scrypt_stream, key_id[8] | secret_key[64] | checksum[32])
               kdf_alg "Sc" = scrypt-encrypted, 0x0000 = not encrypted.
               checksum = BLAKE2b-256(sig_alg | key_id | secret_key)
  signature    sig_alg[2] | key_id[8] | signature[64]
               then a "trusted comment:" line, then
               global_signature[64] = Ed25519(sk, signature | trusted_comment)
               sig_alg "Ed" = signs the message, "ED" = signs its BLAKE2b-512
               (minisign's -H prehashed mode, which is what this build uses:
               it streams the input, so peak memory stays ~64 KiB instead of
               the whole image).

The build signs exactly the first `<image>.size` bytes of the rootfs volume,
because the volume is padded beyond the filesystem image - hence --size.

NOTE on encrypted secret keys: minisign's defaults are opslimit 2^25 and
memlimit 1 GiB, so decrypting one needs about a gigabyte of RAM. That is fine
on a workstation and impossible on a 64-256 MB board, which is another reason
the on-device path should derive its key from entropy rather than decrypt a
stored one.

Pure stdlib (hashlib gives BLAKE2b and scrypt; Ed25519 is implemented here).

  keygen   --entropy <hex|@file> -p <pub> -s <sec> [--comment <c>]
  digest   <file> [--size N] [-o <f>]      BLAKE2b-512 of the signed prefix
  sign     <file> --seckey <f> [--size N] [-t <c>] [-o <f>]
  sign-digest --digest <f> --seckey <f> [-t <c>] -o <f>
  verify   <file> --pubkey <f> [--sig <f>] [--size N]
  keyid    <pub|sec>

Exit codes: 0 ok, 1 usage/IO, 2 verification failed, 3 parse error.
"""
import sys, os, base64, struct, hashlib, argparse

TRUSTED_COMMENT = "seedsigner-os-rootfs"      # fixed: no timestamp, so signatures
                                              # are deterministic and builds stay
                                              # byte-reproducible
ALG_PURE = b"Ed"
ALG_PREHASHED = b"ED"
CHUNK = 64 * 1024


class MsError(Exception):
    pass


# --- Ed25519 (RFC 8032), reference implementation ---------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if (x * x - xx) % _P != 0:
        return None
    if x % 2 != sign:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_B = (_recover_x(_BY, 0), _BY, 1, _recover_x(_BY, 0) * _BY % _P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(p, n):
    q = (0, 1, 1, 0)
    while n > 0:
        if n & 1:
            q = _add(q, p)
        p = _add(p, p)
        n >>= 1
    return q


def _encode_point(p):
    x, y, z, _ = p
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode_point(b):
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        raise MsError("bad Ed25519 public key")
    return (x, y, 1, x * y % _P)


def _secret_expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public(seed):
    a, _ = _secret_expand(seed)
    return _encode_point(_mul(_B, a))


def ed25519_sign(seed, msg):
    a, prefix = _secret_expand(seed)
    pk = _encode_point(_mul(_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    rr = _encode_point(_mul(_B, r))
    k = int.from_bytes(hashlib.sha512(rr + pk + msg).digest(), "little") % _L
    s = (r + k * a) % _L
    return rr + int.to_bytes(s, 32, "little")


def ed25519_verify(pk, msg, sig):
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        a = _decode_point(pk)
        rr = _decode_point(sig[:32])
    except MsError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % _L
    lhs = _mul(_B, s)
    rhs = _add(rr, _mul(a, k))
    return _encode_point(lhs) == _encode_point(rhs)


# --- minisign containers ----------------------------------------------------

def _read_lines(path):
    with open(path, "r") as f:
        return [l.rstrip("\r\n") for l in f]


def _b64(line, path):
    try:
        return base64.b64decode(line, validate=True)
    except Exception:
        raise MsError("%s: expected base64, got %r" % (path, line[:32]))


def load_pubkey(path):
    lines = _read_lines(path)
    if len(lines) < 2:
        raise MsError("%s: not a minisign public key" % path)
    b = _b64(lines[1], path)
    if len(b) != 42 or b[:2] != ALG_PURE:
        raise MsError("%s: unexpected public key (%d bytes, alg %r)" % (path, len(b), b[:2]))
    return {"key_id": b[2:10], "pk": b[10:]}


def _scrypt_params(opslimit, memlimit):
    """libsodium pickparams(): opslimit/memlimit -> scrypt (N, r, p)."""
    r = 8
    if opslimit < 32768:
        opslimit = 32768
    if opslimit < memlimit // 32:
        p = 1
        max_n = opslimit // (r * 4)
    else:
        max_n = memlimit // (r * 128)
    n_log2 = 1
    while n_log2 < 63 and (1 << n_log2) <= max_n // 2:
        n_log2 += 1
    if opslimit >= memlimit // 32:
        maxrp = min((opslimit // 4) // (1 << n_log2), 0x3fffffff)
        p = max(1, maxrp // r)
    return 1 << n_log2, r, p


def load_seckey(path, passphrase=None):
    lines = _read_lines(path)
    if len(lines) < 2:
        raise MsError("%s: not a minisign secret key" % path)
    b = _b64(lines[1], path)
    if len(b) != 158:
        raise MsError("%s: unexpected secret key length %d" % (path, len(b)))
    sig_alg, kdf_alg, cksum_alg = b[0:2], b[2:4], b[4:6]
    salt = b[6:38]
    opslimit, memlimit = struct.unpack("<QQ", b[38:54])
    body = b[54:]
    if kdf_alg == b"\x00\x00":
        stream = b"\x00" * len(body)
    elif kdf_alg == b"Sc":
        if passphrase is None:
            raise MsError("%s is encrypted; pass --passphrase (or use an "
                          "unencrypted / derived key)" % path)
        n, r, p = _scrypt_params(opslimit, memlimit)
        try:
            stream = hashlib.scrypt(passphrase.encode(), salt=salt, n=n, r=r, p=p,
                                    dklen=len(body), maxmem=memlimit + (1 << 20))
        except (ValueError, MemoryError) as e:
            raise MsError("scrypt failed (N=%d r=%d p=%d, needs ~%d MiB): %s"
                          % (n, r, p, memlimit >> 20, e))
    else:
        raise MsError("%s: unknown KDF %r" % (path, kdf_alg))
    dec = bytes(a ^ c for a, c in zip(body, stream))
    key_id, sk, checksum = dec[:8], dec[8:72], dec[72:104]
    want = hashlib.blake2b(sig_alg + key_id + sk, digest_size=32).digest()
    if checksum != want:
        raise MsError("%s: checksum mismatch - wrong passphrase?" % path)
    return {"key_id": key_id, "sk": sk, "seed": sk[:32], "pk": sk[32:]}


def write_pubkey(path, key_id, pk, comment=None):
    body = base64.b64encode(ALG_PURE + key_id + pk).decode()
    c = comment or "minisign public key %s" % key_id[::-1].hex().upper()
    with open(path, "w", newline="\n") as f:
        f.write("untrusted comment: %s\n%s\n" % (c, body))


def write_seckey(path, key_id, sk, comment=None):
    """Written UNENCRYPTED (kdf_alg 0x0000) - see the module note."""
    checksum = hashlib.blake2b(ALG_PURE + key_id + sk, digest_size=32).digest()
    blob = (ALG_PURE + b"\x00\x00" + b"B2" + b"\x00" * 32 +
            struct.pack("<QQ", 0, 0) + key_id + sk + checksum)
    c = comment or "minisign secret key (unencrypted)"
    with open(path, "w", newline="\n") as f:
        f.write("untrusted comment: %s\n%s\n" % (c, base64.b64encode(blob).decode()))


def load_sig(path):
    lines = _read_lines(path)
    if len(lines) < 4:
        raise MsError("%s: not a minisign signature (need 4 lines)" % path)
    b = _b64(lines[1], path)
    if len(b) != 74:
        raise MsError("%s: unexpected signature length %d" % (path, len(b)))
    tc = lines[2]
    if not tc.startswith("trusted comment: "):
        raise MsError("%s: missing 'trusted comment:' line" % path)
    return {"alg": b[:2], "key_id": b[2:10], "sig": b[10:],
            "trusted_comment": tc[len("trusted comment: "):],
            "global_sig": _b64(lines[3], path)}


def write_sig(path, alg, key_id, sig, trusted_comment, global_sig, comment=None):
    c = comment or "signature from minisign secret key"
    with open(path, "w", newline="\n") as f:
        f.write("untrusted comment: %s\n" % c)
        f.write("%s\n" % base64.b64encode(alg + key_id + sig).decode())
        f.write("trusted comment: %s\n" % trusted_comment)
        f.write("%s\n" % base64.b64encode(global_sig).decode())


# --- hashing ----------------------------------------------------------------

def prehash(path, size=None):
    """BLAKE2b-512 over the first `size` bytes, streamed (minisign -H)."""
    h = hashlib.blake2b(digest_size=64)
    remaining = size
    with open(path, "rb") as f:
        while remaining is None or remaining > 0:
            want = CHUNK if remaining is None else min(CHUNK, remaining)
            chunk = f.read(want)
            if not chunk:
                break
            h.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    if remaining:
        raise MsError("%s is shorter than the requested size (%d bytes short)"
                      % (path, remaining))
    return h.digest()


def _size_arg(a):
    """--size N, or read it from <image>.size, which the build writes."""
    if a.size is not None:
        return a.size
    sidecar = a.file + ".size"
    if os.path.exists(sidecar):
        with open(sidecar) as f:
            return int(f.read().strip())
    return None


# --- commands ---------------------------------------------------------------

def _entropy(spec):
    if spec.startswith("@"):
        with open(spec[1:], "rb") as f:
            raw = f.read()
        if len(raw) != 32:
            raw = bytes.fromhex(raw.decode().strip())
    else:
        raw = bytes.fromhex(spec)
    if len(raw) != 32:
        raise MsError("entropy must be exactly 32 bytes (got %d)" % len(raw))
    return raw


def cmd_keygen(a):
    seed = _entropy(a.entropy)
    pk = ed25519_public(seed)
    sk = seed + pk
    # Deterministic key_id, so the same BIP85 entropy always rebuilds the same
    # keypair. minisign -G randomises it; ours must be reproducible.
    key_id = hashlib.blake2b(pk, digest_size=8).digest()
    write_pubkey(a.pub, key_id, pk, a.comment)
    if a.sec:
        write_seckey(a.sec, key_id, sk, a.comment)
    print("public key : %s  (key id %s)" % (a.pub, key_id[::-1].hex().upper()))
    with open(a.pub, "rb") as f:
        print("   sha256  : %s" % hashlib.sha256(f.read()).hexdigest())
    if a.sec:
        print("secret key : %s  (UNENCRYPTED - derived from entropy, so prefer to "
              "delete it and re-derive)" % a.sec)
    return 0


def cmd_digest(a):
    d = prehash(a.file, _size_arg(a))
    if a.out:
        with open(a.out, "wb") as f:
            f.write(d)
        print("wrote %s (%d bytes)" % (a.out, len(d)))
    else:
        print(d.hex())
    return 0


def _sign_with(sk_seed, key_id, digest, trusted_comment):
    sig = ed25519_sign(sk_seed, digest)
    gsig = ed25519_sign(sk_seed, sig + trusted_comment.encode())
    return sig, gsig


def cmd_sign(a):
    key = load_seckey(a.seckey, a.passphrase)
    digest = prehash(a.file, _size_arg(a))
    sig, gsig = _sign_with(key["seed"], key["key_id"], digest, a.trusted_comment)
    out = a.out or (a.file + ".minisig")
    write_sig(out, ALG_PREHASHED, key["key_id"], sig, a.trusted_comment, gsig)
    print("wrote %s" % out)
    return 0


def cmd_sign_digest(a):
    """Air-gapped path: the digest was computed elsewhere."""
    key = load_seckey(a.seckey, a.passphrase)
    with open(a.digest, "rb") as f:
        digest = f.read()
    if len(digest) != 64:
        raise MsError("a prehashed digest must be 64 bytes (BLAKE2b-512), got %d" % len(digest))
    sig, gsig = _sign_with(key["seed"], key["key_id"], digest, a.trusted_comment)
    write_sig(a.out, ALG_PREHASHED, key["key_id"], sig, a.trusted_comment, gsig)
    print("wrote %s" % a.out)
    return 0


def cmd_verify(a):
    pub = load_pubkey(a.pubkey)
    sig = load_sig(a.sig or (a.file + ".minisig"))
    if sig["key_id"] != pub["key_id"]:
        print("FAIL: signature key id %s does not match public key %s"
              % (sig["key_id"][::-1].hex().upper(), pub["key_id"][::-1].hex().upper()))
        return 2
    if sig["alg"] == ALG_PREHASHED:
        msg = prehash(a.file, _size_arg(a))
    elif sig["alg"] == ALG_PURE:
        with open(a.file, "rb") as f:
            msg = f.read()
    else:
        raise MsError("unknown signature algorithm %r" % sig["alg"])
    if not ed25519_verify(pub["pk"], msg, sig["sig"]):
        print("FAIL: %s does not match the signature" % a.file)
        return 2
    if not ed25519_verify(pub["pk"], sig["sig"] + sig["trusted_comment"].encode(),
                          sig["global_sig"]):
        print("FAIL: trusted comment is not authentic")
        return 2
    print("OK: %s verifies (trusted comment: %s)" % (a.file, sig["trusted_comment"]))
    return 0


def cmd_keyid(a):
    try:
        k = load_pubkey(a.file)
    except MsError:
        k = load_seckey(a.file, a.passphrase)
    print(k["key_id"][::-1].hex().upper())
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="minisign.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen")
    g.add_argument("--entropy", required=True, help="32 bytes as hex, or @file")
    g.add_argument("-p", "--pub", required=True)
    g.add_argument("-s", "--sec")
    g.add_argument("--comment")
    g.set_defaults(fn=cmd_keygen)

    d = sub.add_parser("digest")
    d.add_argument("file")
    d.add_argument("--size", type=int, help="bytes to hash (default: read <file>.size)")
    d.add_argument("-o", "--out")
    d.set_defaults(fn=cmd_digest)

    s = sub.add_parser("sign")
    s.add_argument("file")
    s.add_argument("--seckey", required=True)
    s.add_argument("--passphrase")
    s.add_argument("--size", type=int)
    s.add_argument("-t", "--trusted-comment", default=TRUSTED_COMMENT)
    s.add_argument("-o", "--out")
    s.set_defaults(fn=cmd_sign)

    sd = sub.add_parser("sign-digest")
    sd.add_argument("--digest", required=True)
    sd.add_argument("--seckey", required=True)
    sd.add_argument("--passphrase")
    sd.add_argument("-t", "--trusted-comment", default=TRUSTED_COMMENT)
    sd.add_argument("-o", "--out", required=True)
    sd.set_defaults(fn=cmd_sign_digest)

    v = sub.add_parser("verify")
    v.add_argument("file")
    v.add_argument("--pubkey", required=True)
    v.add_argument("--sig")
    v.add_argument("--size", type=int)
    v.set_defaults(fn=cmd_verify)

    k = sub.add_parser("keyid")
    k.add_argument("file")
    k.add_argument("--passphrase")
    k.set_defaults(fn=cmd_keyid)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except MsError as e:
        print("minisign: %s" % e, file=sys.stderr)
        return 3
    except (OSError, IOError) as e:
        print("minisign: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
