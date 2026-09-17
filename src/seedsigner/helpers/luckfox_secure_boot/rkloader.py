#!/usr/bin/env python3
"""rkloader.py - sign/verify the Rockchip loader and idblock offline.

This is the RV1103/RV1106 half of air-gapped signing: the tier that
`rk_sign_tool sl` / `sb` normally does with the private key on the build host.
Everything here is implemented from the on-disk format, so the private key can
live anywhere that can turn 32 bytes into a 256-byte RSA-PSS signature - an
air-gapped machine, a SeedSigner over QR, or a PKCS#11 token.

FORMAT (recovered by scanning a signed image for a window that RSA-verifies to a
structurally valid PSS block, then solving for the hashed region; confirmed
byte-identical on mini/max NAND, mini production and pi eMMC builds):

    <container> ... [ RKNS|RKSS header, 0x600 bytes ][ signature, 256 bytes ] ...
                      ^ hdr                           ^ hdr+0x600

  * idblock.img  - header at 0x000, signature at 0x600.
  * download.bin - a boot_merger "LDR " container; header at 0x1bc, signature
                   at 0x7bc.
  * magic RKNS = unsigned, RKSS = signed (and the u32 at hdr+0x0c 0x01 -> 0x11).
  * signed message = the 0x600 header bytes, hashed with SHA-256, natural order.
  * signature = RSA-PSS, MGF1-SHA256, saltLen 32, stored LITTLE-ENDIAN.
  * the RSA modulus is embedded LITTLE-ENDIAN at hdr+0x200; idblock.img also
    carries a big-endian copy in the SPL DTB's `rsa,modulus`.

Only RSA-2048 is supported, which is not a limitation of this script: the SPL
verify path rejects any other key length with -EINVAL before the BootROM is
reached.

Pure stdlib - no openssl, no rk_sign_tool, no vendor blob. Runs anywhere Python
does, including on-device.

  inspect <img>                       what this file is, and whether it verifies
  digest  <img> [-o <f>]              the 32 bytes to sign (the air-gap boundary)
  splice  <img> --sig <f> [-o <f>]    write an externally-made signature back
  sign    <img> --key <pem> [-o <f>]  sign locally (convenience; key on this host)
  verify  <img> --pubkey <pem>        full offline PSS verification
  setkey  <img> --pubkey <pem> [-o]   re-embed a different public key
  canonicalise <img> [-o <f>]         zero the signature + key, for rebuild diffs

Exit codes: 0 ok, 1 usage/IO, 2 verification failed, 3 parse error.
"""
import sys, os, struct, hashlib, argparse, base64

HDR_LEN  = 0x600           # signed header, and the offset of the signature after it
SIG_LEN  = 256             # rsa2048
MOD_OFF  = 0x200           # modulus offset inside the header, little-endian
SALT_LEN = 32              # recovered: equal to hLen
MAGIC_UNSIGNED = b"RKNS"
MAGIC_SIGNED   = b"RKSS"


class RkError(Exception):
    pass


# --- container layout -------------------------------------------------------

def find_header(buf):
    """Return (hdr_offset, magic). Checks the two known layouts, then scans."""
    for off in (0x0, 0x1bc):
        if bytes(buf[off:off + 4]) in (MAGIC_UNSIGNED, MAGIC_SIGNED):
            return off, bytes(buf[off:off + 4])
    for magic in (MAGIC_SIGNED, MAGIC_UNSIGNED):
        off = bytes(buf).find(magic, 0, 0x10000)
        if off >= 0:
            return off, magic
    raise RkError("no RKNS/RKSS header found (not a Rockchip loader or idblock?)")


def layout(buf):
    hdr, magic = find_header(buf)
    if len(buf) < hdr + HDR_LEN + SIG_LEN:
        raise RkError("file too short for a 0x600 header + 256-byte signature at 0x%x" % hdr)
    return {
        "hdr": hdr,
        "magic": magic.decode("ascii"),
        "signed": magic == MAGIC_SIGNED,
        "msg": (hdr, HDR_LEN),
        "sig": (hdr + HDR_LEN, SIG_LEN),
        "mod": (hdr + MOD_OFF, SIG_LEN),
    }


def msg_digest(buf, lay):
    off, ln = lay["msg"]
    return hashlib.sha256(bytes(buf[off:off + ln])).digest()


def read_sig(buf, lay):
    off, ln = lay["sig"]
    return int.from_bytes(bytes(buf[off:off + ln]), "little")


def read_modulus(buf, lay):
    off, ln = lay["mod"]
    return int.from_bytes(bytes(buf[off:off + ln]), "little")


# --- DER / PEM (stdlib only) ------------------------------------------------

def _der_ints(der):
    """Collect every INTEGER in a DER blob, descending into SEQUENCE/BIT STRING."""
    out = []

    def walk(buf):
        i = 0
        while i < len(buf):
            tag = buf[i]; i += 1
            ln = buf[i]; i += 1
            if ln & 0x80:
                nb = ln & 0x7f
                ln = int.from_bytes(buf[i:i + nb], "big"); i += nb
            val = buf[i:i + ln]; i += ln
            if tag == 0x30:
                walk(val)
            elif tag == 0x03:
                walk(val[1:])          # BIT STRING: skip the unused-bits byte
            elif tag == 0x04:
                try:
                    walk(val)          # OCTET STRING: PKCS#8 wraps the key here
                except Exception:
                    pass
            elif tag == 0x02:
                out.append(int.from_bytes(val, "big"))
    walk(der)
    return out


def _pem_der(path):
    with open(path) as f:
        body = "".join(l.strip() for l in f if "-----" not in l)
    try:
        return base64.b64decode(body)
    except Exception as e:
        raise RkError("%s is not valid PEM: %s" % (path, e))


def load_pubkey(path):
    ints = [i for i in _der_ints(_pem_der(path)) if i.bit_length() > 1000]
    if not ints:
        raise RkError("no RSA modulus found in %s" % path)
    n = ints[0]
    if n.bit_length() != 2048:
        raise RkError("modulus is %d bits; this chain is RSA-2048 only" % n.bit_length())
    return n, 65537


def load_privkey(path):
    """PKCS#1 or PKCS#8 RSA private key -> (n, e, d)."""
    big = [i for i in _der_ints(_pem_der(path)) if i.bit_length() > 1000]
    if len(big) < 2:
        raise RkError("no RSA private key found in %s (is it a public key?)" % path)
    n, d = big[0], big[1]
    if n.bit_length() != 2048:
        raise RkError("modulus is %d bits; this chain is RSA-2048 only" % n.bit_length())
    if pow(pow(0xdeadbeef, 65537, n), d, n) != 0xdeadbeef:
        raise RkError("key self-test failed - could not read a consistent (n, d) from %s" % path)
    return n, 65537, d


# --- RSA-PSS (RFC 8017), MGF1-SHA256, saltLen 32 ----------------------------

def _mgf1(seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + struct.pack(">I", counter)).digest()
        counter += 1
    return out[:length]


def pss_encode(mhash, embits=2047, salt=None):
    """EMSA-PSS-ENCODE. salt=None -> random; pass bytes for a deterministic test."""
    hlen, emlen = 32, (embits + 7) // 8
    if salt is None:
        salt = os.urandom(SALT_LEN)
    h = hashlib.sha256(b"\x00" * 8 + mhash + salt).digest()
    ps_len = emlen - len(salt) - hlen - 2
    if ps_len < 0:
        raise RkError("salt too long for this modulus")
    db = b"\x00" * ps_len + b"\x01" + salt
    masked = bytes(a ^ b for a, b in zip(db, _mgf1(h, len(db))))
    # clear the leftmost 8*emLen - emBits bits
    masked = bytes([masked[0] & (0xff >> (8 * emlen - embits))]) + masked[1:]
    return masked + h + b"\xbc"


def pss_verify(mhash, em, embits=2047):
    hlen, emlen = 32, (embits + 7) // 8
    if len(em) != emlen or em[-1] != 0xbc:
        return False
    masked, h = em[:emlen - hlen - 1], em[emlen - hlen - 1:-1]
    if masked[0] & ~(0xff >> (8 * emlen - embits)) & 0xff:
        return False
    db = bytes(a ^ b for a, b in zip(masked, _mgf1(h, len(masked))))
    db = bytes([db[0] & (0xff >> (8 * emlen - embits))]) + db[1:]
    i = 0
    while i < len(db) and db[i] == 0:
        i += 1
    if i >= len(db) or db[i] != 0x01:
        return False
    salt = db[i + 1:]
    return hashlib.sha256(b"\x00" * 8 + mhash + salt).digest() == h


def rsa_sign_digest(mhash, n, d, salt=None):
    """32-byte SHA-256 digest -> 256-byte signature, little-endian as stored."""
    em = pss_encode(mhash, n.bit_length() - 1, salt)
    s = pow(int.from_bytes(em, "big"), d, n)
    return s.to_bytes(SIG_LEN, "little")


def rsa_verify_digest(mhash, sig_int, n, e=65537):
    if sig_int >= n:
        return False
    return pss_verify(mhash, pow(sig_int, e, n).to_bytes(SIG_LEN, "big"), n.bit_length() - 1)


# --- helpers ----------------------------------------------------------------

def read(path):
    with open(path, "rb") as f:
        return bytearray(f.read())


def write_out(buf, src, out):
    dst = out or src
    with open(dst, "wb") as f:
        f.write(buf)
    return dst


def prepare_for_signing(buf, lay):
    """RKNS -> RKSS, and set 0x10 in the flag word at hdr+0x0c. Idempotent.

    Both fields live INSIDE the 0x600-byte signed header, so this must happen
    BEFORE the digest is taken - the vendor tool signs the header in its final,
    already-marked form (every shipped signed image carries RKSS inside its own
    signed region). Marking afterwards silently produces a signature over the
    wrong bytes.
    """
    hdr = lay["hdr"]
    buf[hdr:hdr + 4] = MAGIC_SIGNED
    flag = struct.unpack_from("<I", bytes(buf), hdr + 0x0c)[0]
    struct.pack_into("<I", buf, hdr + 0x0c, flag | 0x10)


def signing_digest(buf, lay):
    """The 32 bytes actually signed: sha256 over the header in its marked form."""
    tmp = bytearray(buf)
    prepare_for_signing(tmp, lay)
    return msg_digest(tmp, lay)


# --- commands ---------------------------------------------------------------

def cmd_inspect(a):
    buf = read(a.image)
    lay = layout(buf)
    n = read_modulus(buf, lay)
    print("== %s" % a.image)
    print("   container      : %s" % ("boot_merger 'LDR ' loader" if lay["hdr"] else "raw idblock"))
    print("   header         : 0x%x .. 0x%x  (magic %s, %s)"
          % (lay["hdr"], lay["hdr"] + HDR_LEN, lay["magic"],
             "SIGNED" if lay["signed"] else "unsigned"))
    print("   signature      : 0x%x .. 0x%x" % (lay["sig"][0], lay["sig"][0] + SIG_LEN))
    print("   sha256(header) : %s%s" % (signing_digest(buf, lay).hex(),
                                    "" if lay["signed"] else "  (as it will be once marked signed)"))
    if n:
        print("   embedded key   : %d-bit, modulus sha256 %s"
              % (n.bit_length(), hashlib.sha256(n.to_bytes(SIG_LEN, "big")).hexdigest()))
        ok = rsa_verify_digest(msg_digest(buf, lay), read_sig(buf, lay), n)
        print("   self-check     : %s" % ("VALID (signed by the embedded key)" if ok
                                          else "no valid signature for the embedded key"))
    else:
        print("   embedded key   : none (all-zero modulus)")
    return 0


def cmd_digest(a):
    buf = read(a.image)
    d = signing_digest(buf, layout(buf))
    if a.out:
        with open(a.out, "wb") as f:
            f.write(d)
        print("wrote %s (%d bytes)" % (a.out, len(d)))
    else:
        print(d.hex())
    return 0


def cmd_splice(a):
    buf = read(a.image)
    lay = layout(buf)
    with open(a.sig, "rb") as f:
        sig = f.read()
    if len(sig) in (SIG_LEN * 2, SIG_LEN * 2 + 1):
        sig = bytes.fromhex(sig.decode().strip())          # accept hex too
    if len(sig) != SIG_LEN:
        raise RkError("signature must be %d bytes, got %d" % (SIG_LEN, len(sig)))
    if a.big_endian:
        sig = sig[::-1]
    prepare_for_signing(buf, lay)
    off, _ = lay["sig"]
    buf[off:off + SIG_LEN] = sig
    n = read_modulus(buf, lay)
    if not n:
        raise RkError("this image embeds no public key (all-zero modulus): run setkey "
                      "with your pubkey before splicing, or the signature is unverifiable "
                      "on-device")
    if not rsa_verify_digest(msg_digest(buf, lay), int.from_bytes(sig, "little"), n):
        raise RkError("spliced signature does NOT verify against the embedded key - "
                      "wrong key, wrong endianness (try --big-endian), or wrong digest")
    dst = write_out(buf, a.image, a.out)
    print("spliced signature into %s (verified against the embedded key)" % dst)
    return 0


def sign_buf(buf, lay, n, d):
    """Sign an in-memory image. Returns the 256-byte little-endian signature.

    The library entry point: callers holding a key in memory (a BIP85-derived
    key on a SeedSigner, say) must never have to write it to disk.
    """
    prepare_for_signing(buf, lay)
    sig = rsa_sign_digest(msg_digest(buf, lay), n, d)
    off, _ = lay["sig"]
    buf[off:off + SIG_LEN] = sig
    if not rsa_verify_digest(msg_digest(buf, lay), int.from_bytes(sig, "little"), n):
        raise RkError("internal error: freshly made signature does not verify")
    return sig


def set_pubkey(buf, lay, n):
    """Re-embed public key `n`, clearing the now-meaningless signature.

    Returns the number of locations rewritten. Also updates the big-endian copy
    in idblock's SPL DTB and the derived Montgomery constants.
    """
    old = read_modulus(buf, lay)
    off, _ = lay["mod"]
    buf[off:off + SIG_LEN] = n.to_bytes(SIG_LEN, "little")
    replaced = 1
    if old:
        old_be = old.to_bytes(SIG_LEN, "big")
        new_be = n.to_bytes(SIG_LEN, "big")
        at = bytes(buf).find(old_be)
        while at >= 0:
            buf[at:at + SIG_LEN] = new_be
            replaced += 1
            at = bytes(buf).find(old_be, at + SIG_LEN)
        old_n0 = (-pow(old, -1, 1 << 32)) % (1 << 32)
        new_n0 = (-pow(n, -1, 1 << 32)) % (1 << 32)
        at = bytes(buf).find(struct.pack(">I", old_n0))
        if at >= 0:
            struct.pack_into(">I", buf, at, new_n0)
            replaced += 1
        old_r2 = pow(2, 2 * 2048, old).to_bytes(SIG_LEN, "big")
        new_r2 = pow(2, 2 * 2048, n).to_bytes(SIG_LEN, "big")
        at = bytes(buf).find(old_r2)
        if at >= 0:
            buf[at:at + SIG_LEN] = new_r2
            replaced += 1
    soff, _ = lay["sig"]
    buf[soff:soff + SIG_LEN] = b"\x00" * SIG_LEN
    buf[lay["hdr"]:lay["hdr"] + 4] = MAGIC_UNSIGNED
    return replaced


def cmd_sign(a):
    buf = read(a.image)
    lay = layout(buf)
    n, e, d = load_privkey(a.key)
    emb = read_modulus(buf, lay)
    if not emb and not a.force:
        raise RkError("this image embeds no public key (all-zero modulus), so nothing "
                      "on-device could verify the signature. Run "
                      "'rkloader.py setkey %s --pubkey <your pubkey.pem>' first, "
                      "or pass --force to sign anyway." % a.image)
    if emb and emb != n and not a.force:
        raise RkError("the image embeds a different public key than %s - "
                      "run setkey first, or pass --force" % a.key)
    if a.force and emb != n:
        print("!! signing with a key that does not match the embedded modulus (--force)")
    sign_buf(buf, lay, n, d)
    dst = write_out(buf, a.image, a.out)
    print("signed %s (verified)" % dst)
    return 0


def cmd_verify(a):
    buf = read(a.image)
    lay = layout(buf)
    n = load_pubkey(a.pubkey)[0] if a.pubkey else read_modulus(buf, lay)
    if not n:
        print("FAIL: no key to verify against")
        return 2
    emb = read_modulus(buf, lay)
    if a.pubkey and emb and emb != n:
        print("!! WARNING: the image embeds a DIFFERENT key than %s" % a.pubkey)
    if rsa_verify_digest(msg_digest(buf, lay), read_sig(buf, lay), n):
        print("OK: %s carries a valid RSA-PSS signature over its 0x600-byte header" % a.image)
        return 0
    print("FAIL: %s does not verify" % a.image)
    return 2


def cmd_setkey(a):
    """Re-embed a different public key. See the warning printed at the end."""
    buf = read(a.image)
    lay = layout(buf)
    n = load_pubkey(a.pubkey)[0]
    replaced = set_pubkey(buf, lay, n)
    dst = write_out(buf, a.image, a.out)
    print("re-embedded key in %s (%d location(s)); signature cleared - sign it next" % (dst, replaced))
    print("   new modulus sha256: %s" % hashlib.sha256(n.to_bytes(SIG_LEN, "big")).hexdigest())
    print("!! setkey rewrites fields that are NOT fully characterised. Verify on a")
    print("!! SACRIFICIAL, UNFUSED board before trusting it. Nothing here burns a fuse.")
    return 0


def cmd_canonicalise(a):
    """Zero every byte a rebuild cannot reproduce: the signature and the key.

    What is left is key-independent, so a release and a reproducible rebuild
    should canonicalise to identical bytes.
    """
    buf = read(a.image)
    lay = layout(buf)
    soff, _ = lay["sig"]
    moff, _ = lay["mod"]
    n = read_modulus(buf, lay)
    buf[soff:soff + SIG_LEN] = b"\x00" * SIG_LEN
    buf[moff:moff + SIG_LEN] = b"\x00" * SIG_LEN
    zeroed = 1
    # idblock.img also carries the key big-endian in its SPL DTB, plus the
    # derived Montgomery constants. All of them are key-dependent, so all of
    # them have to go or two images signed with different keys will not
    # canonicalise to the same bytes.
    if n:
        for blob in (n.to_bytes(SIG_LEN, "big"),
                     pow(2, 2 * 2048, n).to_bytes(SIG_LEN, "big")):
            at = bytes(buf).find(blob)
            while at >= 0:
                buf[at:at + SIG_LEN] = b"\x00" * SIG_LEN
                zeroed += 1
                at = bytes(buf).find(blob, at + SIG_LEN)
        n0 = struct.pack(">I", (-pow(n, -1, 1 << 32)) % (1 << 32))
        at = bytes(buf).find(n0)
        if at >= 0:
            struct.pack_into(">I", buf, at, 0)
            zeroed += 1
    buf[lay["hdr"]:lay["hdr"] + 4] = MAGIC_UNSIGNED
    dst = write_out(buf, a.image, a.out)
    print("canonicalised %s" % dst)
    print("   zeroed the signature and %d key-dependent field(s)" % zeroed)
    print("   sha256: %s" % hashlib.sha256(bytes(buf)).hexdigest())
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="rkloader.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, *, key=False, pub=False, sig=False, out=False):
        sp = sub.add_parser(name)
        sp.add_argument("image")
        if key:
            sp.add_argument("--key", required=True, help="RSA private key PEM")
        if pub:
            sp.add_argument("--pubkey", required=(name == "setkey"), help="RSA public key PEM")
        if sig:
            sp.add_argument("--sig", required=True, help="256-byte (or hex) signature file")
            sp.add_argument("--big-endian", action="store_true",
                            help="the signature file is big-endian; byte-swap it on the way in")
        if out:
            sp.add_argument("-o", "--out", help="write here instead of in place")
        sp.set_defaults(fn=fn)
        return sp

    add("inspect", cmd_inspect)
    d = sub.add_parser("digest")
    d.add_argument("image")
    d.add_argument("-o", "--out", help="write the raw 32 bytes here")
    d.set_defaults(fn=cmd_digest)
    add("splice", cmd_splice, sig=True, out=True)
    sp = add("sign", cmd_sign, key=True, out=True)
    sp.add_argument("--force", action="store_true", help="sign even if the embedded key differs")
    add("verify", cmd_verify, pub=True)
    add("setkey", cmd_setkey, pub=True, out=True)
    add("canonicalise", cmd_canonicalise, out=True)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except RkError as e:
        print("rkloader: %s" % e, file=sys.stderr)
        return 3
    except (OSError, IOError) as e:
        print("rkloader: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
