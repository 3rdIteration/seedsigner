import logging
from subprocess import run

from typing import Iterable, Optional

import pgpy
from pgpy.constants import KeyFlags, EllipticCurveOID

from seedsigner.helpers.smartpgp.highlevel import CardConnectionContext

logger = logging.getLogger(__name__)

_curve_map = {
    EllipticCurveOID.NIST_P256: 'P-256',
    EllipticCurveOID.NIST_P384: 'P-384',
    EllipticCurveOID.NIST_P521: 'P-521',
    EllipticCurveOID.Brainpool_P256: 'brainpoolP256r1',
    EllipticCurveOID.Brainpool_P384: 'brainpoolP384r1',
    EllipticCurveOID.Brainpool_P512: 'brainpoolP512r1',
}


def import_keys_with_smartpgp(
    fingerprint: str,
    admin_pin: str,
    subkeys: Optional[Iterable[str]] = None,
) -> bool:
    """Fallback key import using the bundled SmartPGP module.

    Parameters
    ----------
    fingerprint: str
        Fingerprint of the key to import.
    admin_pin: str
        Admin PIN for the OpenPGP card.
    subkeys: Iterable[str], optional
        Iterable of subkey fingerprints to include.  When provided, only those
        subkeys are exported and imported; otherwise the entire key is used.
    """
    try:
        if subkeys:
            keyids = [f[-16:] + "!" for f in subkeys]
            cmd = [
                'gpg',
                '--armor',
                '--export-options=export-minimal',
                '--export-secret-subkeys',
                fingerprint,
                *keyids,
            ]
        else:
            cmd = ['gpg', '--export-secret-key', fingerprint]
        res = run(cmd, capture_output=True, check=True)
        key, _ = pgpy.PGPKey.from_blob(res.stdout)
    except Exception as e:
        logger.exception('Failed to export key for SmartPGP import: %s', e)
        return False

    ctx = CardConnectionContext()
    ctx.admin_pin = admin_pin
    try:
        ctx.connect()
        ctx.verify_admin_pin()
    except Exception as e:
        logger.exception('SmartPGP connection failed: %s', e)
        return False

    # OpenPGP cards are normally loaded with the signing/encryption/auth
    # **sub**keys rather than the primary certification key.  Importing the
    # primary key can confuse GnuPG's card interface.  Restrict the import to
    # subkeys when they exist; fall back to the primary key only if no subkeys
    # are present.  If a list of desired subkey fingerprints was supplied,
    # further trim the set to only those subkeys.
    all_keys = list(key.subkeys.values())
    if subkeys:
        wanted = {f.replace(' ', '').upper() for f in subkeys}
        all_keys = [k for k in all_keys if str(k.fingerprint).replace(' ', '').upper() in wanted]
    if not all_keys:
        all_keys = [key]
    fp_tags = {'sig': 0xC7, 'dec': 0xC8, 'auth': 0xC9}
    # Key generation timestamps are stored in individual DOs for each key
    # slot.  The previous implementation accidentally wrote the signature's
    # timestamp to ``0xCD`` which actually refers to the *combined* "key
    # generation dates" structure.  Aside from leaving the per-slot DOs empty,
    # that corrupted the aggregate record and confused OpenPGP clients when
    # they queried the card.  Use the correct tags for each key instead.
    ts_tags = {'sig': 0xCE, 'dec': 0xCF, 'auth': 0xD0}
    size_map = {
        'P-256': 32,
        'P-384': 48,
        'P-521': 66,
        'brainpoolP256r1': 32,
        'brainpoolP384r1': 48,
        'brainpoolP512r1': 64,
    }

    for k in all_keys:
        try:
            flags = set(k.key_flags)  # pgpy <0.6
        except AttributeError:
            # pgpy 0.6 dropped the ``key_flags`` attribute; rely on the internal
            # helper instead so we still detect the proper key usages
            flags = set(k._get_key_flags())
        role = None
        if KeyFlags.Sign in flags:
            role = 'sig'
        elif KeyFlags.EncryptCommunications in flags or KeyFlags.EncryptStorage in flags:
            role = 'dec'
        elif KeyFlags.Authentication in flags:
            role = 'auth'
        if role is None:
            continue
        km = k._key.keymaterial
        curve_name = _curve_map.get(km.oid)
        if not curve_name:
            logger.error('Unsupported curve %s', km.oid)
            return False
        size = size_map.get(curve_name)
        if not size:
            logger.error('No size mapping for curve %s', curve_name)
            return False
        try:
            priv = km.s.to_bytes(size, 'big')
            point = km.p
            pub = b'\x04' + point.x.to_bytes(size, 'big') + point.y.to_bytes(size, 'big')
            ctx.cmd_switch_crypto(curve_name, role)
            ctx.cmd_put_key(role, pub, priv)
            fp = bytes.fromhex(str(k.fingerprint).replace(' ', ''))
            ts = int(k.created.timestamp()).to_bytes(4, 'big')
            ctx.cmd_put_data(fp_tags[role], fp)
            ctx.cmd_put_data(ts_tags[role], ts)
        except Exception as e:
            logger.exception('Failed to import %s key via SmartPGP: %s', role, e)
            return False
    return True
