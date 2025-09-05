import logging
from subprocess import run

import pgpy
from pgpy.constants import KeyFlags

from seedsigner.helpers.smartpgp.highlevel import CardConnectionContext

logger = logging.getLogger(__name__)

_curve_map = {
    'NIST_P256': 'P-256',
    'NIST_P384': 'P-384',
    'NIST_P521': 'P-521',
    'BRAINPOOLP256R1': 'brainpoolP256r1',
    'BRAINPOOLP384R1': 'brainpoolP384r1',
    'BRAINPOOLP512R1': 'brainpoolP512r1',
}


def import_keys_with_smartpgp(fingerprint: str, admin_pin: str) -> bool:
    """Fallback key import using the bundled SmartPGP module.

    Parameters
    ----------
    fingerprint: str
        Fingerprint of the key to import.
    admin_pin: str
        Admin PIN for the OpenPGP card.
    """
    try:
        res = run(['gpg', '--export-secret-key', fingerprint], capture_output=True, check=True)
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
    # are present.
    all_keys = list(key.subkeys.values())
    if not all_keys:
        all_keys = [key]
    fp_tags = {'sig': 0xC7, 'dec': 0xC8, 'auth': 0xC9}
    ts_tags = {'sig': 0xCD, 'dec': 0xCE, 'auth': 0xCF}
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
        curve_name = _curve_map.get(km.oid.name.upper())
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
