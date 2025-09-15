import logging
from subprocess import run

from typing import Iterable, Optional

import pgpy
from pgpy.constants import KeyFlags, EllipticCurveOID

from seedsigner.helpers.smartpgp.highlevel import CardConnectionContext, AdminPINFailed

logger = logging.getLogger(__name__)

_curve_map = {
    EllipticCurveOID.NIST_P256: 'P-256',
    EllipticCurveOID.NIST_P384: 'P-384',
    EllipticCurveOID.NIST_P521: 'P-521',
    EllipticCurveOID.Brainpool_P256: 'brainpoolP256r1',
    EllipticCurveOID.Brainpool_P384: 'brainpoolP384r1',
    EllipticCurveOID.Brainpool_P512: 'brainpoolP512r1',
}

_rsa_alg_map = {
    2048: 'rsa2048',
    3072: 'rsa3072',
    4096: 'rsa4096',
}


class SmartPGPAdminPinError(Exception):
    """Raised when SmartPGP admin PIN verification fails."""


def import_keys_with_smartpgp(
    fingerprint: str,
    admin_pin: str,
    subkeys: Optional[Iterable[str] | dict[str, str]] = None,
) -> bool:
    """Fallback key import using the bundled SmartPGP module.

    Parameters
    ----------
    fingerprint: str
        Fingerprint of the key to import.
    admin_pin: str
        Admin PIN for the OpenPGP card.
    subkeys: Iterable[str] | dict[str, str], optional
        Iterable or mapping of subkey fingerprints to include.  When provided,
        only those subkeys are exported and imported; otherwise the entire key
        is used.  When a mapping is supplied, the keys should be ``'s'``,
        ``'e'``, or ``'a'`` to denote the desired card slot.
    """
    try:
        if subkeys:
            if isinstance(subkeys, dict):
                fprs = list(subkeys.values())
                selection_repr = {k: v for k, v in subkeys.items() if v}
            else:
                fprs = list(subkeys)
                selection_repr = fprs
            logger.info(
                'Exporting SmartPGP subkeys for %s: %s',
                fingerprint,
                selection_repr,
            )
            keyids = [f[-16:] + "!" for f in fprs]
            cmd = [
                'gpg',
                '--armor',
                '--export-options=export-minimal',
                '--export-secret-subkeys',
                fingerprint,
                *keyids,
            ]
        else:
            logger.info('Exporting full private key %s for SmartPGP import', fingerprint)
            cmd = ['gpg', '--export-secret-key', fingerprint]
        logger.debug('Running command to export key material: %s', cmd)
        res = run(cmd, capture_output=True, check=True)
        key, _ = pgpy.PGPKey.from_blob(res.stdout)
    except Exception as e:
        logger.exception('Failed to export key for SmartPGP import: %s', e)
        return False

    ctx = CardConnectionContext()
    ctx.admin_pin = admin_pin
    try:
        logger.info('Connecting to SmartPGP card for fallback import')
        ctx.connect()
        logger.info('Verifying SmartPGP admin PIN before import')
        ctx.verify_admin_pin()
    except AdminPINFailed as e:
        logger.warning('SmartPGP admin PIN verification failed')
        raise SmartPGPAdminPinError from e
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
    logger.info('Exported key contains %d subkeys', len(all_keys))
    if subkeys:
        if isinstance(subkeys, dict):
            selected = []
            for flag in ('s', 'e', 'a'):
                fpr = subkeys.get(flag)
                if not fpr:
                    continue
                for k in all_keys:
                    if str(k.fingerprint).replace(' ', '').upper() == fpr.replace(' ', '').upper():
                        selected.append((flag, k))
                        break
            logger.info('Subkey mapping for SmartPGP import: %s', selected)
            all_keys = selected
        else:
            wanted = {f.replace(' ', '').upper() for f in subkeys}
            all_keys = [
                (None, k)
                for k in all_keys
                if str(k.fingerprint).replace(' ', '').upper() in wanted
            ]
            logger.info('Selected subkeys for SmartPGP import: %s', wanted)
    else:
        all_keys = [(None, k) for k in all_keys]
    if not all_keys:
        all_keys = [(None, key)]
    logger.info('Preparing to import %d keys via SmartPGP', len(all_keys))
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

    role_map = {'s': 'sig', 'e': 'dec', 'a': 'auth'}
    for flag, k in all_keys:
        if flag:
            role = role_map.get(flag)
        else:
            try:
                flags = set(k.key_flags)  # pgpy <0.6
            except AttributeError:
                flags = set(k._get_key_flags())
            role = None
            if KeyFlags.Sign in flags:
                role = 'sig'
            elif (
                KeyFlags.EncryptCommunications in flags
                or KeyFlags.EncryptStorage in flags
            ):
                role = 'dec'
            elif KeyFlags.Authentication in flags:
                role = 'auth'
            if role is None:
                logger.info(
                    'Skipping subkey %s with unsupported key flags: %s',
                    k.fingerprint,
                    flags,
                )
                continue
        km = k._key.keymaterial
        try:
            if hasattr(km, 'oid'):
                curve_name = _curve_map.get(km.oid)
                if not curve_name:
                    logger.error('Unsupported curve %s', km.oid)
                    return False
                size = size_map.get(curve_name)
                if not size:
                    logger.error('No size mapping for curve %s', curve_name)
                    return False
                priv = km.s.to_bytes(size, 'big')
                point = km.p
                pub = b'\x04' + point.x.to_bytes(size, 'big') + point.y.to_bytes(size, 'big')
                logger.info(
                    'Importing %s subkey %s as %s (size=%d bytes)',
                    role,
                    k.fingerprint,
                    curve_name,
                    size,
                )
                logger.info('Switching SmartPGP slot %s to %s', role, curve_name)
                ctx.cmd_switch_crypto(curve_name, role)
                logger.info(
                    'Writing ECC key material to slot %s (pub=%d bytes, priv=%d bytes)',
                    role,
                    len(pub),
                    len(priv),
                )
                ctx.cmd_put_key(role, pub, priv)
            elif hasattr(km, 'n') and hasattr(km, 'd'):
                modulus_bits = km.n.bit_length()
                alg = _rsa_alg_map.get(modulus_bits)
                if not alg:
                    logger.error('Unsupported RSA modulus size %s bits', modulus_bits)
                    return False
                modulus_len = (modulus_bits + 7) // 8
                if modulus_len % 2:
                    logger.error('Unexpected odd RSA modulus length %s bytes', modulus_len)
                    return False
                half_len = modulus_len // 2
                p_int = int(km.p)
                q_int = int(km.q)
                d_int = int(km.d)
                e_int = int(km.e)
                dp_int = d_int % (p_int - 1)
                dq_int = d_int % (q_int - 1)
                try:
                    qinv_int = pow(q_int, -1, p_int)
                except ValueError as exc:
                    logger.error('Failed to compute RSA CRT coefficient: %s', exc)
                    return False
                exp_len = max(1, (e_int.bit_length() + 7) // 8)
                components = [
                    (0x91, e_int.to_bytes(exp_len, 'big')),
                    (0x92, p_int.to_bytes(half_len, 'big')),
                    (0x93, q_int.to_bytes(half_len, 'big')),
                    (0x94, qinv_int.to_bytes(half_len, 'big')),
                    (0x95, dp_int.to_bytes(half_len, 'big')),
                    (0x96, dq_int.to_bytes(half_len, 'big')),
                    (0x97, int(km.n).to_bytes(modulus_len, 'big')),
                ]
                logger.info(
                    'Importing %s subkey %s as RSA (%d bits)',
                    role,
                    k.fingerprint,
                    modulus_bits,
                )
                logger.info('Switching SmartPGP slot %s to %s', role, alg)
                ctx.cmd_switch_crypto(alg, role)
                logger.info(
                    'Writing RSA key material to slot %s (components=%d)',
                    role,
                    len(components),
                )
                ctx.cmd_put_key(role, components=components)
            else:
                logger.error('Unsupported key type for SmartPGP import: %s', type(km))
                return False
            fp = bytes.fromhex(str(k.fingerprint).replace(' ', ''))
            ts = int(k.created.timestamp()).to_bytes(4, 'big')
            logger.info(
                'Writing fingerprint %s and timestamp %s to slot %s',
                k.fingerprint,
                k.created.isoformat(),
                role,
            )
            ctx.cmd_put_data(fp_tags[role], fp)
            ctx.cmd_put_data(ts_tags[role], ts)
        except Exception as e:
            logger.exception('Failed to import %s key via SmartPGP: %s', role, e)
            return False
    return True
