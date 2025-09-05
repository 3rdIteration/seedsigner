import sys
import types

# Provide a minimal stub of the module that smartpgp_import depends on so
# that the import does not require the external ``smartcard`` package.
dummy_highlevel = types.ModuleType("seedsigner.helpers.smartpgp.highlevel")
class DummyCardConnectionContext:
    pass

dummy_highlevel.CardConnectionContext = DummyCardConnectionContext
sys.modules["seedsigner.helpers.smartpgp.highlevel"] = dummy_highlevel

from pgpy.constants import EllipticCurveOID
from seedsigner.helpers.smartpgp_import import _curve_map


def test_brainpool_curves_supported():
    assert _curve_map[EllipticCurveOID.Brainpool_P256] == 'brainpoolP256r1'
    assert _curve_map[EllipticCurveOID.Brainpool_P384] == 'brainpoolP384r1'
    assert _curve_map[EllipticCurveOID.Brainpool_P512] == 'brainpoolP512r1'
