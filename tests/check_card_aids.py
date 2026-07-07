from smartcard.System import readers
from smartcard.util import toBytes

r = readers()[0]
conn = r.createConnection()
conn.connect()

aids = [
    ('SatoChip',  '5361746F43686970'),
    ('SeedKeeper','536565644B6565706572'),
    ('Satodime',  '5361746F44696D65'),
    ('Keycard',   'A0000008040001'),
    ('SpecterDIY','B00B5111CB'),
]

for name, aid_hex in aids:
    aid = toBytes(aid_hex)
    apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid)
    data, sw1, sw2 = conn.transmit(apdu)
    status = 'PRESENT' if (sw1, sw2) == (0x90, 0x00) else 'NOT FOUND (SW=%02X%02X)' % (sw1, sw2)
    print('%15s (%s): %s' % (name, aid_hex, status))

# Also check ISD
apdu = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]
data, sw1, sw2 = conn.transmit(apdu)
print('%15s: %s' % ('ISD', 'PRESENT' if (sw1,sw2) == (0x90,0x00) else 'NOT FOUND (SW=%02X%02X)' % (sw1, sw2)))
