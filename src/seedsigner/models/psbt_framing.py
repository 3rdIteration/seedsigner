"""
Strict byte-level checks on a serialized psbt, run before embit builds its model.

Some deceptions cannot be seen once embit has parsed a psbt, because embit
resolved them while reading. Up to 0.8.0, embit read the BIP-370 (v2) per-scope
fields in a v0 container too, overwrote the global unsigned tx's values with them
and rebuilt `psbt.tx` from the scopes, leaving no trace of the tx it replaced. So
a v0 psbt could name one transaction in its global unsigned tx and another in its
scopes, and PSBTParser only ever saw the second: enough to show an attacker's
output as the user's change, or to make a forged previous tx for a legacy input
check out against its own hash.

embit 0.8.2 refuses those version mix-ups itself. These checks stay regardless:
they give each refusal a RejectCode the user is shown, rather than a generic
"could not be read"; they are not tied to one embit release's parser; and they
cover what embit still does not -- non-minimal compact sizes, and v2 counts too
large for the data (embit allocates a record per declared input/output before
reading any). The rules, enforced on the raw bytes:

  * the version is 0 or 2;

  * every compact size (key length, key type, value length) uses its minimal
    encoding;
  * no key appears twice in a map;
  * a v0 psbt carries none of the fields BIP-370 defines for v2 only, and a v2
    psbt carries no PSBT_GLOBAL_UNSIGNED_TX;
  * there are exactly as many input and output maps as the transaction has
    inputs and outputs, and nothing after them; a v2 psbt may not declare more
    of them than its remaining bytes could hold.

`parse_psbt()` is the single entry point: every raw psbt the device receives
should go through it rather than through `PSBT.parse()` directly.
"""
from __future__ import annotations

from io import BytesIO

from embit.psbt import PSBT
from embit.transaction import Transaction

from seedsigner.models.psbt_parser import InvalidPSBTError, RejectCode


MAGIC = b"psbt\xff"

PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_VERSION = 0xFB
PSBT_GLOBAL_INPUT_COUNT = 0x04
PSBT_GLOBAL_OUTPUT_COUNT = 0x05

# BIP-370: "excluded" from v0. Each is the v2 home of something v0 keeps in the
# global unsigned tx.
V2_ONLY_GLOBAL = {
    0x02: "PSBT_GLOBAL_TX_VERSION",
    0x03: "PSBT_GLOBAL_FALLBACK_LOCKTIME",
    0x04: "PSBT_GLOBAL_INPUT_COUNT",
    0x05: "PSBT_GLOBAL_OUTPUT_COUNT",
    0x06: "PSBT_GLOBAL_TX_MODIFIABLE",
}
V2_ONLY_INPUT = {
    0x0E: "PSBT_IN_PREVIOUS_TXID",
    0x0F: "PSBT_IN_OUTPUT_INDEX",
    0x10: "PSBT_IN_SEQUENCE",
    0x11: "PSBT_IN_REQUIRED_TIME_LOCKTIME",
    0x12: "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
}
V2_ONLY_OUTPUT = {
    0x03: "PSBT_OUT_AMOUNT",
    0x04: "PSBT_OUT_SCRIPT",
}


class _Unreadable(Exception):
    """
    The bytes are not a psbt this walker can delimit (bad magic, truncation, an
    unparseable global tx). Not a refusal: embit is left to reject them, so
    garbage keeps producing the same "could not be read" outcome it always has.
    """


class _NonMinimal(Exception):
    pass


def _read_compact(stream: BytesIO) -> int:
    first = stream.read(1)
    if len(first) != 1:
        raise _Unreadable()
    prefix = first[0]
    if prefix < 0xFD:
        return prefix
    width, floor = {0xFD: (2, 0xFD), 0xFE: (4, 0x1_0000), 0xFF: (8, 0x1_0000_0000)}[prefix]
    raw = stream.read(width)
    if len(raw) != width:
        raise _Unreadable()
    value = int.from_bytes(raw, "little")
    if value < floor:
        raise _NonMinimal()
    return value


def _read_exact(stream: BytesIO, n: int) -> bytes:
    data = stream.read(n)
    if len(data) != n:
        raise _Unreadable()
    return data


def _malformed(message: str) -> InvalidPSBTError:
    return InvalidPSBTError(message, code=RejectCode.MALFORMED_ENCODING)


def _read_map(stream: BytesIO, where: str) -> dict[bytes, tuple[int, bytes]]:
    """
    One key-value map, up to its 0x00 separator. Returns {key: (key_type, value)}.
    """
    entries = {}
    while True:
        try:
            key_len = _read_compact(stream)
        except _NonMinimal:
            raise _malformed(f"{where}: a key length is not minimally encoded.")
        if key_len == 0:
            return entries

        key = _read_exact(stream, key_len)
        try:
            key_type = _read_compact(BytesIO(key))
        except _NonMinimal:
            raise _malformed(f"{where}: a key type is not minimally encoded.")

        try:
            value_len = _read_compact(stream)
        except _NonMinimal:
            raise _malformed(f"{where}: a value length is not minimally encoded.")
        value = _read_exact(stream, value_len)

        if key in entries:
            raise _malformed(f"{where}: key type 0x{key_type:02x} appears twice.")
        entries[key] = (key_type, value)


def _reject_foreign_fields(entries: dict, forbidden: dict, where: str, version: int):
    for key_type, _value in entries.values():
        if key_type in forbidden:
            raise InvalidPSBTError(
                f"{where}: {forbidden[key_type]} is not allowed in a v{version} psbt.",
                code=RejectCode.WRONG_VERSION_FIELD,
            )


def check_psbt_framing(raw: bytes) -> None:
    """
    Raise InvalidPSBTError if `raw` breaks one of the rules in the module
    docstring. Returns silently both for a clean psbt and for bytes it cannot
    delimit at all; the latter are left for embit to reject.
    """
    try:
        _check(BytesIO(raw))
    except _Unreadable:
        return


def _check(stream: BytesIO) -> None:
    if stream.read(len(MAGIC)) != MAGIC:
        raise _Unreadable()

    globals_ = _read_map(stream, "Global map")
    by_type = {}
    for key_type, value in globals_.values():
        by_type.setdefault(key_type, value)

    version_bytes = by_type.get(PSBT_GLOBAL_VERSION)
    version = int.from_bytes(version_bytes, "little") if version_bytes else 0

    if version == 0:
        _reject_foreign_fields(globals_, V2_ONLY_GLOBAL, "Global map", version)
        if PSBT_GLOBAL_UNSIGNED_TX not in by_type:
            raise _Unreadable()
        try:
            tx = Transaction.parse(by_type[PSBT_GLOBAL_UNSIGNED_TX])
        except Exception:
            raise _Unreadable()
        num_inputs, num_outputs = len(tx.vin), len(tx.vout)

    elif version == 2:
        if PSBT_GLOBAL_UNSIGNED_TX in by_type:
            raise InvalidPSBTError(
                "Global map: PSBT_GLOBAL_UNSIGNED_TX is not allowed in a v2 psbt.",
                code=RejectCode.WRONG_VERSION_FIELD,
            )
        counts = []
        for key_type in (PSBT_GLOBAL_INPUT_COUNT, PSBT_GLOBAL_OUTPUT_COUNT):
            if key_type not in by_type:
                raise _malformed(f"Global map: {V2_ONLY_GLOBAL[key_type]} is missing.")
            count_stream = BytesIO(by_type[key_type])
            try:
                counts.append(_read_compact(count_stream))
            except _NonMinimal:
                raise _malformed(f"Global map: {V2_ONLY_GLOBAL[key_type]} is not minimally encoded.")
            if count_stream.read(1):
                raise _malformed(f"Global map: {V2_ONLY_GLOBAL[key_type]} has trailing bytes.")
        num_inputs, num_outputs = counts

        # Every map is at least its one-byte separator. embit allocates a record
        # per declared input and output before reading any, so a count the
        # remaining bytes cannot hold would otherwise let a few-hundred-byte psbt
        # tie the device up building millions of them.
        remaining = len(stream.getbuffer()) - stream.tell()
        if num_inputs + num_outputs > remaining:
            raise _malformed(
                f"Global map: declares {num_inputs} inputs and {num_outputs} outputs; "
                f"only {remaining} bytes follow."
            )

    else:
        # A format whose fields we would misread. embit refuses it as well, but
        # only as "could not be read"; this names it.
        raise InvalidPSBTError(
            f"PSBT version {version} is not supported.",
            code=RejectCode.UNSUPPORTED_PSBT_VERSION,
        )

    for i in range(num_inputs):
        entries = _read_map(stream, f"Input {i}")
        if version == 0:
            _reject_foreign_fields(entries, V2_ONLY_INPUT, f"Input {i}", version)

    for i in range(num_outputs):
        entries = _read_map(stream, f"Output {i}")
        if version == 0:
            _reject_foreign_fields(entries, V2_ONLY_OUTPUT, f"Output {i}", version)

    if stream.read(1):
        raise _malformed(
            f"Data follows the last of the transaction's {num_outputs} outputs."
        )


def parse_psbt(raw: bytes) -> PSBT:
    """
    `PSBT.parse()` behind the framing checks above. Raises InvalidPSBTError for a
    framing refusal, or whatever embit raises for bytes that are not a psbt.
    """
    check_psbt_framing(raw)
    return PSBT.parse(raw)
