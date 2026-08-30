"""Trusted project signers for GPG file verification.

Maps release artifacts (by filename) to the projects that publish them, and
maps primary-key fingerprints to the projects whose releases those keys are
expected to sign. Used by ToolsGPGVerifyFileView to warn when a signature is
cryptographically valid but was made by a key not associated with the project
the file appears to belong to (e.g. an Electrum key "signing" a Bitcoin Core
release).

Fingerprints are 40-character uppercase hex primary-key fingerprints matching
the bundled public keys in ``gpg_keys/``. Keep this module and
``docs/gpg_trusted_signers.md`` consistent whenever entries change (see
AGENTS.md).

Filename matching rules:
- One trailing detached-signature extension (``.sig`` or ``.asc``) is stripped
  before matching, so ``foo.tar.gz.sig`` matches the patterns for ``foo.tar.gz``.
- A filename matching zero projects, or matching more than one project
  (ambiguous, e.g. a bare ``SHA256SUMS`` published by several projects), does
  not yield a definitive project; callers may disambiguate using the signer's
  fingerprint via :func:`projects_for_fingerprint`.
"""

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Tuple


@dataclass(frozen=True)
class TrustedProject:
    name: str
    fingerprints: FrozenSet[str]
    file_patterns: Tuple[re.Pattern, ...]


def _p(pattern: str) -> re.Pattern:
    return re.compile(pattern, flags=re.IGNORECASE)


# Signers that publish for more than one tracked project list their
# fingerprint under each of those projects.
_EMZY_FPR = "9EDAFF80E080659604F4A76B2EBB056FD847F8A7"  # Electrum + Bitcoin Core

TRUSTED_PROJECTS: Dict[str, TrustedProject] = {
    "seedsigner": TrustedProject(
        name="SeedSigner",
        fingerprints=frozenset({
            "46739B74B56AD88F14B0882EC7EF709007260119",  # Keith Mukai
        }),
        file_patterns=(_p(r"^seedsigner"),),
    ),
    "sparrow": TrustedProject(
        name="Sparrow Wallet",
        fingerprints=frozenset({
            "D4D0D3202FC06849A257B38DE94618334C674B40",  # Craig Raw
        }),
        file_patterns=(_p(r"^sparrow"),),
    ),
    "liana": TrustedProject(
        name="Liana Wallet",
        fingerprints=frozenset({
            "5B63F3B97699C7EEF3B040B19B7F629A53E77B83",  # Edouard Paris
        }),
        file_patterns=(_p(r"^liana"),),
    ),
    "krux": TrustedProject(
        name="Krux Firmware",
        fingerprints=frozenset({
            "B4281DDDFBBD207BFA4113138974C90299326322",  # qlrd
        }),
        file_patterns=(_p(r"^krux-"),),
    ),
    "specter": TrustedProject(
        name="Specter Desktop",
        fingerprints=frozenset({
            "6F16E354F83393D6E52EC25F36ED357AB24B915F",  # Stepan Snigirev (previous signer)
            "9DC33CA830589DE3B3225C26EEF5756B2EA42349",  # Specter Signer 2026
        }),
        file_patterns=(
            _p(r"^specter-"),
            _p(r"^specterd-"),
            _p(r"^specter_"),
            _p(r"^cryptoadvance_specter"),
            _p(r"^sha256sums"),
        ),
    ),
    "electrum": TrustedProject(
        name="Electrum",
        fingerprints=frozenset({
            "0EEDCFD5CAFB459067349B23CA9EEEC43DF911DC",  # Axel Gembe (SomberNight)
            "6694D8DE7BE8EE5631BED9502BD5824B7F9470E6",  # Thomas Voegtlin (ThomasV)
            _EMZY_FPR,
            "AA0BC6824B397BBA99776E157ED8D82B37192688",  # Felix B. (felixb_f321x)
            "33C103B4B2794170546CCF7BCFB2C83C66CD792A",  # Sebastian van Staa (svanstaa)
        }),
        file_patterns=(_p(r"^electrum"),),
    ),
    "bitcoincore": TrustedProject(
        name="Bitcoin Core",
        fingerprints=frozenset({
            "152812300785C96444D3334D17565732E08E5E41",  # Andrew "Ava" Chow (achow101)
            "101598DC823C1B5F9A6624ABA5E0907A0380E6C3",  # Michael Ford (CoinForensics)
            "E777299FC265DD04793070EB944D35F9AC3DB76A",  # Michael Ford (fanquake), second key
            "C388F6961FB972A95678E327F62711DBDCA8AE56",  # Dmitry Kalinkin (Dimitri)
            "6B002C6EA3F91B1B0DF0C9BC8F617F1200A6D25C",  # Gloria Zhao
            "E61773CD6E01040E2F1BD78CE7E2984B6289C93A",  # Matthew Zipkin
            "F4FC70F07310028424EFC20A8E4256593F177720",  # Oliver Gugger
            "A8FC55F3B04BA3146F3492E79303B33A305224CB",  # Sebastian Kung
            "67AA5B46E7AF78053167FE343B8F814A784218F8",  # Will Clark
            "71A3B16735405025D447E8F274810B012346C9A6",  # Wladimir J. van der Laan
            "E86AE73439625BBEE306AAE6B66D427F873CB1A3",  # Matt Edwards (m3dwards)
            "982A193E3CE0EED535E09023188CBB2648416AD5",  # 0xB10C
            "D1DBF2C4B96F2DEBF4C16654410108112E7EA81F",  # Hennadii Stepanov (hebasto)
            "0AD83877C1F0CD1EE9BD660AD7CC770B81FD22A8",  # Ben Carman (benthecarman)
            "5B286407E1EA6FE01CF9AF48BF131C2D0536F8AC",  # Marcel Fornasier (marleo)
            "ED9BDF7AD6A55E232E84524257FF9BDBCC301009",  # Sjors Provoost
            _EMZY_FPR,
        }),
        file_patterns=(
            _p(r"^bitcoin-"),
            _p(r"^sha256sums"),
        ),
    ),
    "gnupg": TrustedProject(
        name="GnuPG",
        fingerprints=frozenset({
            "5B80C5754298F0CB55D8ED6ABCEF7E294B092E28",  # Andre Heinecke (release signing key)
            "6DAA6E64A76D2840571B4902528897B826403ADA",  # Werner Koch (dist signing 2020)
            "AC8E115BF73E2D8D47FA9908E98E9B2D19C6C8BD",  # Niibe Yutaka (GnuPG release key)
        }),
        file_patterns=(_p(r"^gnupg-"),),
    ),
    "coldcard": TrustedProject(
        name="COLDCARD (Coinkite)",
        fingerprints=frozenset({
            "4589779ADFC14F3327534EA8A3A31BAD5A2A5B10",  # Peter D. Gray
        }),
        file_patterns=(
            _p(r"coldcard(-factory)?\.dfu$"),
            _p(r"^(cc|mk4)-recovery-"),
            _p(r"^signatures\.txt$"),
        ),
    ),
    "trezor": TrustedProject(
        name="Trezor Suite (SatoshiLabs)",
        fingerprints=frozenset({
            "EB483B26B078A4AA1B6F425EE21B6950A2ECB65C",  # SatoshiLabs 2021 Signing Key
        }),
        file_patterns=(_p(r"^trezor-suite-"),),
    ),
    "casa": TrustedProject(
        name="Casa Passport (Foundation Devices)",
        fingerprints=frozenset({
            "5DBE7F185293935315E56E31CFE1890AB7FC8B64",  # Ken Carpenter
        }),
        file_patterns=(_p(r"-passport\.bin$"),),
    ),
    "bip39tool": TrustedProject(
        name="BIP39 Tool (Ian Coleman)",
        fingerprints=frozenset({
            "5AD5C88083708E93A2966FF49FF1B58CA7B9E6A5",  # Ian Coleman
        }),
        file_patterns=(_p(r"^bip39-standalone"),),
    ),
    "bitbox02": TrustedProject(
        name="BitBox02 (Shift Crypto)",
        fingerprints=frozenset({
            "DD09E41309750EBFAE0DEF63509249B068D215AE",  # ShiftCrypto Security
        }),
        file_patterns=(
            _p(r"^firmware-bitbox"),
            _p(r"^bitbox02-"),
            _p(r"^assertion"),
        ),
    ),
}


def projects_for_filename(filename: str) -> List[TrustedProject]:
    """Return every project whose patterns match ``filename``.

    One trailing detached-signature extension (``.sig``/``.asc``) is stripped
    first. May return an empty list (unknown file) or multiple projects
    (ambiguous filename such as a bare ``SHA256SUMS``).
    """
    name = filename
    lowered = name.lower()
    if lowered.endswith(".sig") or lowered.endswith(".asc"):
        name = name[:-4]
    return [
        project
        for project in TRUSTED_PROJECTS.values()
        if any(pattern.search(name) for pattern in project.file_patterns)
    ]


def project_for_filename(filename: str) -> Optional[TrustedProject]:
    """Return the single project matching ``filename``, or None.

    None is returned when no project matches or when the filename is
    ambiguous (matches more than one project); callers can disambiguate with
    :func:`projects_for_fingerprint`.
    """
    matched = projects_for_filename(filename)
    if len(matched) == 1:
        return matched[0]
    return None


def projects_for_fingerprint(fingerprint: str) -> List[TrustedProject]:
    """Return every project that lists ``fingerprint`` as a trusted signer.

    Accepts spaced or unspaced hex in either case (e.g. the format GPG prints).
    A key signing for several tracked projects appears under each of them.
    """
    fpr = "".join(fingerprint.split()).upper()
    return [
        project
        for project in TRUSTED_PROJECTS.values()
        if fpr in project.fingerprints
    ]
