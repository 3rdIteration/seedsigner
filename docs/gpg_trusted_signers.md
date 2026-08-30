# GPG Trusted Signers by Project

The **GPG Tools → File Operations → Verify Signature** workflow cryptographically verifies a file's signature, then checks *who* signed it. A valid signature from the wrong project (e.g. an Electrum builder key "signing" a Bitcoin Core release) is still dangerous, so SeedSigner maps filenames to projects and fingerprints to expected signers via `src/seedsigner/models/gpg_trusted_projects.py`.

**How the result is shown:**

| Situation | Result |
|-----------|--------|
| File matches a known project **and** at least one signer is trusted for that project | Success screen showing the project name and full 40-character fingerprint(s) of the valid signer(s). Multi-signature files pass if *any* signer is in the project's set. |
| File matches a known project but the signer belongs to a different tracked project | Blocking warning naming both projects; you must acknowledge ("I Understand") before the success screen. |
| File matches a known project and the signer is not tracked at all | Blocking warning for an unknown key; same acknowledgment flow. |
| Filename matches no tracked project (or is ambiguous, e.g. a bare `SHA256SUMS` that can't be attributed to one project) | Neutral success screen with fingerprints only — no trust judgment is made. |

Filenames are matched case-insensitively; one trailing detached-signature extension (`.sig` or `.asc`) is stripped before matching, so `foo.tar.gz.sig` matches the patterns for `foo.tar.gz`. Clearsigned files (e.g. COLDCARD's `signatures.txt`) are verified directly without a data-file pairing step.

**Keep this page and `src/seedsigner/models/gpg_trusted_projects.py` consistent whenever entries change.**

---

## SeedSigner

- Website: https://seedsigner.org
- Releases: https://github.com/SeedSigner/seedsigner/releases
- Artifacts: `seedsigner-*` images (`.img`, `.zip`) with detached signatures; `SHA256SUMS` manifest.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Keith Mukai | `46739B74 B56AD88F 14B0882E C7EF7090 07260119` | `gpg_keys/Seedsigner_pubkey.asc` |

## Sparrow Wallet

- Website: https://sparrowwallet.com
- Releases: https://github.com/sparrowwallet/sparrow/releases
- Artifacts: `sparrow-*` installers with detached signatures; manifest file named `manifest`.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Craig Raw | `D4D0D320 2FC06849 A257B38D E9461833 4C674B40` | `gpg_keys/Sparrow_Craigraw.asc` |

## Liana Wallet

- Website: https://liana.wiki
- Releases: https://github.com/wizardsardine/liana/releases
- Artifacts: `liana-*` installers with detached signatures; checksums use the `shasums` naming convention.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Edouard Paris | `5B63F3B9 7699C7EE F3B040B1 9B7F629A 53E77B83` | `gpg_keys/Liana_Edouard.asc` |

## Krux Firmware

- Website: https://kruxfirmware.com
- Releases: https://github.com/selfcustody/krux/releases
- Artifacts: `krux-*` firmware files with a `.sig` sidecar.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| qlrd | `B4281DDD FBBD207B FA411313 8974C902 99326322` | `gpg_keys/Krux_Qlrd.asc` |

Known limitation: the published `.sig` files are **not OpenPGP signatures** (they are a small non-PGP binary blob, consistent across releases), so GPG verification of Krux firmware reports "no valid OpenPGP data" regardless of imported keys. The qlrd key is retained for reference; it also expired on 2026-05-14.

## Specter Desktop

- Website: https://specterdesktop.com
- Releases: https://github.com/cryptoadvance/specter-desktop/releases (moved from the old `keepkey` org)
- Artifacts: `specter-*` / `specterd-*` installers, `cryptoadvance_specter*` firmware, and a bare `SHA256SUMS` manifest (ambiguous with Bitcoin Core's — disambiguated by the signer's fingerprint).

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Stepan Snigirev (previous signer) | `6F16E354 F83393D6 E52EC25F 36ED357A B24B915F` | `gpg_keys/Specter_StepanSnigirev.asc` |
| Specter Signer 2026 | `9DC33CA8 30589DE3 B3225C26 EEF5756B 2EA42349` | `gpg_keys/Specter_SigningKey2026.asc` |

Note: Stepan Snigirev's last signed release (v2.1.0-pre1, June 2024) predates the current two-year recency guideline; the key is retained deliberately so older releases remain verifiable. The Specter Signer 2026 key was fetched from a public keyserver and its fingerprint verified against the project's release announcements.

## Electrum

- Website: https://electrum.org
- Releases: https://download.electrum.org/ (per-version directories, each containing `.asc` signatures; no GitHub release objects)
- Artifacts: `Electrum-*` / `electrum-*` installers with detached signatures. Releases are multi-signed by several builders; **any** of the keys below is trusted.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Axel Gembe (SomberNight) | `0EEDCFD5 CAFB4590 67349B23 CA9EEEC4 3DF911DC` | `gpg_keys/Electrum_sombernight_releasekey.asc` |
| Thomas Voegtlin (ThomasV) | `6694D8DE 7BE8EE56 31BED950 2BD5824B 7F9470E6` | `gpg_keys/Electrum_ThomasV.asc` |
| Emzy | `9EDAFF80 E0806596 04F4A76B 2EBB056F D847F8A7` | `gpg_keys/Electrum_Emzy.asc` |
| Felix B. (felixb_f321x) | `AA0BC682 4B397BBA 99776E15 7ED8D82B 37192688` | `gpg_keys/Electrum_felixb_f321x.asc` |
| Sebastian van Staa (svanstaa) | `33C103B4 B2794170 546CCF7B CFB2C83C 66CD792A` | `gpg_keys/Electrum_svanstaa.asc` |

Emzy also signs Bitcoin Core releases (listed under both projects). The felixb_f321x and svanstaa keys were added from the key IDs observed in Electrum's published release signatures.

## Bitcoin Core

- Website: https://bitcoincore.org
- Releases: https://bitcoincore.org/en/releases/ (mirrored at https://github.com/bitcoin/bitcoin/releases)
- Artifacts: `bitcoin-*` archives with detached signatures; bare `SHA256SUMS` manifest (ambiguous with Specter's — disambiguated by the signer's fingerprint).

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Andrew "Ava" Chow (achow101) | `15281230 0785C964 44D3334D 17565732 E08E5E41` | `gpg_keys/BitcoinCore_AvaChow.asc` |
| Michael Ford (CoinForensics) | `101598DC 823C1B5F 9A6624AB A5E0907A 0380E6C3` | `gpg_keys/BitcoinCore_CoinForensicsc.asc` |
| Michael Ford (fanquake) — second key, distinct from the CoinForensics one above | `E777299F C265DD04 793070EB 944D35F9 AC3DB76A` | `gpg_keys/BitcoinCore_Fanquake.asc` |
| Dmitry Kalinkin (Dimitri) | `C388F696 1FB972A9 5678E327 F62711DB DCA8AE56` | `gpg_keys/BitcoinCore_Dimitri.asc` |
| Gloria Zhao | `6B002C6E A3F91B1B 0DF0C9BC 8F617F12 00A6D25C` | `gpg_keys/BitcoinCore_GloriaZhao.asc` |
| Matthew Zipkin | `E61773CD 6E01040E 2F1BD78C E7E2984B 6289C93A` | `gpg_keys/BitcoinCore_MatthewZipkin.asc` |
| Oliver Gugger | `F4FC70F0 73100284 24EFC20A 8E425659 3F177720` | `gpg_keys/BitcoinCore_Oliver_Gugger.asc` |
| Sebastian Kung | `A8FC55F3 B04BA314 6F3492E7 9303B33A 305224CB` | `gpg_keys/BitcoinCore_SebastianKung.asc` |
| Will Clark | `67AA5B46 E7AF7805 3167FE34 3B8F814A 784218F8` | `gpg_keys/BitcoinCore_WillClark.asc` |
| Wladimir J. van der Laan | `71A3B167 35405025 D447E8F2 74810B01 2346C9A6` | `gpg_keys/BitcoinCore_WladimirJvanderLaan.asc` |
| Matt Edwards (m3dwards) | `E86AE734 39625BBE E306AAE6 B66D427F 873CB1A3` | `gpg_keys/BitcoinCore_m3dwards.asc` |
| 0xB10C | `982A193E 3CE0EED5 35E09023 188CBB26 48416AD5` | `gpg_keys/Bitcoin_Core_0xB10C.asc` |
| Hennadii Stepanov (hebasto) | `D1DBF2C4 B96F2DEB F4C16654 41010811 2E7EA81F` | `gpg_keys/BitcoinCore_Hebasto.asc` |
| Ben Carman (benthecarman) | `0AD83877 C1F0CD1E E9BD660A D7CC770B 81FD22A8` | `gpg_keys/BitcoinCore_Benthecarman.asc` |
| Marcel Fornasier (marleo) | `5B286407 E1EA6FE0 1CF9AF48 BF131C2D 0536F8AC` | `gpg_keys/BitcoinCore_Marleo.asc` |
| Sjors Provoost | `ED9BDF7A D6A55E23 2E845242 57FF9BDB CC301009` | `gpg_keys/BitcoinCore_SjorsProvoost.asc` |
| Emzy | `9EDAFF80 E0806596 04F4A76B 2EBB056F D847F8A7` | `gpg_keys/Electrum_Emzy.asc` |

The fanquake, hebasto, benthecarman, marleo, and Sjors Provoost keys were added after auditing the v31.1 (July 2026) `SHA256SUMS` signatures: each key ID observed in that manifest was mapped to its primary fingerprint via a public keyserver. Note that several Bitcoin Core signers — including Sjors Provoost's key above (expired 2026-07-01, yet used for v31.1) and the Ava Chow key — have lapsed expirations; GPG still verifies signatures made with them cryptographically, so they remain trusted here.

## GnuPG

- Website: https://gnupg.org
- Releases: https://www.gnupg.org/download/ (source at https://github.com/gpg/gnupg)
- Artifacts: `gnupg-*` source archives with detached signatures.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Andre Heinecke (release signing key) | `5B80C575 4298F0CB 55D8ED6A BCEF7E29 4B092E28` | `gpg_keys/GNUPG_ReleaseKeys.asc` |
| Werner Koch (dist signing 2020) | `6DAA6E64 A76D2840 571B4902 528897B8 26403ADA` | `gpg_keys/GNUPG_ReleaseKeys.asc` |
| Niibe Yutaka (GnuPG release key) | `AC8E115B F73E2D8D 47FA9908 E98E9B2D 19C6C8BD` | `gpg_keys/GNUPG_ReleaseKeys.asc` |

All three keys (plus a fourth, "GnuPG.com Release Signing Key 2021", which is not listed because it has not signed any release in the tracked window) are bundled together in the single `GNUPG_ReleaseKeys.asc` file. Current releases (gnupg-2.4.x and later) are signed by Werner Koch and/or Niibe Yutaka; older 2.0–2.3 era releases used yet other keys that predate this list.

## COLDCARD (Coinkite)

- Website: https://coldcard.com
- Firmware downloads: https://coldcard.com/downloads (source repo without GitHub releases: https://github.com/Coldcard/firmware); upgrade instructions at https://coldcard.com/docs/upgrade/
- Artifacts: `*-coldcard.dfu` firmware files. The release manifest `signatures.txt` (published in the source repo's `releases/` directory) is **clearsigned** (signature embedded in the file) and verified directly; its SHA-256 hashes cover the `.dfu` files.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Peter D. Gray | `4589779A DFC14F33 27534EA8 A3A31BAD 5A2A5B10` | `gpg_keys/Coinkite_Peter_Gray.asc` |

## Trezor Suite (SatoshiLabs)

- Website: https://trezor.io
- Releases: https://github.com/trezor/trezor-suite/releases
- Artifacts: `trezor-suite-*` installers with detached signatures. Only the desktop app is tracked — SatoshiLabs does not publish GPG signatures for device firmware, which is verified through other means (see https://wiki.trezor.io).

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| SatoshiLabs 2021 Signing Key | `EB483B26 B078A4AA 1B6F425E E21B6950 A2ECB65C` | `gpg_keys/SatoshiLabs_2021_Signing_Key.asc` |

## Casa Passport (Foundation Devices)

- Website: https://casacurrency.com
- Releases: https://github.com/Foundation-Devices/passport-firmware/releases (redirect target of the old `Foundation-Devices/Passport` repo)
- Artifacts: `passport-fw-*` firmware files with detached signatures.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Ken Carpenter | `5DBE7F18 52939353 15E56E31 CFE1890A B7FC8B64` | `gpg_keys/Foundationdevices_Ken_Carpenter.asc` |

Note: the latest published release (v1.1.0, August 2022) predates the two-year recency window and was signed with Ken Carpenter's older "GitHub" key (`E7FA9F9E 3477BA54 9091B6A7 57C004A5 20148A68`), which is not bundled. No newer releases have been published in the tracked window, so no action was taken.

## BIP39 Tool (Ian Coleman)

- Website: https://iancoleman.io/bip39/
- Releases: https://github.com/iancoleman/bip39-standalone/releases
- Artifacts: `bip39-standalone*` archives with detached signatures.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| Ian Coleman | `5AD5C880 83708E93 A2966FF4 9FF1B58C A7B9E6A5` | `gpg_keys/BIP39Tool_IanColeman.asc` |

Known limitation: the currently published signatures are made with an older key (key ID `8DA6044ECA5B2250`) that does not match the bundled public key, so verification of recent releases reports "Signing key not found" until the matching key is imported manually.

## BitBox02 (Shift Crypto)

- Website: https://shiftcrypto.ch
- Firmware: https://github.com/shiftcrypto/firmware-bitbox02; app releases at https://github.com/shiftcrypto/bitbox02-app
- Artifacts: `firmware-bitbox*`, `bitbox02-*` files, and `assertion*` reproducibility-build assertion files. Shift Crypto does not publish conventional GitHub release signatures for the firmware; integrity is established through reproducible builds — the `assertion` files record that independent rebuilds produced byte-identical output. Verify the assertions' signature with the key below and confirm the recorded hashes match the downloaded artifacts.

| Signer | Fingerprint | Bundled key |
|--------|-------------|-------------|
| ShiftCrypto Security | `DD09E413 09750EBF AE0DEF63 509249B0 68D215AE` | `gpg_keys/shiftcrypto_pubkey.asc` |

---

## Not tracked

Files whose names match no project above (including Tails, which was previously bundled but removed because its public key is stale — it lacks the EdDSA subkey used by current signatures) are verified cryptographically and shown neutrally: SeedSigner reports the valid signer's fingerprint(s) without making a trust judgment.
