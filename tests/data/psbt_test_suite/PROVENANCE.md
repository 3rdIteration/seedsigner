# psbt_faker adversarial PSBT corpus

Vendored from the `psbt_faker` signing-test suite (`psbt_test_suite/psbts/`).

Every vector derives from the canonical BIP39 all-zeros test vector:

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

* Master fingerprint: `73C5DA0A`
* Network: **mainnet**
* Accounts: `m/84h/0h/0h` (also `m/49h/0h/0h`, `m/44h/0h/0h`)

The `NORMAL-*` vectors are well-formed transactions that must sign cleanly. The
`TX-*` and `XTRAS.*` vectors are malicious or malformed and must be rejected or
flagged. See `tests/psbt_suite_util.py` for the per-vector trap description and
the behavior SeedSigner is expected to exhibit.

## BIP-370 (v2) coverage

The `*_V2` fixtures are spec-valid BIP-370 v2 twins of their v0 counterparts: the
same transactions, but with inputs and outputs described by their own fields
(`PSBT_IN_PREVIOUS_TXID`, `PSBT_OUT_AMOUNT`, ...) instead of an embedded unsigned
tx. SeedSigner accepts valid v2 psbts and judges them exactly like their v0 twins --
the version is not a reason to refuse or misread them.

The one v2-specific refusal is `TX-12`: it leaves `PSBT_GLOBAL_TX_MODIFIABLE = 0x03`,
meaning a coordinator may still add or remove inputs and outputs *after* we sign.
That voids the review, so it is refused (`RejectCode.TX_MODIFIABLE`) rather than
merely warned about. A missing or zero `TX_MODIFIABLE` means final and is accepted.

## Resync of 2026-09-17

Re-vendored from the regenerated corpus (97 vectors). That regeneration fixed
the BIP-371 taproot derivation encoding, so TX-09.* and TX-11.v1_bech32 now
parse in embit, and it made TX-10, TX-14.cross_net and
XTRAS.NETWORK_HRP_MISMATCH real traps rather than vacuous ones. It added the
TX-19/20/21/22/23 families and the structural XTRAS vectors (missing utxo,
unsupported version, undisplayable outputs, witness/non-witness mismatch).

Local deviations from upstream:

* `XTRAS.LOCKTIME_FUTURE.psbt` is kept though upstream dropped it (superseded by
  TX-19.timestamp_future); TestTimelocks mutates it.
* The TX-20 vectors were re-vendored on 2026-09-18 after two generator fixes
  (P2WSH was built as a p2wpkh-shaped hash160, and OP_CLTV/OP_CSV had the wrong
  opcode values); all three now carry a committed CLTV/CSV script.
* Only three vectors are refused by embit itself: TX-04, TX-13.duplicate and
  XTRAS.TRUNCATED_PSBT.

## Follow-up of 2026-09-18

Vectors added for the fixes brought over from the upstream SeedSigner PR review
(#995/#977, #965/#1003, #1040, and the #1032 review thread), generated with the
local psbt_faker: XTRAS.PREV_TX_TXID_MISMATCH(_V2), XTRAS.LEGACY_P2SH_WITNESS_ONLY,
XTRAS.OP_RETURN_DIRECT_PUSH(_V2), TX-24.xpub_fingerprint_mismatch,
TX-21.ms_foreign_quorum, TX-21.ms_foreign_quorum_no_xpubs and
TX-21.ms_honest_change_no_xpubs. XTRAS.MIXED_INPUT_TYPES was re-vendored too: its
legacy input used to spend its previous tx by a placeholder txid.

The multisig vectors (TX-04/05, TX-13.*, TX-21.ms_*, TX-22.ms_*) are built
against the suite's 2-of-3 `wsh(sortedmulti)` wallet at `m/48h/0h/0h/2h`; see
`MULTISIG_DESCRIPTOR` in `tests/psbt_suite_util.py`.

`XTRAS.HUGE_WITNESS_STACK.psbt` is deliberately **not** vendored: the original is
1.5 MB of incompressible witness data. `psbt_suite_util.build_huge_witness_psbt()`
synthesizes an equivalent at test time.

Regenerate the upstream corpus with:

```
python psbt_test_suite/generate.py
```
