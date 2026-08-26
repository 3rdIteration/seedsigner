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

`XTRAS.HUGE_WITNESS_STACK.psbt` is deliberately **not** vendored: the original is
1.5 MB of incompressible witness data. `psbt_suite_util.build_huge_witness_psbt()`
synthesizes an equivalent at test time.

Regenerate the upstream corpus with:

```
python psbt_test_suite/generate.py
```
