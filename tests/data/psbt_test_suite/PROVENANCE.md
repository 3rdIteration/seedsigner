# psbt_faker adversarial PSBT corpus

Vendored from the `psbt_faker` signing-test suite (`psbt_test_suite/psbts/`).

Every vector derives from the canonical BIP39 all-zeros test vector:

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

* Master fingerprint: `73C5DA0A`
* Network: **mainnet**
* Accounts: `m/84h/0h/0h` (also `m/49h/0h/0h`, `m/44h/0h/0h`)

Four `NORMAL-*` vectors are well-formed transactions that must sign cleanly. The
`TX-*` and `XTRAS.*` vectors are malicious or malformed and must be rejected or
flagged. See `tests/psbt_suite_util.py` for the per-vector trap description and
the behavior SeedSigner is expected to exhibit.

`XTRAS.HUGE_WITNESS_STACK.psbt` is deliberately **not** vendored: the original is
1.5 MB of incompressible witness data. `psbt_suite_util.build_huge_witness_psbt()`
synthesizes an equivalent at test time.

Regenerate the upstream corpus with:

```
python psbt_test_suite/generate.py
```
