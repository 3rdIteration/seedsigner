# Rebuilding the bundled ETH function-signature index

The firmware ships a memory-mapped selector index used for **offline** calldata
decoding (so a transaction shows `transfer 5 USDC` instead of *"Blind signing"*):

    src/seedsigner/resources/eth_sig_index.bin
    src/seedsigner/resources/eth_sig_blob.bin

These are generated **on the build machine** (never on the air-gapped device) by
`scripts/build_eth_signature_index.py` from a plain-text dump of canonical
function signatures (one per line, e.g. `supply(address,uint256,address,uint16)`).

This file documents **where the dump comes from** so the index is reproducible
and auditable — the offline analogue of keycard-shell's signed "database build".

## Why rebuild

The currently-committed index is a **collision-free** set of ~842 847 selectors
(one signature per selector — the shape of the `ethereum-lists/4bytes` repo). The
real 4byte / openchain corpora are larger (~1.3 M+ signatures, **with** real
collisions) and include common functions the current set is missing
(`executeBatch(address[],uint256[],bytes[])`, LayerZero `sendFrom`, …). Rebuilding
from a fuller corpus raises the decode hit-rate for everyday mainnet DeFi.

Keep collisions: the decoder's decode-consistency tie-break
(`calldata_decoder._consistent_candidates`) resolves most of them, and curated
selectors always win (the generator excludes them from the index).

## Sources — what actually works (checked 2026-06-18)

| Source | Size | Bulk download? |
|--------|------|----------------|
| **openchain.xyz** | ~3.8M function sigs | **No** — per-selector *lookup* API only, no export endpoint. Not crawlable politely at that scale. |
| **4byte.directory** | ~1.17M function sigs (with collisions) | **Yes** — paginated API (100/page). A superset of the collision-free `ethereum-lists/4bytes` the current index was built from. **Use this.** |
| **ethereum-lists/4bytes** | ~842k (collision-free) | Yes (git clone of `signatures/`), but it's the *current* source → no coverage gain. |

The runnable "full corpus" path is the **4byte.directory crawl** via
`scripts/fetch_4byte_signatures.py` (polite, rate-limited, resumable).

## Build + verify (copy-paste)

    # 1. Crawl 4byte → one signature per line (~1.17M, ~30–60 min; resumable —
    #    just re-run if it stops; progress is tracked in corpus.txt.cursor).
    python scripts/fetch_4byte_signatures.py --out corpus.txt

    # 2. Regenerate the bundled index from the corpus (KEEP collisions — the
    #    decode-consistency tie-break + curated-wins handle them).
    python scripts/build_eth_signature_index.py \
        --input corpus.txt \
        --out-index src/seedsigner/resources/eth_sig_index.bin \
        --out-blob  src/seedsigner/resources/eth_sig_blob.bin \
        --verify

    # 3. Confirm coverage (previously-blind anchors must resolve).
    python scripts/probe_eth_signature_coverage.py

Anything in the curated registry (`function_registry.py`) is *intentionally*
excluded from the index and resolved by the curated table instead, so those rows
show as `CURATED` in the probe — that's expected, not a miss.

To union multiple dumps (e.g. add a one-off list of in-house signatures), just
concatenate the files before step 2; the generator dedups `(selector, signature)`
pairs, so overlap is free.

## Record provenance

When you commit regenerated `.bin` files, note in the commit message **which
source(s)** were used and their **export date / git commit**, so the binary
artefacts can be reproduced byte-for-byte (the generator is deterministic: same
input ⇒ identical output).

## Size / device notes

A fuller corpus grows the index from ~33 MB toward ~60–75 MB. This is fine: the
files are memory-mapped and binary-searched (O(log N)), so resident RAM stays at
a handful of pages even on the Pi Zero. They are auto-bundled into the firmware
image by the `seedsigner.resources` package-data glob in `pyproject.toml`.
