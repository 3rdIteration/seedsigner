---
description: Fill fork-translation gaps for a locale (agent-translated, upstream-glossary-consistent)
argument-hint: <locale e.g. es, de, zh_Hans_CN> [--dry-run]
---

Fill the fork's translation overlay for locale **$ARGUMENTS**.

The fork adds UI strings upstream never translates. Overlay catalogs live at
`l10n/fork/<locale>/messages.po` and are merged into the upstream catalogs at
build time by `python setup.py compile_catalog` (upstream always wins on
overlap). Managed by `l10n/fork_translations.py`. See `l10n/README.md`.

## Procedure

1. **Prepare.** Run `python l10n/fork_translations.py prune` then
   `python l10n/fork_translations.py stub --locale <locale>`. Open
   `l10n/fork/<locale>/messages.po` — every entry with an empty `msgstr` is a gap.

2. **Build the glossary FIRST.** Read the upstream catalog at
   `src/seedsigner/resources/seedsigner-translations/l10n/<locale>/LC_MESSAGES/messages.po`
   and extract how upstream renders recurring terms before translating anything:
   seed, mnemonic, passphrase, fingerprint, derivation path, descriptor,
   multisig/single sig, script type, wallet, address, QR code, scan, verify,
   backup, entropy, dice, coordinator/wallet software, and the names of
   screens/buttons the fork strings extend. **Match upstream's choices exactly** —
   including which terms upstream deliberately leaves in English (e.g. "xpub",
   "SeedQR", "PSBT" typically stay untranslated).

3. **Translate every empty msgstr**, respecting:
   - Placeholders `{}` / `{name}` copied verbatim, same count and names.
   - `\n` line structure preserved.
   - UI limits (see AGENTS.md): body copy ≤ ~120 chars over ≤ 2 lines; button
     labels and titles as short as their English counterparts (the 240px screen
     does not scroll horizontally).
   - Sentence casing conventions of the target language; upstream's existing
     style wins over textbook style.
   - Brand/product names (SeedSigner, SeedKeeper, Satochip, Keycard, Specter,
     BitBox02, Passport, TAPSIGNER, GPG, BIP39/BIP85/SLIP39) are never translated.
   - Add `#. FORK: translated by Claude <YYYY-MM-DD>` above each entry you fill.

4. **Doubt handling — ask, don't guess.** Collect ambiguous strings while
   translating (polysemous words like "share" (SLIP39 share vs. verb),
   "load" (from storage vs. onto card), terse fragments whose UI context is
   unclear). Look up the source file/line from the entry's `#:` comment to get
   context first; if still uncertain, mark the entry `#. FORK-REVIEW: <question>`
   with msgstr left empty, and ask the user **in one batch** (AskUserQuestion)
   at the end rather than one-at-a-time. Fill after answers arrive.

5. **Verify.**
   - `python l10n/fork_translations.py check` → 0 errors.
   - `python setup.py compile_catalog` → look for `(+N fork overlay entries)`.
   - Spot-check via gettext: load the locale and confirm 2–3 fork strings return
     translations while an upstream string still returns upstream's text.
   - `python -m pytest tests/test_flows_l10n.py` passes.
   - Rendering (fonts/line lengths) is validated by the screenshot generator in
     CI — locally Pillow lacks libraqm, don't attempt it.

6. **Deliver.** `python l10n/fork_translations.py status` for the final coverage
   number, then commit just this locale's overlay file on a dedicated branch and
   report gap→coverage before/after. One locale per PR keeps diffs reviewable.

If `--dry-run` was passed: do steps 1–2 and report the gap list and glossary,
but don't write translations.
