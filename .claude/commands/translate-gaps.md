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

1. **Prepare.** Run `python l10n/fork_translations.py prune`, then dump the gap
   list: the msgids in `l10n/messages.pot` that the upstream catalog for the
   locale hasn't translated and the overlay doesn't cover yet
   (`fork_translations.py status` shows counts).

2. **Read `l10n/GLOSSARY.md` and the upstream catalog FIRST.** GLOSSARY.md holds
   settled cross-locale decisions (never-translate list, SLIP-39 "share"
   terminology per Trezor, per-locale conventions). The upstream catalog at
   `src/seedsigner/resources/seedsigner-translations/l10n/<locale>/LC_MESSAGES/messages.po`
   is the primary glossary — extract how it renders recurring terms (seed,
   mnemonic, passphrase, fingerprint, descriptor, multisig, wallet, address,
   scan, verify, backup, entropy, dice) and **match its choices exactly**,
   including which terms it deliberately leaves in English. Record any new
   cross-locale decision back into GLOSSARY.md.

   **Preferred mechanism:** write the translations as a
   `TRANSLATIONS = {msgid: msgstr}` dict in `l10n/_tr_<locale>.py` (untracked
   session file), then run `python -X utf8 l10n/apply_translations.py <locale>`
   to build the overlay catalog with provenance comments, a typo guard on
   msgids, and a report of what remains untranslated.

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
