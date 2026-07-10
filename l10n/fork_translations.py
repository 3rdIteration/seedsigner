#!/usr/bin/env python3
"""Manage the fork's translation overlay catalogs.

The fork adds UI strings that upstream's translators (Transifex) will never see.
Those translations live in overlay catalogs at ``l10n/fork/<locale>/messages.po``
containing ONLY the fork-gap entries. At build time the custom ``compile_catalog``
command in setup.py merges each upstream catalog (in the seedsigner-translations
submodule) with its overlay — upstream always wins for any msgid it has translated —
and writes the combined ``.mo``.

Subcommands:
    status  Per-locale coverage table (pot vs upstream vs overlay).
    stub    Add missing msgids to a locale's overlay catalog with empty msgstr.
    prune   Drop overlay entries now translated upstream or gone from the pot.
    check   Validate overlay catalogs (parse, placeholders, stray empties).

Run from the repo root, e.g.:
    python l10n/fork_translations.py status
    python l10n/fork_translations.py stub --locale es
    python l10n/fork_translations.py stub --all
    python l10n/fork_translations.py prune
    python l10n/fork_translations.py check
"""
import argparse
import os
import re
import sys

from babel.messages.catalog import Catalog
from babel.messages.pofile import read_po, write_po


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POT_PATH = os.path.join(REPO_ROOT, "l10n", "messages.pot")
UPSTREAM_L10N_DIR = os.path.join(
    REPO_ROOT, "src", "seedsigner", "resources", "seedsigner-translations", "l10n"
)
OVERLAY_DIR = os.path.join(REPO_ROOT, "l10n", "fork")

# Matches str.format() placeholders, both positional and named: {}, {0}, {name}
FORMAT_PLACEHOLDER_REGEX = re.compile(r"\{[a-zA-Z0-9_]*\}")


def load_pot() -> Catalog:
    with open(POT_PATH, "rb") as f:
        return read_po(f)


def upstream_locales() -> list[str]:
    if not os.path.isdir(UPSTREAM_L10N_DIR):
        raise SystemExit(
            f"Upstream l10n dir not found: {UPSTREAM_L10N_DIR}\n"
            "Did you run `git submodule update --init`?"
        )
    return sorted(
        d for d in os.listdir(UPSTREAM_L10N_DIR)
        if os.path.isfile(os.path.join(UPSTREAM_L10N_DIR, d, "LC_MESSAGES", "messages.po"))
    )


def upstream_po_path(locale: str) -> str:
    return os.path.join(UPSTREAM_L10N_DIR, locale, "LC_MESSAGES", "messages.po")


def overlay_po_path(locale: str) -> str:
    return os.path.join(OVERLAY_DIR, locale, "messages.po")


def load_catalog(path: str, locale: str = None) -> Catalog:
    with open(path, "rb") as f:
        return read_po(f, locale=locale)


def load_overlay(locale: str) -> Catalog:
    path = overlay_po_path(locale)
    if os.path.isfile(path):
        return load_catalog(path, locale=locale)
    catalog = Catalog(locale=locale, domain="messages", fuzzy=False)
    catalog.header_comment = (
        "# Fork translation overlay for SeedSigner (3rdIteration fork).\n"
        "# Contains ONLY strings that upstream's catalogs do not translate.\n"
        "# Merged with the upstream catalog at build time (upstream wins on overlap).\n"
        "# Managed by l10n/fork_translations.py — see l10n/README.md."
    )
    return catalog


def save_overlay(locale: str, catalog: Catalog):
    path = overlay_po_path(locale)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        write_po(f, catalog, width=0, sort_by_file=False, omit_header=False)


def translated_ids(catalog: Catalog) -> set:
    """msgids with a non-empty msgstr (excludes the header entry)."""
    return {m.id for m in catalog if m.id and m.string}


def all_ids(catalog: Catalog) -> set:
    return {m.id for m in catalog if m.id}


def cmd_status(args) -> int:
    pot_ids = all_ids(load_pot())
    print(f"messages.pot: {len(pot_ids)} translatable strings\n")
    print(f"{'locale':12} {'upstream':>9} {'overlay':>8} {'stubs':>6} {'gap':>6} {'coverage':>9}")
    print("-" * 56)
    for locale in upstream_locales():
        upstream_done = translated_ids(load_catalog(upstream_po_path(locale), locale)) & pot_ids
        overlay = load_overlay(locale)
        overlay_done = (translated_ids(overlay) & pot_ids) - upstream_done
        overlay_stubs = (all_ids(overlay) & pot_ids) - translated_ids(overlay) - upstream_done
        gap = len(pot_ids) - len(upstream_done) - len(overlay_done)
        coverage = (len(upstream_done) + len(overlay_done)) / len(pot_ids)
        print(f"{locale:12} {len(upstream_done):>9} {len(overlay_done):>8} {len(overlay_stubs):>6} {gap:>6} {coverage:>8.1%}")
    return 0


def cmd_stub(args) -> int:
    pot = load_pot()
    pot_ids = all_ids(pot)
    locales = upstream_locales() if args.all else [args.locale]
    for locale in locales:
        if not os.path.isfile(upstream_po_path(locale)):
            print(f"{locale}: no upstream catalog; skipping")
            continue
        upstream_done = translated_ids(load_catalog(upstream_po_path(locale), locale))
        overlay = load_overlay(locale)
        existing = all_ids(overlay)
        added = 0
        for message in pot:
            if not message.id or message.id in upstream_done or message.id in existing:
                continue
            overlay.add(
                message.id,
                string="",
                locations=message.locations,
                auto_comments=message.auto_comments,
                context=message.context,
            )
            added += 1
        if added:
            save_overlay(locale, overlay)
        print(f"{locale}: added {added} stub(s) -> {os.path.relpath(overlay_po_path(locale), REPO_ROOT)}")
    return 0


def cmd_prune(args) -> int:
    pot_ids = all_ids(load_pot())
    for locale in upstream_locales():
        path = overlay_po_path(locale)
        if not os.path.isfile(path):
            continue
        upstream_done = translated_ids(load_catalog(upstream_po_path(locale), locale))
        overlay = load_overlay(locale)
        kept = Catalog(locale=locale, domain="messages", fuzzy=False)
        kept.header_comment = overlay.header_comment
        dropped_upstream = dropped_obsolete = 0
        for message in overlay:
            if not message.id:
                continue
            if message.id in upstream_done:
                dropped_upstream += 1
                continue
            if message.id not in pot_ids:
                dropped_obsolete += 1
                continue
            kept.add(
                message.id,
                string=message.string,
                locations=message.locations,
                auto_comments=message.auto_comments,
                user_comments=message.user_comments,
                context=message.context,
                flags=message.flags,
            )
        if dropped_upstream or dropped_obsolete:
            save_overlay(locale, kept)
        print(
            f"{locale}: dropped {dropped_upstream} now-translated-upstream, "
            f"{dropped_obsolete} obsolete; {len(all_ids(kept))} entries remain"
        )
    return 0


def cmd_check(args) -> int:
    pot_ids = all_ids(load_pot())
    errors = 0
    checked = 0
    for locale in upstream_locales():
        path = overlay_po_path(locale)
        if not os.path.isfile(path):
            continue
        checked += 1
        try:
            overlay = load_catalog(path, locale)
        except Exception as e:
            print(f"ERROR {locale}: catalog does not parse: {e}")
            errors += 1
            continue

        upstream_done = translated_ids(load_catalog(upstream_po_path(locale), locale))
        for message in overlay:
            if not message.id:
                continue
            prefix = f"{locale}: {message.id[:60]!r}"
            if message.id not in pot_ids:
                print(f"WARN  {prefix} not in messages.pot (run prune)")
            if message.id in upstream_done:
                print(f"WARN  {prefix} already translated upstream (run prune)")
            if message.string:
                src_ph = sorted(FORMAT_PLACEHOLDER_REGEX.findall(message.id))
                dst_ph = sorted(FORMAT_PLACEHOLDER_REGEX.findall(message.string))
                if src_ph != dst_ph:
                    print(f"ERROR {prefix} placeholder mismatch: {src_ph} vs {dst_ph}")
                    errors += 1
                if message.id.count("\n") != message.string.count("\n"):
                    print(f"WARN  {prefix} line-break count differs from source")
    print(f"\nChecked {checked} overlay catalog(s); {errors} error(s).")
    return 1 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Per-locale coverage report")

    p_stub = sub.add_parser("stub", help="Add missing msgids to an overlay catalog")
    group = p_stub.add_mutually_exclusive_group(required=True)
    group.add_argument("--locale", help="Locale code, e.g. es, de, zh_Hans_CN")
    group.add_argument("--all", action="store_true", help="Stub every upstream locale")

    sub.add_parser("prune", help="Drop entries now translated upstream or gone from the pot")
    sub.add_parser("check", help="Validate overlay catalogs")

    args = parser.parse_args()
    return {"status": cmd_status, "stub": cmd_stub, "prune": cmd_prune, "check": cmd_check}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
