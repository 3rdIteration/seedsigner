"""Build a fork overlay catalog from a translation dict.

Part of the /translate-gaps workflow (see .claude/commands/translate-gaps.md
and l10n/README.md):

1. Create l10n/_tr_<locale>.py containing a ``TRANSLATIONS = {msgid: msgstr}``
   dict (the leading underscore keeps it untracked; it's a session working file).
2. Run:  python -X utf8 l10n/apply_translations.py <locale>
3. The overlay at l10n/fork/<locale>/messages.po is rebuilt with every pot-gap
   msgid found in the dict (ids upstream already translated are skipped, and a
   ``FORK: translated by Claude <date>`` provenance comment is added to each).
4. The script fails on dict keys that don't exist in messages.pot (typo guard)
   and lists any gaps left untranslated so deliberate skips are visible.
"""
import datetime
import importlib
import sys

sys.path.insert(0, "l10n")
from babel.messages.catalog import Catalog

from fork_translations import (
    load_catalog, load_overlay, load_pot, save_overlay,
    translated_ids, upstream_po_path,
)


def main(locale: str) -> int:
    mod = importlib.import_module(f"_tr_{locale}")
    translations = mod.TRANSLATIONS

    pot = load_pot()
    pot_ids = {m.id for m in pot if m.id}
    upstream_done = translated_ids(load_catalog(upstream_po_path(locale), locale))
    date = datetime.date.today().isoformat()

    unknown = sorted(k for k in translations if k not in pot_ids)
    if unknown:
        print(f"ERROR: {len(unknown)} translation key(s) not in messages.pot:")
        for key in unknown:
            print("   ", repr(key))
        return 1

    catalog = Catalog(locale=locale, domain="messages", fuzzy=False)
    catalog.header_comment = load_overlay(locale).header_comment

    filled = 0
    untranslated = []
    for message in pot:
        if not message.id or message.id in upstream_done:
            continue
        translation = translations.get(message.id)
        if translation:
            catalog.add(
                message.id,
                string=translation,
                locations=message.locations,
                auto_comments=[f"FORK: translated by Claude {date}"] + list(message.auto_comments),
            )
            filled += 1
        else:
            untranslated.append(message.id)

    save_overlay(locale, catalog)
    print(f"{locale}: filled {filled}; left untranslated: {len(untranslated)}")
    for mid in untranslated:
        print("   (gap)", repr(mid))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
