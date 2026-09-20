"""Collect the curated static screenshots the documentation embeds.

The screenshot generator renders every stock screen into a locale tree
(`<root>/en/<section>/<Name>.png`). The docs only reference a subset, so this script
copies exactly those files into `docs/img/guide/`, keeping the generated set out of the
repository.

The smartcard card-data screenshots are produced separately by the jcardsim capture
(`tests/docs_screenshots`), which writes into `docs/img/guide/` directly.

Usage:
    python tools/collect_docs_screenshots.py <generator-root>/en
"""

import sys
from pathlib import Path

# section under the generator locale tree -> destination under docs/img/guide
SECTION_COPIES = {
    "smartcard_views": "smartcard",
    "password_generator_views": "password_generator",
    "microsd_views": "microsd",
}

# per-source-section explicit files -> destination under docs/img/guide
FILE_COPIES = {
    "seed_views": ("seed_views", ["LoadSeedView.png", "SeedBackupView.png", "SeedOptionsView.png"]),
    "tools_views": ("tools", ["ToolsMenuView.png"]),
}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    source = Path(sys.argv[1]).resolve()
    if not source.is_dir():
        print(f"generator output not found: {source}")
        return 1

    repo_root = Path(__file__).resolve().parent.parent
    dest_root = repo_root / "docs" / "img" / "guide"

    copied = 0
    for section, dest in SECTION_COPIES.items():
        src_dir = source / section
        if not src_dir.is_dir():
            print(f"warning: missing generator section {section}")
            continue
        (dest_root / dest).mkdir(parents=True, exist_ok=True)
        for png in sorted(src_dir.glob("*.png")):
            (dest_root / dest / png.name).write_bytes(png.read_bytes())
            copied += 1

    for section, (dest, names) in FILE_COPIES.items():
        (dest_root / dest).mkdir(parents=True, exist_ok=True)
        for name in names:
            png = source / section / name
            if not png.is_file():
                print(f"warning: missing {section}/{name}")
                continue
            (dest_root / dest / name).write_bytes(png.read_bytes())
            copied += 1

    print(f"collected {copied} screenshots into {dest_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
