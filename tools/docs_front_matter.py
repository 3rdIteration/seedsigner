#!/usr/bin/env python3
"""Inject just-the-docs front matter into the docs/ markdown for the Pages build.

Reads the navigation tree from docs/nav.yml and, for every listed page, prepends
the YAML front matter the theme needs (title, layout, nav_order, parent links).
Section groups without a real page get a small generated landing page under
docs/nav/ listing their children. The markdown files in git stay front-matter
free so they still read nicely when browsed directly on GitHub.

Run from the repository root (see .github/workflows/docs-pages.yml):

    python3 tools/docs_front_matter.py docs

Idempotent: files that already carry front matter are left untouched, and the
generated docs/nav/ directory is rebuilt from scratch each run. Fails the build
on nav.yml entries pointing at missing files, and warns (but keeps the page out
of the sidebar via nav_exclude) for any page nav.yml forgot.
"""

import re
import sys
from pathlib import Path

import yaml

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE_RE = re.compile(r"^\s*(```|~~~)")


def page_title(md_path: Path) -> str:
    """Title for a markdown file: first ATX heading outside code fences, else filename."""
    in_fence = False
    for line in md_path.read_text(encoding="utf-8").splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            m = HEADING_RE.match(line)
            if m:
                return m.group(2).strip()
    return md_path.stem.replace("_", " ").replace("-", " ").title()


def front_matter(meta: dict) -> str:
    body = yaml.safe_dump(meta, sort_keys=False, allow_unicode=True, width=10_000)
    return "---\n" + body + "---\n"


def slugify(text: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", text.lower())).strip("-")


class NavBuilder:
    def __init__(self, docs: Path):
        self.docs = docs.resolve()
        self.errors: list[str] = []
        self.covered: set[Path] = set()
        self.written: list[Path] = []

    def resolve(self, rel: str) -> Path:
        path = (self.docs / rel).resolve()
        if not path.is_file():
            self.errors.append(f"nav.yml entry points at a missing file: {rel}")
        return path

    def inject(self, path: Path, meta: dict) -> None:
        if not path.is_file():
            return  # already reported by resolve()
        text = path.read_text(encoding="utf-8")
        if text.startswith("---\n"):
            self.errors.append(f"{path} unexpectedly already has front matter; "
                               "committing front matter to a nav.yml-listed page "
                               "would silently drop it from the sidebar")
            return
        path.write_text(front_matter(meta) + text, encoding="utf-8")
        self.covered.add(path)
        self.written.append(path)

    def page_meta(self, entry: dict, path: Path, order: int,
                  parent: str | None, grand_parent: str | None) -> dict:
        meta: dict = {"layout": "default", "title": entry.get("title") or page_title(path)}
        if parent:
            meta["parent"] = parent
        if grand_parent:
            meta["grand_parent"] = grand_parent
        meta["nav_order"] = order
        if entry.get("nav_exclude"):
            meta["nav_exclude"] = True
        return meta

    def section_meta(self, title: str, order: int) -> dict:
        return {"layout": "default", "title": title, "nav_order": order,
                "has_children": True, "nav_fold": True}

    def build(self, nav: dict) -> list[str]:
        """Return the sidebar outline (for logging)."""
        stub_dir = self.docs / "nav"
        if stub_dir.exists():
            for old in stub_dir.glob("*.md"):
                old.unlink()
        outline: list[str] = []
        for order, section in enumerate(nav["sections"], start=1):
            title = section["title"]
            if "path" in section:  # section IS a page (e.g. Home)
                path = self.resolve(section["path"])
                self.inject(path, self.page_meta(section, path, order, None, None))
                outline.append(title)
                continue
            # section is a group: generate its landing page, then process children
            self.docs.joinpath("nav").mkdir(exist_ok=True)
            stub = stub_dir / (slugify(title) + ".md")
            lines = []
            for child_order, child in enumerate(section.get("pages", []), start=1):
                lines.append(self.build_page(child, child_order, title, None, stub, ""))
            stub_meta = self.section_meta(title, order)
            stub.write_text(
                front_matter(stub_meta) + (section.get("desc") or "") + "\n\n"
                + "\n".join(lines) + "\n", encoding="utf-8")
            outline.append(title)
        return outline

    def build_page(self, child, order: int, parent: str,
                   grand_parent: str | None, stub: Path, indent: str) -> str:
        """Inject a (sub)page and return its markdown bullet for the stub page."""
        entry = {"path": child} if isinstance(child, str) else child
        if entry.get("pages"):  # nested subgroup -> another stub, one level down
            sub_stub = stub.with_name(stub.stem + "-" + slugify(entry["title"]) + ".md")
            sub_lines = [self.build_page(sub, i, entry["title"], parent, sub_stub, "  ")
                         for i, sub in enumerate(entry["pages"], start=1)]
            sub_meta = self.section_meta(entry["title"], order)
            # nested groups also need parent/grand_parent so they nest in the tree
            sub_meta["parent"] = parent
            sub_stub.write_text(
                front_matter(sub_meta) + (entry.get("desc") or "") + "\n\n"
                + "\n".join(sub_lines) + "\n", encoding="utf-8")
            url = self.site_url(sub_stub)
            return f"{indent}- [{entry['title']}]({url})"
        path = self.resolve(entry["path"])
        meta = self.page_meta(entry, path, order, parent, grand_parent)
        self.inject(path, meta)
        title = entry.get("title") or meta["title"]
        return f"{indent}- [{title}]({self.site_url(path)})"

    def site_url(self, path: Path) -> str:
        rel = path.relative_to(self.docs).with_suffix(".html")
        return "{{ site.baseurl }}/" + str(rel).replace("\\", "/")

    def exclude_unlisted(self) -> list[Path]:
        """Everything rendered but absent from nav.yml gets layout + nav_exclude."""
        skip_roots = [(self.docs / "nav").resolve()]
        orphans = []
        for md in sorted(self.docs.rglob("*.md")):
            if any(md.is_relative_to(r) for r in skip_roots) or md in self.covered:
                continue
            if md.read_text(encoding="utf-8").startswith("---\n"):
                continue
            orphans.append(md)
            md.write_text(front_matter({"layout": "default", "title": page_title(md),
                                        "nav_exclude": True})
                          + md.read_text(encoding="utf-8"), encoding="utf-8")
        return orphans


def write_index_md(docs: Path, nav: dict) -> Path | None:
    """Emit docs/index.md (rendered at the site root) from the Home section's page.

    The Home page itself gets nav_exclude so it does not appear twice; index.md
    carries the real "Home" front matter. Doing this in the build keeps the root
    independent of jekyll-readme-index, which only maps front-matter-less readmes.
    """
    index = docs / "index.md"
    if index.exists():
        index.unlink()  # always regenerated from the Home page; never committed
    for section in nav["sections"]:
        if "path" not in section:
            continue
        source = (docs / section["path"]).resolve()
        body = source.read_text(encoding="utf-8")
        if body.startswith("---\n"):
            body = body.split("---\n", 2)[2]
        # The theme renders page.title as the H1; drop the readme's own top heading.
        body = re.sub(r"\A\s*#\s.*?\n", "\n", body, count=1)
        meta = {"layout": "default", "title": section["title"], "nav_order": 1}
        index.write_text(front_matter(meta) + body, encoding="utf-8")
        return index
    return None


def main() -> int:
    docs = Path(sys.argv[1] if len(sys.argv) > 1 else "docs").resolve()
    nav = yaml.safe_load((docs / "nav.yml").read_text(encoding="utf-8"))
    builder = NavBuilder(docs)
    outline = builder.build(nav)
    if builder.errors:
        print("\n".join("ERROR: " + e for e in builder.errors), file=sys.stderr)
        return 1
    orphans = builder.exclude_unlisted()
    home_md = write_index_md(docs, nav)
    print(f"Injected front matter into {len(builder.written)} pages; "
          f"{len(outline)} top-level sections: {', '.join(outline)}")
    if home_md:
        print(f"Generated {home_md.relative_to(Path.cwd())} (site root) from README.md")
    if orphans:
        print("Pages not listed in nav.yml (published, but hidden from the sidebar):")
        for md in orphans:
            print(f"  {md.relative_to(Path.cwd())}")
    if builder.errors:
        print("\n".join("ERROR: " + e for e in builder.errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())