"""
setup.py for the python-babel integration (e.g. python setup.py extract_messages).
See the configuration in setup.cfg.

`compile_catalog` is overridden to merge the fork's translation overlay catalogs
(l10n/fork/<locale>/messages.po) into the upstream catalogs from the
seedsigner-translations submodule before writing each .mo. Upstream translations
always win for any msgid they cover; the overlay only fills the gaps for
fork-added strings. See l10n/README.md and l10n/fork_translations.py.

This keeps every build path (CI, seedsigner-os image builds, local dev) on the
same single command it already runs: `python setup.py compile_catalog`.
"""
import os

import setuptools

# Babel is only needed for the translation commands (e.g. `python setup.py
# compile_catalog`). Those run in an environment that has
# l10n/requirements-l10n.txt installed. Babel is NOT available during the
# isolated build that `pip install -e .` performs, so import it lazily and fall
# back to a plain setup() when it is absent — otherwise the editable install
# fails with ModuleNotFoundError before compile_catalog is ever invoked. Any
# environment that actually runs `compile_catalog` must have babel installed
# (see l10n/requirements-l10n.txt); without it the command is simply unavailable.
try:
    from babel.messages.frontend import compile_catalog
    from babel.messages.mofile import write_mo
    from babel.messages.pofile import read_po
    HAVE_BABEL = True
except ImportError:
    HAVE_BABEL = False

OVERLAY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "l10n", "fork")

cmdclass = {}

if HAVE_BABEL:

    class compile_catalog_with_overlay(compile_catalog):
        """Compile upstream + fork-overlay catalogs into a single .mo per locale."""

        def run(self):
            # babel's finalize_options() turns `domain` into a list
            domains = self.domain if isinstance(self.domain, list) else [self.domain]
            # Honor `-l <locale>` filtering (babel accepts a comma-separated list)
            only_locales = None
            if self.locale:
                only_locales = self.locale if isinstance(self.locale, list) else [loc.strip() for loc in self.locale.split(",")]
            for domain in domains:
                for locale in sorted(os.listdir(self.directory)):
                    if only_locales and locale not in only_locales:
                        continue
                    upstream_po = os.path.join(self.directory, locale, "LC_MESSAGES", f"{domain}.po")
                    if not os.path.isfile(upstream_po):
                        continue

                    with open(upstream_po, "rb") as f:
                        catalog = read_po(f, locale=locale, domain=domain)

                    overlay_po = os.path.join(OVERLAY_DIR, locale, f"{domain}.po")
                    merged = 0
                    if os.path.isfile(overlay_po):
                        with open(overlay_po, "rb") as f:
                            overlay = read_po(f, locale=locale, domain=domain)
                        for message in overlay:
                            if not message.id or not message.string:
                                continue
                            existing = catalog.get(message.id, context=message.context)
                            if existing is None:
                                catalog.add(
                                    message.id,
                                    string=message.string,
                                    context=message.context,
                                    flags=message.flags,
                                )
                                merged += 1
                            elif not existing.string:
                                existing.string = message.string
                                merged += 1

                    mo_path = os.path.join(self.directory, locale, "LC_MESSAGES", f"{domain}.mo")
                    self.log.info(
                        "compiling catalog %s to %s (+%d fork overlay entries)",
                        upstream_po, mo_path, merged,
                    )
                    with open(mo_path, "wb") as f:
                        write_mo(f, catalog, use_fuzzy=self.use_fuzzy)

            return 0

    cmdclass["compile_catalog"] = compile_catalog_with_overlay


setuptools.setup(
    cmdclass=cmdclass,
)
