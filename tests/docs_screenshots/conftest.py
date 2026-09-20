import os
import sys
from pathlib import Path

# The real-screen harness modules (base, ui_driver, real_screen_fixtures) live
# directly under tests/, not in this package.
_TESTS_DIR = Path(__file__).resolve().parent.parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))


def pytest_ignore_collect(collection_path, config):
    """Only collect the docs captures when an output directory is configured."""
    if not os.environ.get("SEEDSIGNER_DOCS_OUT"):
        return True
    return None
