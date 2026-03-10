import os
import pytest

TRANSLATIONS_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "src",
    "seedsigner",
    "resources",
    "seedsigner-translations",
    "l10n",
)

def _translations_available() -> bool:
    return os.path.isdir(TRANSLATIONS_DIR) and any(
        file.endswith(".mo")
        for _, _, files in os.walk(TRANSLATIONS_DIR)
        for file in files
    )


def pytest_ignore_collect(collection_path, config):
    if not _translations_available() and "screenshot_generator" in str(collection_path):
        return True



def pytest_addoption(parser):
    parser.addoption("--locale", action="store", default=None)


@pytest.fixture(scope='session')
def target_locale(request):
    return request.config.option.locale
