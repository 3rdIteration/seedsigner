"""Regression guard for the keycard-only refactor.

The Satochip-as-Bitcoin-wallet flows were removed along with the on-device
seed manager (``models.seed``, ``views.seed_views``, ``views.psbt_views``,
``models.bip38``).  Several of those removed views imported the now-deleted
modules from inside their ``run()`` methods, so a stray re-introduction would
only surface as an ``ImportError`` at navigation time on real hardware.

These tests import the surviving view/model modules eagerly and assert the
removed Satochip-wallet classes stay gone, so any regression fails in CI
instead of on a user's device.
"""

import importlib

import pytest


def test_core_view_modules_import_clean():
    # Eager import must not raise (e.g. a module-level import of a deleted
    # module).  These are the modules that previously carried the broken
    # function-level imports.
    importlib.import_module("seedsigner.views.tools_views")
    importlib.import_module("seedsigner.models.decode_qr")


def test_removed_satochip_wallet_views_are_gone():
    tools_views = importlib.import_module("seedsigner.views.tools_views")
    for name in (
        "ToolsSatochipView",
        "ToolsSatochipLoadPsbtView",
        "ToolsSatochipImportSeedView",
        "ToolsSatochipEnable2FAView",
        "SatochipExportXpubSigTypeView",
        "SatochipLoadDescriptorScriptTypeView",
        "ToolsSatochipDIYView",
        "ToolsJavacardKeysView",
        "ToolsDIYInstallAppletView",
        "ToolsSeedkeeperLoadDescriptorView",
        "ToolsSeedkeeperSaveDescriptorView",
    ):
        assert not hasattr(tools_views, name), f"{name} should have been removed"


def test_deleted_modules_stay_deleted():
    for mod in (
        "seedsigner.models.seed",
        "seedsigner.models.bip38",
        "seedsigner.views.seed_views",
        "seedsigner.views.psbt_views",
    ):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(mod)


def test_seedkeeper_secret_views_survive():
    # The SeedKeeper secret-storage flows must remain reachable.
    tools_views = importlib.import_module("seedsigner.views.tools_views")
    for name in (
        "ToolsSeedkeeperView",
        "ToolsSeedkeeperViewSecretsView",
        "ToolsSeedkeeperImportPasswordView",
        "ToolsSeedkeeperDeleteSecretView",
        "ToolsSeedkeeperCloneSecretsView",
    ):
        assert hasattr(tools_views, name), f"{name} must survive the refactor"
