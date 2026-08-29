"""Tests for the GPG trusted-projects whitelist (models.gpg_trusted_projects)."""
import base  # noqa: F401 -- ensure hardware mocks

from seedsigner.models.gpg_trusted_projects import (
    TRUSTED_PROJECTS,
    project_for_filename,
    projects_for_filename,
    projects_for_fingerprint,
)


class TestProjectsForFilename:
    def test_each_project_matches_its_artifacts(self):
        cases = {
            "seedsigner": [
                "seedsigner_os.0.8.7.pi4.img",
                "seedsigner.0.8.7.sha256.txt",
                "Seedsigner-0.9.0.zip",
            ],
            "sparrow": [
                "Sparrow-2.5.4.msi",
                "sparrow-2.5.4-manifest.txt",
                "sparrowserver-1.0.0-linux-amd64.tar.gz",
                "sparrowwallet_2.5.4_arm64.apk",
            ],
            "liana": [
                "Liana-15.0-macos.zip",
                "liana-15.0.exe",
                "liana-15.0-shasums.txt",
            ],
            "krux": ["krux-v26.08.0.zip"],
            "specter": [
                "Specter-Setup-v2.2.0-pre5.exe",
                "Specter-v2.2.0-pre5.dmg",
                "specterd-v2.2.0-pre5-win64.zip",
                "specter_desktop-v2.2.0-pre5-x86_64-linux-gnu.tar.gz",
                "cryptoadvance_specter-2.2.0rc5.tar.gz",
            ],
            "electrum": [
                "Electrum-4.8.1.tar.gz",
                "electrum-4.8.1-setup.exe",
                "Electrum-sourceonly-4.8.1.tar.gz",
                "electrum-4.8.1-arm64-v8a-release.apk",
            ],
            "bitcoincore": [
                "bitcoin-31.1-x86_64-linux-gnu.tar.gz",
                "bitcoin-31.1-win64-setup-unsigned.exe",
            ],
            "gnupg": ["gnupg-2.5.21.tar.bz2"],
            "coldcard": [
                "2026-08-20T1336-v5.6.1-mk-coldcard.dfu",
                "2026-08-20T1336-v5.6.1-mk-coldcard-factory.dfu",
                "2026-08-20T1335-v1.5.1Q-q1-coldcard.dfu",
                "cc-recovery-2026-08-25.img.xz",
                "mk4-recovery-2023-10-11.img.xz",
                "signatures.txt",
            ],
            "trezor": [
                "Trezor-Suite-22.4.3-linux-x86_64.AppImage",
                "Trezor-Suite-22.4.3-mac-x64.dmg",
                "Trezor-Suite-22.4.3-win-x64.exe",
            ],
            "casa": [
                "v2.3.11-passport.bin",
                "founders-v2.3.11-passport.bin",
            ],
            "bip39tool": ["bip39-standalone.html"],
            "bitbox02": [
                "firmware-bitbox02-btconly.v9.27.0.signed.bin",
                "firmware-bitbox02-multi.v9.27.0.signed.bin",
                "firmware-bitbox02nova-multi.v9.27.0.signed.bin",
                "bitbox02-multi-v9.27.0-simulator1.0.0-linux-amd64",
                "assertion.txt",
                "assertion-bitbox02-multi.txt",
            ],
        }
        for project_key, filenames in cases.items():
            for filename in filenames:
                assert project_for_filename(filename) is TRUSTED_PROJECTS[project_key], (
                    f"{filename!r} should match {project_key}"
                )

    def test_detached_sig_extension_is_stripped(self):
        assert project_for_filename("krux-v26.08.0.zip.sig") is TRUSTED_PROJECTS["krux"]
        # Ambiguous manifest: stripping .asc yields the same (ambiguous) result.
        assert projects_for_filename("SHA256SUMS.asc") == projects_for_filename("SHA256SUMS")
        assert project_for_filename("SHA256SUMS.asc") is None
        assert (
            projects_for_filename("liana-15.0-shasums.txt.asc")
            == [TRUSTED_PROJECTS["liana"]]
        )
        assert (
            projects_for_filename("Trezor-Suite-22.4.3-win-x64.exe.asc")
            == [TRUSTED_PROJECTS["trezor"]]
        )

    def test_matching_is_case_insensitive(self):
        assert project_for_filename("SEEDSIGNER_OS.0.8.7.PI4.IMG") is TRUSTED_PROJECTS["seedsigner"]
        assert project_for_filename("sPArRoW-2.5.4.msi") is TRUSTED_PROJECTS["sparrow"]

    def test_unknown_file_matches_nothing(self):
        assert projects_for_filename("random-file.bin") == []
        assert project_for_filename("random-file.bin") is None
        assert project_for_filename("some-random-file.bin.sig") is None

    def test_bare_sha256sums_is_ambiguous(self):
        # Published by both Specter and Bitcoin Core.
        matched = projects_for_filename("SHA256SUMS")
        assert TRUSTED_PROJECTS["specter"] in matched
        assert TRUSTED_PROJECTS["bitcoincore"] in matched
        assert len(matched) == 2
        assert project_for_filename("SHA256SUMS") is None

    def test_non_matching_base_name_stays_unmatched_with_sig_extension(self):
        assert projects_for_filename("random.bin.asc") == []
        assert projects_for_filename("random.bin.sig") == []


class TestProjectForFilename:
    def test_specter_manifest_variants(self):
        for name in ("SHA256SUMS-macos_arm64", "sha256sums"):
            matched = projects_for_filename(name)
            assert TRUSTED_PROJECTS["specter"] in matched

    def test_coldcard_dfu_requires_coldcard_in_name(self):
        # Generic .dfu files from other vendors must not match COLDCARD.
        assert project_for_filename("2026-01-01-v1.0.0-someotherwallet.dfu") is None


class TestProjectsForFingerprint:
    EMZY_FPR = "9EDAFF80E080659604F4A76B2EBB056FD847F8A7"

    def test_multi_project_signer(self):
        # Emzy signs for both Electrum and Bitcoin Core.
        matched = projects_for_fingerprint(self.EMZY_FPR)
        assert TRUSTED_PROJECTS["electrum"] in matched
        assert TRUSTED_PROJECTS["bitcoincore"] in matched
        assert len(matched) == 2

    def test_single_project_signer(self):
        matched = projects_for_fingerprint("B4281DDDFBBD207BFA4113138974C90299326322")
        assert matched == [TRUSTED_PROJECTS["krux"]]

    def test_accepts_spaced_and_lowercase_fingerprint(self):
        spaced = "b428 1ddd fbbd 207b fa41 1313 8974 c902 9932 6322"
        assert projects_for_fingerprint(spaced) == [TRUSTED_PROJECTS["krux"]]

    def test_unknown_fingerprint(self):
        assert projects_for_fingerprint("0000000000000000000000000000000000000000") == []


class TestWhitelistIntegrity:
    def test_all_fingerprints_are_40_hex_chars(self):
        for project in TRUSTED_PROJECTS.values():
            assert len(project.fingerprints) > 0, f"{project.name} has no fingerprints"
            for fpr in project.fingerprints:
                assert len(fpr) == 40 and all(c in "0123456789ABCDEF" for c in fpr), (
                    f"bad fingerprint {fpr!r} in {project.name}"
                )

    def test_every_project_has_patterns(self):
        for project in TRUSTED_PROJECTS.values():
            assert len(project.file_patterns) > 0, f"{project.name} has no file patterns"
