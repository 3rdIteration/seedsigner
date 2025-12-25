import json
import os

from seedsigner.helpers.version import Version, VersionUtils


"""
CLI utility to extract the current version data and write to
`src/seedsigner/version.json`. Primarily used by the SeedSigner OS build process.

SeedSigner OS lifecycle:
    * Build process runs this script to generate version.json.
    * version.json is included in the SeedSigner OS image.
    * SeedSigner OS reads version.json at runtime.

Notes:
    * The SeedSigner OS build environment already relies on `git` being installed.
    * This script can also be run in local dev but `git` shell commands are required.

Version data:
    * version_name:
        * Check for the SEEDSIGNER_VERSION_NAME env var (provided in SeedSigner OS build
          env).
            * Will be the branch, tag, or commit hash being built.
        * If running in local dev instead, this script will try to populate that env var
          using `git` shell commands:
            * Current git branch name
            * Current git tag name
            * Current git commit hash

    * version_fork:
        * Pulls the current repo owner from the `git remote` shell command.

    * version_timestamp:
        * Pulls last git commit time from `git log`.    

    * short_commit_hash:
        * Pulls current git commit hash from `git` shell command.
"""
if __name__ == "__main__":
    is_seedsigner_os_builder = VersionUtils._is_seedsigner_os_builder_env()

    if not is_seedsigner_os_builder:
        # Pull version_name from the current git state via `git` shell commands
        version_name = VersionUtils._get_version_name_from_git_shell()
        
        # Temporarily set the env var
        os.environ[VersionUtils.ENV_VAR__SEEDSIGNER_OS_BUILDER__VERSION_NAME] = version_name

    version_info = Version.get_instance().to_dict()
    version_file_path = VersionUtils._get_version_file_path()
    with open(version_file_path, "w") as f:
        json.dump(version_info, f, indent=4)

    print(f"Wrote version info to: {version_file_path}")
    print(json.dumps(version_info, indent=4))

    # Clean up the temp env var if needed
    if not is_seedsigner_os_builder:
        del os.environ[VersionUtils.ENV_VAR__SEEDSIGNER_OS_BUILDER__VERSION_NAME]
