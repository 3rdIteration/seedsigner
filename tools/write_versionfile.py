import json

from seedsigner.helpers.version import VersionUtils


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
        * In local dev will fall back to using `git` shell commands:
            * Current git branch name
            * Current git tag name
            * Current git commit hash

    * version_fork:
        * Pulls the current repo owner from the `git remote` shell command.

    * version_timestamp:
        * Pulls last git commit time from `git log`.    

    * version_commit_hash:
        * Pulls current git commit hash from `git` shell command.
"""

if __name__ == "__main__":
    version_info = dict()

    for get_version_name_method in [
        VersionUtils._get_version_name_from_env_var,
        VersionUtils._get_version_name_from_git_shell,
    ]:
        version_name = get_version_name_method()
        if version_name:
            break

    version_timestamp = VersionUtils._get_version_timestamp_from_git_shell()
    version_commit_hash = VersionUtils._get_full_commit_hash_from_git_shell()

    if not version_name or not version_timestamp or not version_commit_hash:
        raise Exception("Could not determine version information from git.")

    version_info[VersionUtils.VERSIONFILE_ATTR__NAME] = version_name
    version_info[VersionUtils.VERSIONFILE_ATTR__FORK] = VersionUtils._get_version_fork_from_git_shell()
    version_info[VersionUtils.VERSIONFILE_ATTR__TIMESTAMP] = version_timestamp.isoformat()
    version_info[VersionUtils.VERSIONFILE_ATTR__COMMIT_HASH] = version_commit_hash[:7]  # short hash

    version_file_path = VersionUtils._get_version_file_path()
    with open(version_file_path, "w") as f:
        json.dump(version_info, f, indent=4)

    print(f"Wrote version info to: {version_file_path}")
    print(json.dumps(version_info, indent=4))
