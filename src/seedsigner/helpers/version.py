import json
import logging
import os
from datetime import datetime


logger = logging.getLogger(__name__)



class Version:
    """
    Utility class to detect the current version and the last edit time of the source code.

    Version detection attempts to read the current git branch, commit hash, or tag but
    will fall back to the hard-coded VERSION constant if no git info is available.

    Internal utility functions are separated out as class methods for easier mocking in tests.
    """

    VERSION = "0.8.6"

    VERSION_FILENAME = "version.json"


    @classmethod
    def _get_dot_git_dir(cls) -> str:
        # If it exists, the .git dir will be in the project root
        path = os.path.dirname(os.path.abspath(__file__))

        # Have to back out of "helpers" and "seedsigner" and "src" dirs
        project_root = os.path.join(path, "..", "..", "..")

        return os.path.join(project_root, ".git")


    @classmethod
    def _read_HEAD_file(cls) -> tuple[str,str]:
        git_HEAD_path = os.path.join(cls._get_dot_git_dir(), "HEAD")

        branch_name = None
        commit_hash = None
        if os.path.exists(git_HEAD_path):
            with open(git_HEAD_path, "r") as f:
                git_ref = f.read().strip()
                if git_ref.startswith("ref:"):
                    # HEAD format: "ref: refs/heads/some_branch_name"
                    branch_name = git_ref.split("/")[-1]
                else:
                    # If we're on a detached HEAD, the contents will just be the current
                    # commit hash.
                    commit_hash = git_ref
        return (branch_name, commit_hash)


    @classmethod
    def _get_matching_tag(cls, commit_hash: str) -> str:
        # Check the .git/refs/tags dir for a tag matching this commit hash
        git_refs_tags_dir = os.path.join(cls._get_dot_git_dir(), "refs", "tags")
        if os.path.exists(git_refs_tags_dir):
            for tag_filename in os.listdir(git_refs_tags_dir):
                tag_path = os.path.join(git_refs_tags_dir, tag_filename)
                with open(tag_path, "r") as tag_file:
                    # Tag files just contain their associated commit hash
                    tag_commit_hash = tag_file.read().strip()
                    if tag_commit_hash == commit_hash:
                        # Filename is the tag name
                        return tag_filename
        return None


    @classmethod
    def _get_version_file_path(cls) -> str:
        # Have to back out of "helpers" dir to the main "seedsigner" dir
        return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", cls.VERSION_FILENAME))


    @classmethod
    def _get_version_file(cls) -> dict | None:
        """
        Attempts to read the VERSION_FILENAME and return its contents as a dict.
        """
        version_file_path = cls._get_version_file_path()
        try:
            with open(version_file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            # In local dev we don't expect/want this file to exist
            pass
        return None


    @classmethod
    def get_version(cls) -> str:
        """
            Will attempt to read the current git branch name or commit hash from
            .git/HEAD. But if there's no git info available, it will fall back to the
            hard-coded VERSION constant.
        """
        name = None
        branch_name, commit_hash = cls._read_HEAD_file()
        if branch_name:
            name = branch_name
        elif commit_hash:
            # See if this commit_hash matches a tag
            matching_tag = cls._get_matching_tag(commit_hash)
            if matching_tag:
                name = matching_tag
            else:
                name = commit_hash[:7]  # short commit hash
        
        if name is None:
            # Try reading from version.json file
            version_file_data = cls._get_version_file()
            if version_file_data:
                name = version_file_data.get("version")

        if name is None:
            # Fallback to hard-coded version
            name = f"v{cls.VERSION}"

        return name


    @classmethod
    def get_last_src_edit(cls) -> datetime:
        """
        Recursively scan the src/ directory for the most recent python file edit time.
        """
        try:
            path = os.path.dirname(os.path.abspath(__file__))

            # Have to back out of "helpers" and "seedsigner" dirs
            src_path = os.path.join(path, "..", "..")

            last_modified = 0.0
            num_files = 0
            for dirpath, dirnames, filenames in os.walk(src_path):
                if "__pycache__" in dirpath:
                    continue
                for filename in filenames:
                    if filename.endswith(".py"):
                        num_files += 1
                        filepath = os.path.join(dirpath, filename)

                        # getmtime returns the file's last modified time
                        file_mtime = os.path.getmtime(filepath)
                        last_modified = max(file_mtime, last_modified)

            if num_files == 0:
                # Fallback to reading from the version file
                version_file_data = cls._get_version_file()
                if version_file_data:
                    last_src_edit_str = version_file_data.get("last_src_edit")
                    return datetime.fromisoformat(last_src_edit_str)

            return datetime.fromtimestamp(last_modified)

        except Exception as e:
            # Catch and log any unexpected errors but this isn't a mission-critical
            # function so return gracefully.
            import traceback
            logger.error(traceback.format_exc())
            return None


if __name__ == "__main__":
    """
    CLI to extract the current version and last edit time and write to `src/seedsigner/version.json`.
    """
    version_info = dict(version=Version.get_version())
    last_edit_dt = Version.get_last_src_edit()
    if last_edit_dt:
        version_info["last_src_edit"] = last_edit_dt.isoformat()

    version_file_path = Version._get_version_file_path()
    with open(version_file_path, "w") as f:
        json.dump(version_info, f, indent=4)

    print(f"Wrote version info to: {version_file_path}")
    print(json.dumps(version_info, indent=4))