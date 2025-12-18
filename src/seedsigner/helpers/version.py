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


    @classmethod
    def _get_dot_git_dir(cls) -> str:
        # If it exists, the .git dir will be in the project root
        path = os.path.dirname(os.path.abspath(__file__))
        project_root = path.rsplit("/src", 1)[0]

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
    def get_version(cls) -> str:
        """
            Will attempt to read the current git branch name or commit hash from
            .git/HEAD. But if there's no git info available, it will fall back to the
            hard-coded VERSION constant.
        """
        name = f"v{cls.VERSION}"

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

        return name


    @classmethod
    def get_last_src_edit(cls) -> datetime:
        """
        Recursively scan the src/ directory for the most recent python file edit time.
        """
        try:
            path = os.path.dirname(os.path.abspath(__file__))
            src_path = path.rsplit("/src", 1)[0] + "/src"

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

            # Sanity check
            if num_files == 0:
                raise Exception(f"No python source files found in {src_path}")

            return datetime.fromtimestamp(last_modified)

        except Exception as e:
            # Catch and log any unexpected errors but this isn't a mission-critical
            # function so return gracefully.
            import traceback
            logger.error(traceback.format_exc())
            return None