import json
import os
import pytest
from datetime import datetime, timezone
from unittest import mock
from unittest.mock import Mock, patch

# Must import this before any SeedSigner imports
from base import BaseTest

from seedsigner.helpers.version import Version, VersionUtils, NotAllowedInSeedSignerOS, not_allowed_in_seedsigner_os
from seedsigner.models.settings import Settings



# overrides
TEST__VERSIONFILE__FILENAME = "version-test.json"
TEST__DOT_GIT_DIR_NAME = f"dot-git-test"

# Reusable test data
TEST__VERSION_NAME = "1.2.3"  # Will require VersionUtils._prefix_version_name when verifying results
TEST__VERSION_FORK = "some_repo_owner"
TEST__VERSION_TIMESTAMP = datetime.now().astimezone(timezone.utc).replace(tzinfo=None)
TEST__VERSION_BRANCH = "some_test_branch"
TEST__VERSION_TAG = "some_test_tag"
TEST__SEMANTIC_TAG = "1.2.3-rc1"
TEST__SHORT_COMMIT_HASH = "c5efda3"
TEST__FULL_COMMIT_HASH = "c5efda306c60877191013a6093d92cd0bfcccec8"
TEST__VERSION_DICT = {
    VersionUtils.VERSIONFILE_ATTR__NAME: TEST__VERSION_NAME,
    VersionUtils.VERSIONFILE_ATTR__FORK: TEST__VERSION_FORK,
    VersionUtils.VERSIONFILE_ATTR__TIMESTAMP: TEST__VERSION_TIMESTAMP.isoformat(),
    VersionUtils.VERSIONFILE_ATTR__COMMIT_HASH: TEST__SHORT_COMMIT_HASH,
}

# Mimic result of reading from version.json
TEST__VERSION_FILE_CONTENTS = str(TEST__VERSION_DICT).replace("'", '"')  # JSON uses double quotes



class VersionBaseTest(BaseTest):
    """ Sets up test-specific overrides and reusable methods and fixtures. """

    @pytest.fixture(autouse=True, scope="class")
    def mock_versionfile_filename(self):
        """
        Every test in this class (and subclasses) will automatically run with this patch
        applied (autouse=True), but the patch will not persist beyond the test class.
        """
        with patch.object(VersionUtils, 'VERSIONFILE__FILENAME', TEST__VERSIONFILE__FILENAME):
            yield


    @pytest.fixture(autouse=True)
    def mock_DOT_GIT_DIR_NAME(self):
        """
        Patch out the DOT_GIT_DIR_NAME to facilitate testing git-related methods
        without touching the real filesystem.
        """
        with patch.object(VersionUtils, 'DOT_GIT_DIR_NAME', TEST__DOT_GIT_DIR_NAME):
            yield


    @pytest.fixture(autouse=True)
    def mock_GITHUB_ACTIONS__IS_CI(self):
        """
        Patch out the GITHUB_ACTIONS__IS_CI env var so that tests operate under the same
        assumptions when running locally and when actually running in CI. Any test that
        needs to simulate being in CI can override this env var as needed.
        """
        with mock.patch.dict(os.environ, {VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "false"}):
            yield


    @pytest.fixture(autouse=True)
    def mock_popen(self):
        """
        Prevent any os.popen calls from actually executing during tests.
        """
        with patch("os.popen", autospec=True) as mock_popen:
            # Default to returning an empty string for `read()`
            mock_popen.return_value.read.return_value = ""
            yield mock_popen


    @classmethod
    def write_test_version_file(cls):
        """
        Write the test version file to disk.
        """
        assert VersionUtils.VERSIONFILE__FILENAME == TEST__VERSIONFILE__FILENAME
        with open(VersionUtils._get_version_file_path(), "w") as f:
            f.write(TEST__VERSION_FILE_CONTENTS)


    @classmethod
    def delete_test_version_file(cls):
        """
        Delete the test version file from disk.
        """
        assert VersionUtils.VERSIONFILE__FILENAME == TEST__VERSIONFILE__FILENAME
        try:
            os.remove(VersionUtils._get_version_file_path())
        except FileNotFoundError:
            pass


    def reset_version_singleton(self):
        Version._instance = None


    def setup_method(self):
        super().setup_method()


    def teardown_method(self):
        super().teardown_method()

        # Clean up any test version file created
        self.delete_test_version_file()

        self.reset_version_singleton()



class TestVersionBaseTest(VersionBaseTest):
    def test_setup_and_teardown(self):
        """
        Ensure that the setup and teardown methods work as expected.
        """
        assert VersionUtils.VERSIONFILE__FILENAME == TEST__VERSIONFILE__FILENAME

        # During setup, the test version file should not exist
        assert not os.path.exists(VersionUtils._get_version_file_path())

        # Write the test version file
        self.write_test_version_file()
        assert os.path.exists(VersionUtils._get_version_file_path())

        # Delete should remove it
        self.delete_test_version_file()
        assert not os.path.exists(VersionUtils._get_version_file_path())

        # Teardown should also delete the test version file
        self.write_test_version_file()
        self.teardown_method()
        assert not os.path.exists(VersionUtils._get_version_file_path())


    def test_mock_popen(self):
        """ All os.popen calls should be automatically/invisibly mocked out. """
        result = os.popen("echo 'Hello, World!'")
        assert isinstance(result, mock.MagicMock)



class TestVersionUtils_BasicCalls(VersionBaseTest):
    def test__prefix_version_name(self):
        """
        Semantic versions should be prefixed with 'v' but others should be left as-is.
        """
        # Expected to end up starting with "v":
        for version_name in [
            "1.2.3",
            "v1.2.3",
            "1.2.3-rc1",
            "v1.2.3-rc1",
            "21.known.slight.flaw",
        ]:
            result = VersionUtils._prefix_version_name(version_name)
            assert result.startswith("v"), f"Expected '{result}' to start with 'v'"
            if version_name.startswith("v"):
                assert result == version_name, f"Expected '{result}' to equal input '{version_name}'"

        # Expect no change:
        for version_name in [
            "release-branch",
            "feature/foo",
            "hotfix-123",
            "foo.bar.not.semantic",
            "1234abcd",
            "1234",
        ]:
            result = VersionUtils._prefix_version_name(version_name)
            assert result == version_name, f"Expected '{result}' to equal input '{version_name}'"



class TestVersionUtils_VersionFile(VersionBaseTest):
    def test_seedsigner_os_reads_from_version_file(self):
        """
        Test the high-level basic public calls. Does just the minimal necessary mocking
        since all the downstream helper methods are tested in detail elsewhere.

        When running on SeedSigner OS, the version data should be read from the
        version.json file.
        """
        self.write_test_version_file()

        # Simulate running on SeedSigner OS
        with patch("seedsigner.models.settings.Settings.HOSTNAME", Settings.SEEDSIGNER_OS):
            assert VersionUtils.get_version_name() == VersionUtils._prefix_version_name(TEST__VERSION_NAME)
            assert VersionUtils.get_version_fork() == TEST__VERSION_FORK
            assert VersionUtils.get_version_timestamp() == TEST__VERSION_TIMESTAMP
            assert VersionUtils.get_short_commit_hash() == TEST__SHORT_COMMIT_HASH

            # Expect errors if keys are missing from version.json
            with mock.patch("builtins.open", mock.mock_open(read_data="{'some_key':'some_value'}")):
                with pytest.raises(Exception):
                    VersionUtils.get_version_name()

            # This time it's the timestamp that's missing
            with mock.patch("builtins.open", mock.mock_open(read_data=str({VersionUtils.VERSIONFILE_ATTR__NAME: TEST__VERSION_NAME}).replace("'", '"'))):
                with pytest.raises(Exception):
                    VersionUtils.get_version_timestamp()



    def test__read_version_file(self):
        """
        Low-level test for reading the version.json file.
        """
        self.write_test_version_file()

        version_data = VersionUtils._read_version_file()
        assert version_data is not None
        assert version_data[VersionUtils.VERSIONFILE_ATTR__NAME] == TEST__VERSION_NAME
        assert version_data[VersionUtils.VERSIONFILE_ATTR__FORK] == TEST__VERSION_FORK
        assert version_data[VersionUtils.VERSIONFILE_ATTR__TIMESTAMP] == TEST__VERSION_TIMESTAMP.isoformat()
        assert version_data[VersionUtils.VERSIONFILE_ATTR__COMMIT_HASH] == TEST__SHORT_COMMIT_HASH


    def test__read_version_file__missing(self):
        """ _read_version_file should return None if the version file is missing. """
        assert os.path.exists(VersionUtils._get_version_file_path()) is False
        assert VersionUtils._read_version_file() is None

        # The upstream dependent calls should also return None
        assert VersionUtils._get_version_name_from_version_file() is None
        assert VersionUtils._get_version_fork_from_version_file() is None
        assert VersionUtils._get_version_timestamp_from_version_file() is None
        assert VersionUtils._get_short_commit_hash_from_version_file() is None

        # Gracefully handle other unexpected exceptions
        with patch("builtins.open", side_effect=Exception("Unexpected error")):
            assert VersionUtils._read_version_file() is None


    def test__get_version_name_from_env_var(self):
        assert os.environ.get(VersionUtils.ENV_VAR__SEEDSIGNER_OS_BUILDER__VERSION_NAME) is None
        assert VersionUtils._get_version_name_from_env_var() is None

        with mock.patch.dict(os.environ, {VersionUtils.ENV_VAR__SEEDSIGNER_OS_BUILDER__VERSION_NAME: TEST__VERSION_NAME}):
            result = VersionUtils._get_version_name_from_env_var()
            assert result == TEST__VERSION_NAME



class TestVersionUtils_GithubActions(VersionBaseTest):
    def test_github_actions_env_vars(self):
        """
        Test the high-level basic public calls. Does just the minimal necessary mocking
        since all the downstream helper methods are tested in detail elsewhere.

        When running in a GitHub Actions CI environment, the version data should be
        pulled from the appropriate env vars.
        """
        # CI uses some limited `git` shell calls; mock out the associated calls.
        with mock.patch("seedsigner.helpers.version.VersionUtils._get_version_timestamp_from_git_shell", return_value=TEST__VERSION_TIMESTAMP):
            # When running CI on a branch
            with mock.patch.dict(os.environ, {
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "true",
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__REF_NAME: TEST__VERSION_BRANCH,
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__SHA: TEST__FULL_COMMIT_HASH,
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__REPOSITORY_OWNER: TEST__VERSION_FORK,
            }):
                assert VersionUtils.get_version_name() == TEST__VERSION_BRANCH
                assert VersionUtils.get_version_fork() == TEST__VERSION_FORK
                assert VersionUtils.get_short_commit_hash() == TEST__SHORT_COMMIT_HASH
                assert VersionUtils.get_version_timestamp() == TEST__VERSION_TIMESTAMP

            # When running CI on a semantic tag
            with mock.patch.dict(os.environ, {
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "true",
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__REF_NAME: TEST__SEMANTIC_TAG,
            }):
                # Should be prefixed with "v"
                assert VersionUtils.get_version_name() == f"v{TEST__SEMANTIC_TAG}"

            # When running CI on a generic tag
            with mock.patch.dict(os.environ, {
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "true",
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__REF_NAME: TEST__VERSION_TAG,
            }):
                # Should NOT be prefixed with "v"
                assert VersionUtils.get_version_name() == TEST__VERSION_TAG

            # When running CI on a commit (detached HEAD) with no REF_NAME, the
            # version_name should be the short commit hash.
            # TODO: I don't think this scenario ever happens.
            with mock.patch.dict(os.environ, {
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "true",
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__REF_NAME: "",
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__SHA: TEST__FULL_COMMIT_HASH,
            }):
                assert VersionUtils.get_version_name() == TEST__SHORT_COMMIT_HASH

            # When running CI on a commit (detached HEAD) with no REF_NAME and no SHA,
            # raise error.
            # Note: This scenario definitely would never happen. Just trying to get to
            # 100% test coverage.
            with mock.patch.dict(os.environ, {
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "true",
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__REF_NAME: "",
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__SHA: "",
            }):
                with pytest.raises(Exception):
                    VersionUtils.get_version_name()


    def test_is_github_actions_ci(self):
        """
        is_github_actions_ci should return True only when the
        ENV_VAR__GITHUB_ACTIONS__IS_CI env var is set to "true".

        Note: Have to mock a value for ALL scenario variations here because this test will
        actually run in Github Actions so the env var will already be present!
        """
        with mock.patch.dict(os.environ, {VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "true"}):
            assert VersionUtils.is_github_actions_ci() is True

        with mock.patch.dict(os.environ, {VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "false"}):
            assert VersionUtils.is_github_actions_ci() is False

        with mock.patch.dict(os.environ, {VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "1"}):
            assert VersionUtils.is_github_actions_ci() is False


    def test_get_version_name_from_github_actions_env_vars(self):
        """
        get_version_name_from_github_actions_env_vars should return the REF_NAME or SHA
        env vars when set.
        """
        # Need to signal that we're in a GitHub Actions CI environment
        with mock.patch.dict(os.environ, {
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__IS_CI: "true",
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__REF_NAME: "",
                VersionUtils.ENV_VAR__GITHUB_ACTIONS__SHA: "",
            }):
            assert VersionUtils._get_version_name_from_github_actions_env_vars() is None

            # REF_NAME should be passed straight through
            with mock.patch.dict(os.environ, {VersionUtils.ENV_VAR__GITHUB_ACTIONS__REF_NAME: TEST__VERSION_NAME}):
                result = VersionUtils._get_version_name_from_github_actions_env_vars()
                assert result == TEST__VERSION_NAME

            # Unlikely scenario: no REF_NAME but SHA is set; should return short commit hash
            with mock.patch.dict(os.environ, {
                    VersionUtils.ENV_VAR__GITHUB_ACTIONS__REF_NAME: "",
                    VersionUtils.ENV_VAR__GITHUB_ACTIONS__SHA: TEST__FULL_COMMIT_HASH,
                }):
                result = VersionUtils._get_version_name_from_github_actions_env_vars()
                assert result == TEST__SHORT_COMMIT_HASH[:7]



class TestVersionUtils_DotGitFiles(VersionBaseTest):
    def test_local_dev_with_dot_git_dir_parsing(self, mock_popen: Mock):
        """
        Test the high-level basic public calls. Does just the minimal necessary mocking
        since all the downstream helper methods are tested in detail elsewhere.

        When running in a local dev environment without access to `git` shell commands,
        the version data should be pulled from parsing the .git directory.

        We pull in the `mock_popen` fixture here to simulate `git` shell commands failing.

        Note that in local dev we use the last modified timestamp from the source files
        rather than from git.
        """
        # If we're on a branch, getting the commit hash requires the
        # .git/refs/heads/<branch> file.
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _read_git_HEAD_file=Mock(return_value=(TEST__VERSION_BRANCH, None)),
            _get_full_commit_hash_from_git_refs_heads=Mock(return_value=TEST__FULL_COMMIT_HASH),
            _get_version_fork_from_git_config=Mock(return_value=TEST__VERSION_FORK),
            _get_version_timestamp_from_src_files=Mock(return_value=TEST__VERSION_TIMESTAMP),
        ):
            assert VersionUtils.get_version_name() == TEST__VERSION_BRANCH
            assert VersionUtils.get_version_fork() == TEST__VERSION_FORK
            assert VersionUtils.get_version_timestamp() == TEST__VERSION_TIMESTAMP
            assert VersionUtils.get_short_commit_hash() == TEST__SHORT_COMMIT_HASH

        # If we're on a tag (detached HEAD), getting the commit hash requires
        # checking the refs/tags for a matching tag.
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _read_git_HEAD_file=Mock(return_value=(None, TEST__FULL_COMMIT_HASH)),
            _get_matching_tag_from_git_refs_tags=Mock(return_value=TEST__VERSION_TAG),
        ):
            assert VersionUtils.get_version_name() == TEST__VERSION_TAG
            assert VersionUtils.get_short_commit_hash() == TEST__SHORT_COMMIT_HASH

        # If we're on a commit hash (detached HEAD) with no matching tag, the
        # version name should be the short commit hash.
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _read_git_HEAD_file=Mock(return_value=(None, TEST__FULL_COMMIT_HASH)),
            _get_matching_tag_from_git_refs_tags=Mock(return_value=None),
        ):
            assert VersionUtils.get_version_name() == TEST__SHORT_COMMIT_HASH
            assert VersionUtils.get_short_commit_hash() == TEST__SHORT_COMMIT_HASH


    def test__get_dot_git_dir(self):
        """
        _get_dot_git_dir should return the expected .git directory path.
        """
        # The mocked DOT_GIT_DIR_NAME should be in the result
        result = VersionUtils._get_dot_git_dir()
        assert TEST__DOT_GIT_DIR_NAME in result


    def test__read_git_HEAD_file(self):
        """
        _read_git_HEAD_file should parse the git HEAD file to extract the current
        branch name or commit hash. Or gracefully return None if the HEAD file is missing.
        """
        # Initially our test setup has no .git dir
        assert VersionUtils._read_git_HEAD_file() == (None, None)

        # If we're on a branch...
        git_HEAD_content = f"ref: refs/heads/{TEST__VERSION_BRANCH}"
        with patch("builtins.open", mock.mock_open(read_data=git_HEAD_content)):
            branch_name, commit_hash = VersionUtils._read_git_HEAD_file()
            assert branch_name == TEST__VERSION_BRANCH
            assert commit_hash is None

        # If we're in a detached HEAD state at a specific commit hash...
        with patch("builtins.open", mock.mock_open(read_data=TEST__FULL_COMMIT_HASH)):
            branch_name, commit_hash = VersionUtils._read_git_HEAD_file()
            assert branch_name is None
            assert commit_hash == TEST__FULL_COMMIT_HASH

        # Gracefully handle a read error
        with patch("builtins.open", side_effect=FileNotFoundError):
            assert VersionUtils._read_git_HEAD_file() == (None, None)

        # Or any other kind of exception
        with patch("builtins.open", side_effect=Exception("Unexpected error")):
            assert VersionUtils._read_git_HEAD_file() == (None, None)


    def test__get_matching_tag_from_git_refs_tags(self):
        """
        _get_matching_tag_from_git_refs_tags should return the expected tag name
        if a matching tag is found for the given commit hash.
        """
        # No .git dir initially
        assert os.path.exists(VersionUtils._get_dot_git_dir()) is False

        # Mock the os.listdir of the .git/refs/tags directory to the target tag name
        with patch("os.listdir", return_value=[TEST__VERSION_NAME]):
            # Mock the open of the tag ref file to return our test commit hash
            with patch("builtins.open", mock.mock_open(read_data=TEST__FULL_COMMIT_HASH)):
                tag_name = VersionUtils._get_matching_tag_from_git_refs_tags(TEST__FULL_COMMIT_HASH)
                assert tag_name == TEST__VERSION_NAME

        # If no matching tag is found, should return None
        with patch("os.listdir", return_value=["some_other_tag"]):
            with patch("builtins.open", mock.mock_open(read_data="different_commit_hash")):
                tag_name = VersionUtils._get_matching_tag_from_git_refs_tags(TEST__FULL_COMMIT_HASH)
                assert tag_name is None

        # If the refs/tags directory is missing, should return None
        with patch("seedsigner.helpers.version.VersionUtils._get_dot_git_dir", return_value="/nonexistent/path"):
            tag_name = VersionUtils._get_matching_tag_from_git_refs_tags(TEST__FULL_COMMIT_HASH)
            assert tag_name is None

        # If any other exception occurs, should return None
        with patch("os.listdir", side_effect=Exception("Unexpected error")):
            tag_name = VersionUtils._get_matching_tag_from_git_refs_tags(TEST__FULL_COMMIT_HASH)
            assert tag_name is None


    def test__get_version_name_from_git_HEAD(self):
        # Should gracefully return None if there's no .git dir or .git/HEAD file.
        assert VersionUtils._get_version_name_from_git_HEAD() == None

        # We already tested _read_git_HEAD_file() above, so just mock scenarios here.
        # On a branch:
        with mock.patch.object(VersionUtils, '_read_git_HEAD_file', return_value=(TEST__VERSION_BRANCH, None)):
            assert VersionUtils._get_version_name_from_git_HEAD() == TEST__VERSION_BRANCH
        
        # Detached HEAD at commit hash, with matching tag
        with mock.patch.object(VersionUtils, '_read_git_HEAD_file', return_value=(None, TEST__FULL_COMMIT_HASH)):
            with mock.patch.object(VersionUtils, '_get_matching_tag_from_git_refs_tags', return_value=TEST__VERSION_NAME):
                assert VersionUtils._get_version_name_from_git_HEAD() == TEST__VERSION_NAME
        
        # Detached HEAD at commit hash, no matching tag; returns the short commit hash
        with mock.patch.object(VersionUtils, '_read_git_HEAD_file', return_value=(None, TEST__FULL_COMMIT_HASH)):
            with mock.patch.object(VersionUtils, '_get_matching_tag_from_git_refs_tags', return_value=None):
                assert VersionUtils._get_version_name_from_git_HEAD() == TEST__SHORT_COMMIT_HASH


    def test__get_commit_hash_from_git_HEAD(self):
        # _get_commit_hash_from_git_HEAD is a trivial convenience function that relies on _read_git_HEAD_file which we've already tested.
        # Just verify the expected outputs here.
        with mock.patch.object(VersionUtils, '_read_git_HEAD_file', return_value=(None, TEST__SHORT_COMMIT_HASH)):
            assert VersionUtils._get_full_commit_hash_from_git_HEAD() == TEST__SHORT_COMMIT_HASH


    def test__get_full_commit_hash_from_git_refs_heads(self):
        """
        _get_full_commit_hash_from_git_refs_heads should return the expected commit hash
        for the given branch name.
        """
        # No .git dir initially
        assert os.path.exists(VersionUtils._get_dot_git_dir()) is False
        assert VersionUtils._get_full_commit_hash_from_git_refs_heads(TEST__VERSION_BRANCH) is None

        # Mock the open of the branch ref file to return our test commit hash
        with patch("builtins.open", mock.mock_open(read_data=TEST__FULL_COMMIT_HASH)):
            with patch("os.path.exists", return_value=True):
                commit_hash = VersionUtils._get_full_commit_hash_from_git_refs_heads(TEST__VERSION_BRANCH)
                assert commit_hash == TEST__FULL_COMMIT_HASH

        # If the branch ref file is missing, should return None
        with patch("os.path.exists", return_value=False):
            commit_hash = VersionUtils._get_full_commit_hash_from_git_refs_heads(TEST__VERSION_BRANCH)
            assert commit_hash is None

        # If any other exception occurs, should return None
        with patch("builtins.open", side_effect=Exception("Unexpected error")):
            commit_hash = VersionUtils._get_full_commit_hash_from_git_refs_heads(TEST__VERSION_BRANCH)
            assert commit_hash is None


    def test__parse_git_remote_url(self):
        """
        _parse_git_remote_url should return the expected repo owner from various
        git remote url formats.
        """
        # Might be called with no remote url or unrecognized format
        for url in [None, "", "what/is/this"]:
            assert VersionUtils._parse_git_remote_url(url) is None

        for url, expected_owner in [
            ("https://github.com/SeedSigner/seedsigner.git", "SeedSigner"),
            ("git@github.com:SeedSigner/seedsigner.git", "SeedSigner"),
            ("https://gitlab.com/some_user/some-repo.git", "some_user"),
            ("git@gitlab.com:other-user/some-repo.git", "other-user"),
        ]:
            assert VersionUtils._parse_git_remote_url(url) == expected_owner


    def test__get_version_fork_from_git_config(self):
        """
        Test that _get_version_fork_from_git_config returns the expected repo owner from
        the remote url.
        """
        expected_fork = "SeedSigner"
        remote_url = f"git@github.com:{expected_fork}/seedsigner.git"
        git_config = f"""
            [some_section]
                some_key = some_value
            [remote "origin"] 
                url = {remote_url}
                fetch = +refs/heads/*:refs/remotes/origin/*
            [next_section]
                next_key = next_value
            """
        with mock.patch("builtins.open", mock.mock_open(read_data=git_config)):
            assert VersionUtils._get_version_fork_from_git_config() == expected_fork

        # Missing origin section should return None
        git_config_no_origin = """
            [some_section]
                some_key = some_value
            [next_section]
                next_key = next_value
            """
        with mock.patch("builtins.open", mock.mock_open(read_data=git_config_no_origin)):
            assert VersionUtils._get_version_fork_from_git_config() is None

        # Handle malformed origin section (can't find url) should return None
        git_config_malformed_origin = """
            [remote "origin"] 
                fetch = +refs/heads/*:refs/remotes/origin/*
            [next_section]
                next_key = next_value
            """
        with mock.patch("builtins.open", mock.mock_open(read_data=git_config_malformed_origin)):
            assert VersionUtils._get_version_fork_from_git_config() is None

        # If the git config file is missing, should return None
        with mock.patch("builtins.open", side_effect=FileNotFoundError):
            assert VersionUtils._get_version_fork_from_git_config() is None


    def test__get_version_timestamp_from_src_files(self):
        """
        _get_version_timestamp_from_src_files should return the most recent file
        modification timestamp from the SeedSigner python files.
        """
        # Do the real filesystem scan
        timestamp = VersionUtils._get_version_timestamp_from_src_files()
        assert timestamp < datetime.now()
        assert timestamp > datetime(2020, 12, 13)  # after first SeedSigner release

        # Now mock out os.path.getmtime to force all files to have a known timestamp
        expected_timestamp = datetime(2025, 12, 23, 0, 0, 0)
        with mock.patch("os.path.getmtime", return_value=expected_timestamp.timestamp()):
            assert VersionUtils._get_version_timestamp_from_src_files() == expected_timestamp

        # Mock out os.walk() to simulate no .py files found
        with mock.patch("os.walk", return_value=[]):
            assert VersionUtils._get_version_timestamp_from_src_files() is None



class TestVersionUtils_GitShell(VersionBaseTest):
    def test_local_dev_with_git_shell_calls(self):
        """
        Test the high-level basic public calls. Does just the minimal necessary mocking
        since all the downstream helper methods are tested in detail elsewhere.

        When running in a local dev environment with access to `git` shell commands,
        the version data should be pulled from those commands.

        Note that in local dev we use the last modified timestamp from the source files
        rather than from git.
        """
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _get_version_name_from_git_shell=Mock(return_value=TEST__VERSION_BRANCH),
            _get_version_fork_from_git_shell=Mock(return_value=TEST__VERSION_FORK),
            _get_version_timestamp_from_src_files=Mock(return_value=TEST__VERSION_TIMESTAMP),
            _get_full_commit_hash_from_git_shell=Mock(return_value=TEST__SHORT_COMMIT_HASH),
        ):
            assert VersionUtils.get_version_name() == TEST__VERSION_BRANCH
            assert VersionUtils.get_version_fork() == TEST__VERSION_FORK
            assert VersionUtils.get_version_timestamp() == TEST__VERSION_TIMESTAMP
            assert VersionUtils.get_short_commit_hash() == TEST__SHORT_COMMIT_HASH


    def test__get_version_name_from_git_shell(self):
        """
        Test that _get_version_name_from_git_shell returns the expected name depending on
        the current git state
        """
        # Default mock_popen return empty string; simulates no `git` shell command available
        # or no local git data.
        result = VersionUtils._get_version_name_from_git_shell()
        assert result is None

        # If we're on a branch, should return the branch name
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _get_version_name_from_git_shell_branch=Mock(return_value=TEST__VERSION_BRANCH),
            _get_version_name_from_git_shell_tag=Mock(return_value=TEST__VERSION_TAG),
            _get_full_commit_hash_from_git_shell=Mock(return_value=TEST__FULL_COMMIT_HASH),
        ):
            result = VersionUtils._get_version_name_from_git_shell()
            assert result == TEST__VERSION_BRANCH

        # If we're on a tag, the detached HEAD state wipes out the branch name
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _get_version_name_from_git_shell_branch=Mock(return_value=None),
            _get_version_name_from_git_shell_tag=Mock(return_value=TEST__VERSION_TAG),
            _get_full_commit_hash_from_git_shell=Mock(return_value=TEST__FULL_COMMIT_HASH),
        ):
            result = VersionUtils._get_version_name_from_git_shell()
            assert result == TEST__VERSION_TAG

        # Similarly, if we're detached at a specific commit hash
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _get_version_name_from_git_shell_branch=Mock(return_value=None),
            _get_version_name_from_git_shell_tag=Mock(return_value=None),
            _get_full_commit_hash_from_git_shell=Mock(return_value=TEST__FULL_COMMIT_HASH),
        ):
            result = VersionUtils._get_version_name_from_git_shell()
            assert result == TEST__FULL_COMMIT_HASH


    def test__get_version_fork_from_git_shell(self, mock_popen: Mock):
        """
        Test that _get_version_fork_from_git_shell returns the expected repo owner from
        the remote url.
        """
        remote_url = "https://github.com/SeedSigner/seedsigner.git"
        expected_fork = "SeedSigner"

        mock_popen.return_value.read.return_value = remote_url
        result = VersionUtils._get_version_fork_from_git_shell()
        assert result == expected_fork


    def test__get_version_timestamp_from_git_shell(self, mock_popen: Mock):
        """
        Test that _get_version_timestamp_from_git_shell returns the expected datetime.
        """
        # Should gracefully handle no `git` shell command available or no local git data.
        mock_popen.return_value.read.return_value = ""
        assert VersionUtils._get_version_timestamp_from_git_shell() is None

        # Initial timestamp has timezone info
        hour = 14
        tz_offset = 1
        test_local_isoformat = f"2025-12-20T{hour:02}:00:00-{tz_offset:02}:00"
        mock_popen.return_value.read.return_value = test_local_isoformat

        # But the final result will be UTC
        expected_datetime = datetime.fromisoformat(f"2025-12-20T{hour + tz_offset:02}:00:00")
        assert VersionUtils._get_version_timestamp_from_git_shell() == expected_datetime

        # And UTC-to-UTC should be unchanged
        mock_popen.return_value.read.return_value = expected_datetime.isoformat() + "+00:00"
        assert VersionUtils._get_version_timestamp_from_git_shell() == expected_datetime


    def test__get_short_commit_hash_from_git_shell(self, mock_popen: Mock):
        """
        Test that _get_full_commit_hash_from_git_shell returns the expected short commit hash.
        """
        mock_popen.return_value.read.return_value = TEST__SHORT_COMMIT_HASH

        result = VersionUtils._get_full_commit_hash_from_git_shell()
        assert result == TEST__SHORT_COMMIT_HASH


    def test__fetch_latest_seedsigner_release_tag(self, mock_popen: Mock):
        """
        Test that _fetch_latest_seedsigner_release_tag returns the expected version string.
        """
        latest_releases_response_dict = {
            "url": "https://api.github.com/repos/SeedSigner/seedsigner/releases/228915183",
            "tag_name": "0.8.6",
            "prerelease": False,
            "created_at": "2025-06-22T01:38:41Z",
            "updated_at": "2025-06-30T20:49:22Z",
            "published_at": "2025-06-30T20:45:05Z"
        }

        fake_response = Mock()
        fake_response.status = 200
        fake_response.read.return_value = json.dumps(latest_releases_response_dict).encode('utf-8')

        with mock.patch("urllib.request.urlopen", return_value=fake_response):
            release_tag, release_timestamp = VersionUtils._fetch_latest_seedsigner_release_tag()

            # mock_popen returns empty string, which mimics not having local git data to
            # retrieve the commit timestamp.
            assert mock_popen.called is True

            # So then we expect to fall back to using the published_at time from the API
            expected_timestamp = datetime.fromisoformat(latest_releases_response_dict["published_at"].replace("Z", "+00:00")).replace(tzinfo=None)

            assert release_tag == VersionUtils._prefix_version_name(latest_releases_response_dict["tag_name"])
            assert release_timestamp == expected_timestamp

            # Update mock_popen so that we CAN get the (simulated) commit timestamp from
            # local git data.
            git_timestamp = "2025-06-21T21:38:41-04:00"
            mock_popen.return_value.read.return_value = f"{git_timestamp}\n"
            expected_timestamp = datetime.fromisoformat(git_timestamp).astimezone(timezone.utc).replace(tzinfo=None)

            release_tag, release_timestamp = VersionUtils._fetch_latest_seedsigner_release_tag()
            assert release_tag == VersionUtils._prefix_version_name(latest_releases_response_dict["tag_name"])
            assert release_timestamp == expected_timestamp
        
        # Should gracefully handle HTTP errors
        fake_error_response = Mock()
        fake_error_response.status = 404
        with mock.patch("urllib.request.urlopen", return_value=fake_error_response):
            release_tag, release_timestamp = VersionUtils._fetch_latest_seedsigner_release_tag()
            assert release_tag is None
            assert release_timestamp is None
        
        # And other exceptions
        with mock.patch("urllib.request.urlopen", side_effect=Exception("Network error")):
            release_tag, release_timestamp = VersionUtils._fetch_latest_seedsigner_release_tag()
            assert release_tag is None
            assert release_timestamp is None



class TestVersion(VersionBaseTest):
    """
    `Version` is really just a way to store the version data; all the real work is done in
    `VersionUtils` and all of those calls have already been fully covered by the above
    tests. So there's nothing to really test here. Just providing minimal tests in order
    to get full test coverage.
    """
    def test_basic_calls(self):
        self.write_test_version_file()
        with patch("seedsigner.models.settings.Settings.HOSTNAME", Settings.SEEDSIGNER_OS):
            Version.get_version_name() == TEST__VERSION_DICT[VersionUtils.VERSIONFILE_ATTR__NAME]
            Version.get_version_fork() == TEST__VERSION_DICT[VersionUtils.VERSIONFILE_ATTR__FORK]
            Version.get_version_commit_hash() == TEST__VERSION_DICT[VersionUtils.VERSIONFILE_ATTR__COMMIT_HASH]
            Version.get_version_timestamp() == TEST__VERSION_TIMESTAMP


    def test_get_last_edit(self):
        """
        Test that get_last_src_edit returns a sane datetime object. Assumes the system
        running this test has a reasonably correct system time.
        """
        last_edit = Version.get_version_timestamp()
        assert isinstance(last_edit, datetime)

        # Has to be more recent than the first SeedSigner v0.0.1 release
        known_past = datetime(2020, 12, 13)
        assert last_edit > known_past

        # Could not have happened tomorrow
        known_future = datetime.now().replace(year=datetime.now().year + 1)
        assert last_edit < known_future



class TestNotAllowedInSeedSignerOSDecorator(BaseTest):
    SUCCESS = "success"

    @not_allowed_in_seedsigner_os
    def dummy_function(self):
        return self.SUCCESS


    def test_not_allowed_in_seedsigner_os(self):
        """
        The not_allowed_in_seedsigner_os decorator should raise its associated exception
        if we run a decorated function while in SeedSigner OS.
        """
        # Patch over the Settings.HOSTNAME value to simulate running in SeedSigner OS
        with mock.patch("seedsigner.models.settings.Settings.HOSTNAME", Settings.SEEDSIGNER_OS):
            with pytest.raises(NotAllowedInSeedSignerOS):
                self.dummy_function()


    def test_allowed_outside_seedsigner_os(self):
        # Now try with any other HOSTNAME
        with mock.patch("seedsigner.models.settings.Settings.HOSTNAME", "my_dev_machine"):
            assert self.dummy_function() == self.SUCCESS



class TestNotVersionBaseTest(BaseTest):
    def test_version_file_name__not_patched(self):
        """
        Ensure that outside of VersionBaseTest, the VERSIONFILE__FILENAME patch does not
        persist.
        """
        assert VersionUtils.VERSIONFILE__FILENAME != TEST__VERSIONFILE__FILENAME


    def test_mock_popen__not_patched(self):
        """
        Ensure that outside of VersionBaseTest, os.popen is not patched.
        """
        # Call os.popen
        result = os.popen("echo 'Hello, World!'")
        # The result should not be a MagicMock instance
        assert not isinstance(result, mock.MagicMock)
