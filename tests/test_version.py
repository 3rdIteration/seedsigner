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
TEST__VERSION_FILE_NAME = "version-test.json"
TEST__DOT_GIT_DIR_NAME = f"dot-git-test"

# Reusable test data
TEST__VERSION_NAME = "1.2.3"  # Will require VersionUtils._prefix_version_name when verifying results
TEST__VERSION_FORK = "some_repo_owner"
TEST__VERSION_TIMESTAMP = datetime.now()
TEST__VERSION_COMMIT_HASH = "abcd123"
TEST__VERSION_DICT = {
    VersionUtils.ATTR__VERSION_NAME: TEST__VERSION_NAME,
    VersionUtils.ATTR__VERSION_FORK: TEST__VERSION_FORK,
    VersionUtils.ATTR__VERSION_TIMESTAMP: TEST__VERSION_TIMESTAMP.isoformat(),
    VersionUtils.ATTR__VERSION_COMMIT_HASH: TEST__VERSION_COMMIT_HASH,
}

# Mimic result of reading from version.json
TEST__VERSION_FILE_CONTENTS = str(TEST__VERSION_DICT).replace("'", '"')  # JSON uses double quotes



class VersionBaseTest(BaseTest):
    """ Sets up test-specific overrides and reusable methods and fixtures. """

    @pytest.fixture(autouse=True, scope="class")
    def mock_version_file_name(self):
        """
        Every test in this class (and subclasses) will automatically run with this patch
        applied (autouse=True), but the patch will not persist beyond the test class.
        """
        with patch.object(VersionUtils, 'VERSION_FILENAME', TEST__VERSION_FILE_NAME):
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
        assert VersionUtils.VERSION_FILENAME == TEST__VERSION_FILE_NAME
        with open(VersionUtils._get_version_file_path(), "w") as f:
            f.write(TEST__VERSION_FILE_CONTENTS)


    @classmethod
    def delete_test_version_file(cls):
        """
        Delete the test version file from disk.
        """
        assert VersionUtils.VERSION_FILENAME == TEST__VERSION_FILE_NAME
        try:
            os.remove(VersionUtils._get_version_file_path())
        except FileNotFoundError:
            pass


    def setup_method(self):
        super().setup_method()


    def teardown_method(self):
        super().teardown_method()
        # Clean up any test version file created
        self.delete_test_version_file()



class TestVersionBaseTest(VersionBaseTest):
    def test_setup_and_teardown(self):
        """
        Ensure that the setup and teardown methods work as expected.
        """
        assert VersionUtils.VERSION_FILENAME == TEST__VERSION_FILE_NAME

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



class TestVersion(VersionBaseTest):
    def test_seedsigner_os_reads_from_version_file(self):
        """
        When running on SeedSigner OS, the version data should be read from the
        version.json file.
        """
        self.write_test_version_file()

        # Simulate running on SeedSigner OS
        with patch("seedsigner.models.settings.Settings.HOSTNAME", Settings.SEEDSIGNER_OS):
            assert Version.get_version_name() == VersionUtils._prefix_version_name(TEST__VERSION_NAME)
            assert Version.get_version_fork() == TEST__VERSION_FORK
            assert Version.get_version_timestamp() == TEST__VERSION_TIMESTAMP
            assert Version.get_version_commit_hash() == TEST__VERSION_COMMIT_HASH


    # def test_version_with_no_git_head(self):
    #     """
    #     If there is no .git/HEAD file, the hard-coded VERSION constant should be returned.
    #     """
    #     # mock out the os.path.exists call to always return False
    #     with mock.patch("os.path.exists", return_value=False):
    #         version = Version.get_version()
    #         assert version == f"v{Version.VERSION}"


    # def test_version_with_actual_git_head(self):
    #     """
    #     If the .git dir exists on our actual filesystem right now, we should get a version
    #     based on its contents.

    #     NOTE: This test is potentially fragile as it depends on the test runner system's actual
    #     git state. The get_version() call should be able to handle all possible git states, but
    #     this does create the possibility of external variability.
    #     """
    #     fake_hardcoded_version = "fake.version.123"
    #     with mock.patch.object(Version, 'VERSION', fake_hardcoded_version):
    #         git_dot_dir = Version._get_dot_git_dir()
    #         if os.path.exists(git_dot_dir):
    #             assert Version.get_version() != f"v{fake_hardcoded_version}"
    #         else:
    #             # If there's no .git dir, mark this test as skipped
    #             pytest.skip(f"No .git dir found at {git_dot_dir}, skipping test.")


    # def test_version_with_mocked_git_head(self):
    #     """
    #     If there is a .git/HEAD file, the version should report the current git branch
    #     name, commit hash, or a matching tag.
    #     """
    #     with mock.patch("os.path.exists", return_value=True):
    #         # Mock the HEAD file read in _read_HEAD_file to return our fake branch name
    #         branch_name = "my_feature_branch"
    #         git_HEAD_content = f"ref: refs/heads/{branch_name}"
    #         with mock.patch("builtins.open", mock.mock_open(read_data=git_HEAD_content)):
    #             version = VersionUtils._get_version_name_from_git_HEAD()
    #             assert version == branch_name
        
    #         # Mock the HEAD file read in _read_HEAD_file to return a fake commit hash
    #         commit_hash = "abcdef1234567890"
    #         with mock.patch("builtins.open", mock.mock_open(read_data=commit_hash)):
    #             # Mock that there are no matching tags for this commit hash
    #             with mock.patch.object(Version, '_get_matching_tag', return_value=None):
    #                 version = Version.get_version_name()
    #                 assert version == commit_hash[:7]  # short commit hash
                
    #             # Now mock that there is a matching tag for this commit hash
    #             tag_name = "v1.2.3"
    #             with mock.patch.object(Version, '_get_matching_tag', return_value=tag_name):
    #                 version = Version.get_version_name()
    #                 assert version == tag_name


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


class TestVersionUtils(VersionBaseTest):
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


    def test__read_version_file(self):
        """
        Low-level test for reading the version.json file.
        """
        self.write_test_version_file()

        version_data = VersionUtils._read_version_file()
        assert version_data is not None
        assert version_data[VersionUtils.ATTR__VERSION_NAME] == TEST__VERSION_NAME
        assert version_data[VersionUtils.ATTR__VERSION_FORK] == TEST__VERSION_FORK
        assert version_data[VersionUtils.ATTR__VERSION_TIMESTAMP] == TEST__VERSION_TIMESTAMP.isoformat()
        assert version_data[VersionUtils.ATTR__VERSION_COMMIT_HASH] == TEST__VERSION_COMMIT_HASH


    def test__read_version_file__missing(self):
        """ _read_version_file should return None if the version file is missing. """
        assert os.path.exists(VersionUtils._get_version_file_path()) is False
        assert VersionUtils._read_version_file() is None


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
        expected_branch = "my_test_branch"
        git_HEAD_content = f"ref: refs/heads/{expected_branch}"
        with patch("builtins.open", mock.mock_open(read_data=git_HEAD_content)):
            branch_name, commit_hash = VersionUtils._read_git_HEAD_file()
            assert branch_name == expected_branch
            assert commit_hash is None

        # If we're in a detached HEAD state at a specific commit hash...
        expected_commit_hash = "47212c98f1bf948e9918b672c4bb88b1c965aff4"
        with patch("builtins.open", mock.mock_open(read_data=expected_commit_hash)):
            branch_name, commit_hash = VersionUtils._read_git_HEAD_file()
            assert branch_name is None
            assert commit_hash == expected_commit_hash

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
        assert VersionUtils._get_matching_tag_from_git_refs_tags("anyhash") is None

        # Mock out the .git/refs/tags file read to return some fake tags
        fake_tags_content = """v1.0.0:abcd1234567890
v1.2.3:deadbeefcafebabe
v2.0.0-rc1:47212c98f1bf948e9918b672c4bb88b1c965aff4
"""
        with patch("builtins.open", mock.mock_open(read_data=fake_tags_content)):
            # Existing tag
            tag_name = VersionUtils._get_matching_tag_from_git_refs_tags("deadbeefcafebabe")
            assert tag_name == "v1.2.3"

            # Another existing tag
            tag_name = VersionUtils._get_matching_tag_from_git_refs_tags("47212c98f1bf948e9918b672c4bb88b1c965aff4")
            assert tag_name == "v2.0.0-rc1"

            # Non-existing tag
            tag_name = VersionUtils._get_matching_tag_from_git_refs_tags("nonexistenthash")
            assert tag_name is None


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




    def test__get_version_name_from_git_shell(self):
        """
        Test that _get_version_name_from_git_shell returns the expected name depending on
        the current git state
        """
        branch_name = "my_test_branch"
        tag_name = "my_test_tag"
        commit_hash = "abcd123"

        # Default mock_popen return empty string; simulates no `git` shell command available
        # or no local git data.
        result = VersionUtils._get_version_name_from_git_shell()
        assert result is None

        # If we're on a branch, should return the branch name
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _get_version_name_from_git_shell_branch=Mock(return_value=branch_name),
            _get_version_name_from_git_shell_tag=Mock(return_value=tag_name),
            _get_version_name_from_git_shell_commit_hash=Mock(return_value=commit_hash),
        ):
            result = VersionUtils._get_version_name_from_git_shell()
            assert result == branch_name
        
        # If we're on a tag, the detached HEAD state wipes out the branch name
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _get_version_name_from_git_shell_branch=Mock(return_value=None),
            _get_version_name_from_git_shell_tag=Mock(return_value=tag_name),
            _get_version_name_from_git_shell_commit_hash=Mock(return_value=commit_hash),
        ):
            result = VersionUtils._get_version_name_from_git_shell()
            assert result == tag_name
        
        # Similarly, if we're detached at a specific commit hash
        with mock.patch.multiple(
            "seedsigner.helpers.version.VersionUtils",
            _get_version_name_from_git_shell_branch=Mock(return_value=None),
            _get_version_name_from_git_shell_tag=Mock(return_value=None),
            _get_version_name_from_git_shell_commit_hash=Mock(return_value=commit_hash),
        ):
            result = VersionUtils._get_version_name_from_git_shell()
            assert result == commit_hash[:7]  # short hash


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


    def test__get_version_commit_hash_from_git_shell(self, mock_popen: Mock):
        """
        Test that _get_version_commit_hash_from_git_shell returns the expected short commit hash.
        """
        commit_hash = "abcd123"
        mock_popen.return_value.read.return_value = commit_hash

        result = VersionUtils._get_version_commit_hash_from_git_shell()
        assert result == commit_hash


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
        Ensure that outside of VersionBaseTest, the VERSION_FILENAME patch does not
        persist.
        """
        assert VersionUtils.VERSION_FILENAME != TEST__VERSION_FILE_NAME


    def test_mock_popen__not_patched(self):
        """
        Ensure that outside of VersionBaseTest, os.popen is not patched.
        """
        # Call os.popen
        result = os.popen("echo 'Hello, World!'")
        # The result should not be a MagicMock instance
        assert not isinstance(result, mock.MagicMock)
