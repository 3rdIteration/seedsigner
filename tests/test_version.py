import os
import pytest
from datetime import datetime
from unittest import mock

# Must import this before any SeedSigner imports
from base import BaseTest

from seedsigner.helpers.version import Version



class TestVersion(BaseTest):
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


    def test_version_with_mocked_git_head(self):
        """
        If there is a .git/HEAD file, the version should report the current git branch
        name, commit hash, or a matching tag.
        """
        with mock.patch("os.path.exists", return_value=True):
            # Mock the HEAD file read in _read_HEAD_file to return our fake branch name
            branch_name = "my_feature_branch"
            git_HEAD_content = f"ref: refs/heads/{branch_name}"
            with mock.patch("builtins.open", mock.mock_open(read_data=git_HEAD_content)):
                version = Version.get_version_name()
                assert version == branch_name
        
            # Mock the HEAD file read in _read_HEAD_file to return a fake commit hash
            commit_hash = "abcdef1234567890"
            with mock.patch("builtins.open", mock.mock_open(read_data=commit_hash)):
                # Mock that there are no matching tags for this commit hash
                with mock.patch.object(Version, '_get_matching_tag', return_value=None):
                    version = Version.get_version_name()
                    assert version == commit_hash[:7]  # short commit hash
                
                # Now mock that there is a matching tag for this commit hash
                tag_name = "v1.2.3"
                with mock.patch.object(Version, '_get_matching_tag', return_value=tag_name):
                    version = Version.get_version_name()
                    assert version == tag_name


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