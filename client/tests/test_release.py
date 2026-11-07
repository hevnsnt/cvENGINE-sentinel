"""The release number (1.4.0): read from the installed package's metadata, reported beside the commit, never invented."""
import importlib.metadata
import unittest
from unittest import mock

from client import config, daemon


def installed(version):
    return mock.patch.object(importlib.metadata, 'version', return_value=version)


class ReleaseTests(unittest.TestCase):
    def test_a_tagged_build_reports_its_release(self):
        for value in ('1.4.0', '1.4', '2.0.1', '1.4.0rc1'):
            with installed(value):
                self.assertEqual(config.release(), value)

    def test_a_build_without_a_tag_has_no_release_number(self):
        for value in ('0.0.0.dev0', '1.4.1.dev3+gabc123', '0.0.0', '1.4.0.dev0', 'abc123', '', '1'):
            with installed(value):
                self.assertIsNone(config.release(), value)

    def test_a_package_that_is_not_installed_has_no_release_number(self):
        with mock.patch.object(importlib.metadata, 'version', side_effect=importlib.metadata.PackageNotFoundError('cvengine-scanner')):
            self.assertIsNone(config.release())

    def test_registration_and_heartbeat_carry_the_release_next_to_the_commit(self):
        with installed('1.4.0'), mock.patch.object(config, 'version', return_value='abc123def456'):
            info = daemon.info()
        self.assertEqual((info['version'], info['release']), ('abc123def456', '1.4.0'))

    def test_without_a_tag_the_commit_alone_is_reported_as_before(self):
        with installed('0.0.0.dev0'), mock.patch.object(config, 'version', return_value='abc123def456'):
            info = daemon.info()
        self.assertEqual(info['version'], 'abc123def456')
        self.assertNotIn('release', info)

    def test_the_release_never_comes_from_anywhere_but_the_package(self):
        with installed('0.0.0.dev0'), mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_VERSION': '1.4.0'}):
            self.assertIsNone(config.release())


if __name__ == '__main__':
    unittest.main()
