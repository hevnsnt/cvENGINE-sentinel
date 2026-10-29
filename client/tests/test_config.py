import builtins
import io
import unittest
from unittest import mock

from client import config


def _fake_open(contents):
    """A ``builtins.open`` replacement: files named in ``contents`` (path -> text) open normally; anything else
    raises ``FileNotFoundError``, matching a host or container that simply does not have that cgroup file."""
    real_open = builtins.open

    def opener(path, *args, **kwargs):
        if path in contents:
            return io.StringIO(contents[path])
        raise FileNotFoundError(path)
    return opener


class MaxConcurrentEnvOverrideTests(unittest.TestCase):
    def test_explicit_value_wins_over_auto_detection(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_MAX_CONCURRENT': '3'}), \
                mock.patch('client.config._detected_cpus', return_value=64):
            self.assertEqual(config.max_concurrent(), 3)

    def test_zero_or_negative_is_floored_at_one(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_MAX_CONCURRENT': '0'}):
            self.assertEqual(config.max_concurrent(), 1)
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_MAX_CONCURRENT': '-5'}):
            self.assertEqual(config.max_concurrent(), 1)

    def test_an_explicit_value_is_capped_like_the_servers(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_MAX_CONCURRENT': '500'}):
            self.assertEqual(config.max_concurrent(), config.MAX_AUTO_CONCURRENT)
            self.assertEqual(config.local_settings()['max_concurrent'], config.MAX_AUTO_CONCURRENT)

    def test_garbage_value_falls_back_to_one_not_auto_detection(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_MAX_CONCURRENT': 'not-a-number'}), \
                mock.patch('client.config._detected_cpus', return_value=64):
            self.assertEqual(config.max_concurrent(), 1)

    def test_empty_string_is_treated_as_unset_and_auto_detects(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_MAX_CONCURRENT': ''}), \
                mock.patch('client.config._detected_cpus', return_value=4):
            self.assertEqual(config.max_concurrent(), 4)


class AutoDetectionTests(unittest.TestCase):
    def setUp(self):
        # CVENGINE_SENTINEL_MAX_CONCURRENT must be genuinely unset for every test in this class.
        patcher = mock.patch.dict('os.environ', {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        import os as _os
        _os.environ.pop('CVENGINE_SENTINEL_MAX_CONCURRENT', None)

    def test_unset_env_auto_detects_from_cpus(self):
        with mock.patch('client.config._detected_cpus', return_value=4):
            self.assertEqual(config.max_concurrent(), 4)

    def test_auto_detection_is_capped_at_the_server_side_limit(self):
        with mock.patch('client.config._detected_cpus', return_value=64):
            self.assertEqual(config.max_concurrent(), config.MAX_AUTO_CONCURRENT)

    def test_auto_detection_never_goes_below_one(self):
        with mock.patch('client.config._detected_cpus', return_value=0):
            self.assertEqual(config.max_concurrent(), 1)


class CgroupCpuLimitTests(unittest.TestCase):
    def test_cgroup_v2_quota_is_parsed_into_whole_cpus(self):
        with mock.patch('builtins.open', side_effect=_fake_open({'/sys/fs/cgroup/cpu.max': '400000 100000\n'})):
            self.assertEqual(config._cgroup_cpu_limit(), 4)

    def test_cgroup_v2_max_means_no_limit(self):
        with mock.patch('builtins.open', side_effect=_fake_open({'/sys/fs/cgroup/cpu.max': 'max 100000\n'})):
            self.assertIsNone(config._cgroup_cpu_limit())

    def test_cgroup_v2_quota_narrower_than_one_cpu_still_reports_one(self):
        with mock.patch('builtins.open', side_effect=_fake_open({'/sys/fs/cgroup/cpu.max': '50000 100000\n'})):
            self.assertEqual(config._cgroup_cpu_limit(), 1)

    def test_falls_back_to_cgroup_v1_when_v2_file_is_absent(self):
        contents = {'/sys/fs/cgroup/cpu/cpu.cfs_quota_us': '200000\n', '/sys/fs/cgroup/cpu/cpu.cfs_period_us': '100000\n'}
        with mock.patch('builtins.open', side_effect=_fake_open(contents)):
            self.assertEqual(config._cgroup_cpu_limit(), 2)

    def test_cgroup_v1_unset_quota_is_minus_one_meaning_no_limit(self):
        contents = {'/sys/fs/cgroup/cpu/cpu.cfs_quota_us': '-1\n', '/sys/fs/cgroup/cpu/cpu.cfs_period_us': '100000\n'}
        with mock.patch('builtins.open', side_effect=_fake_open(contents)):
            self.assertIsNone(config._cgroup_cpu_limit())

    def test_neither_cgroup_file_present_is_none_not_a_crash(self):
        with mock.patch('builtins.open', side_effect=_fake_open({})):
            self.assertIsNone(config._cgroup_cpu_limit())


class DetectedCpusTests(unittest.TestCase):
    def test_a_cgroup_limit_wins_over_affinity_and_cpu_count(self):
        with mock.patch('client.config._cgroup_cpu_limit', return_value=2), \
                mock.patch('os.sched_getaffinity', return_value=set(range(16)), create=True), \
                mock.patch('os.cpu_count', return_value=16):
            self.assertEqual(config._detected_cpus(), 2)

    def test_no_cgroup_limit_falls_back_to_scheduler_affinity(self):
        with mock.patch('client.config._cgroup_cpu_limit', return_value=None), \
                mock.patch('os.sched_getaffinity', return_value=set(range(6)), create=True), \
                mock.patch('os.cpu_count', return_value=32):
            self.assertEqual(config._detected_cpus(), 6)

    def test_no_affinity_api_falls_back_to_cpu_count(self):
        with mock.patch('client.config._cgroup_cpu_limit', return_value=None), \
                mock.patch('os.sched_getaffinity', side_effect=AttributeError, create=True), \
                mock.patch('os.cpu_count', return_value=8):
            self.assertEqual(config._detected_cpus(), 8)

    def test_nothing_readable_at_all_is_one_not_a_crash(self):
        with mock.patch('client.config._cgroup_cpu_limit', return_value=None), \
                mock.patch('os.sched_getaffinity', side_effect=AttributeError, create=True), \
                mock.patch('os.cpu_count', return_value=None):
            self.assertEqual(config._detected_cpus(), 1)


if __name__ == '__main__':
    unittest.main()
