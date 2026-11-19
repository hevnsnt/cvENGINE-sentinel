"""info.machine: the CPU, load and memory this Sentinel's machine has and the kernel's out-of-memory kills by kind, for cvENGINE's per-Sentinel tuning."""
import unittest
from unittest import mock

from client import daemon, machine, tools
from client.tests.test_daemon import DaemonTestCase, wait_for

MEMINFO = 'MemTotal:       8000000 kB\nMemFree:  100 kB\nMemAvailable:   2048000 kB\nSwapTotal:      1024000 kB\nSwapFree:        512000 kB\n'


def reader(files):
    return lambda path: files.get(path, '')


class ReportTests(unittest.TestCase):
    def setUp(self):
        machine.reset()
        self.addCleanup(machine.reset)

    def test_the_report_carries_cpu_load_memory_and_the_cgroup(self):
        files = {'/proc/meminfo': MEMINFO, '/sys/fs/cgroup/memory.max': str(4096 * machine.MB), '/sys/fs/cgroup/memory.current': str(1024 * machine.MB),
                 '/sys/fs/cgroup/memory.events': 'low 0\nhigh 0\nmax 3\noom 2\noom_kill 2\n'}
        with mock.patch('client.machine._cpus', return_value=4), mock.patch('os.cpu_count', return_value=16):
            out = machine.report(read=reader(files), loadavg=lambda: (1.234, 2.0, 3.5))
        self.assertEqual(out['cpus'], 4)
        self.assertEqual(out['host_cpus'], 16)
        self.assertEqual(out['load'], [1.23, 2.0, 3.5])
        self.assertEqual((out['mem_total_mb'], out['mem_available_mb'], out['swap_total_mb'], out['swap_free_mb']), (7812, 2000, 1000, 500))
        self.assertEqual((out['cgroup_limit_mb'], out['cgroup_used_mb'], out['cgroup_oom_kills']), (4096, 1024, 2))
        self.assertEqual(out['oom_kills_1h'], {})

    def test_no_container_limit_and_unreadable_files_are_none(self):
        files = {'/sys/fs/cgroup/memory.max': 'max', '/sys/fs/cgroup/memory.current': '123'}
        out = machine.report(read=reader(files), loadavg=mock.Mock(side_effect=OSError))
        self.assertIsNone(out['cgroup_limit_mb'])
        self.assertIsNone(out['mem_total_mb'])
        self.assertIsNone(out['load'])
        self.assertIsNone(out['cgroup_oom_kills'])

    def test_cgroup_v1_without_a_limit(self):
        files = {'/sys/fs/cgroup/memory/memory.limit_in_bytes': '9223372036854771712', '/sys/fs/cgroup/memory/memory.usage_in_bytes': str(10 * machine.MB)}
        self.assertEqual(machine.cgroup_memory(reader(files)), (None, 10))

    def test_kills_are_counted_by_kind_for_an_hour(self):
        machine.note_oom('nuclei_deep', now=100)
        machine.note_oom('nuclei_deep', now=200)
        machine.note_oom('web_screenshot', now=300)
        machine.note_oom('', now=300)
        self.assertEqual(machine.oom_kills(now=400), {'nuclei_deep': 2, 'web_screenshot': 1})
        self.assertEqual(machine.oom_kills(now=100 + machine.OOM_WINDOW_SECONDS + 1), {'nuclei_deep': 1, 'web_screenshot': 1})
        self.assertEqual(machine.oom_kills(now=10_000), {})


class HeartbeatTests(DaemonTestCase):
    def setUp(self):
        super().setUp()
        machine.reset()
        self.addCleanup(machine.reset)

    def test_the_heartbeat_info_carries_the_machine_report(self):
        with mock.patch('client.machine.report', return_value={'cpus': 2}):
            self.assertEqual(daemon.info()['machine'], {'cpus': 2})

    def test_a_machine_report_that_fails_never_stops_the_heartbeat(self):
        with mock.patch('client.machine.report', side_effect=RuntimeError('boom')):
            out = daemon.info()
        self.assertNotIn('machine', out)
        self.assertEqual(out['contract_version'], daemon.config.CONTRACT_VERSION)

    def test_a_task_killed_for_memory_is_counted_for_its_kind(self):
        self.fc.next_responses = [{'task': {'id': 31, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}}]
        d = self.make()

        def runner(addresses, register=None, timeout=None, ports=None):
            raise tools.ToolOOMError('out of memory, retry later (nmap was killed by the system)')
        with mock.patch.dict(tools.RUNNERS, {'nmap': runner}):
            d._poll_once()
            self.assertTrue(wait_for(lambda: d._active_count() == 0))
        self.assertEqual(machine.oom_kills(), {'nmap': 1})

    def test_a_plain_failure_is_not_counted(self):
        self.fc.next_responses = [{'task': {'id': 32, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}}]
        d = self.make()

        def runner(addresses, register=None, timeout=None, ports=None):
            raise tools.ToolExitError('nmap exited with status 1')
        with mock.patch.dict(tools.RUNNERS, {'nmap': runner}):
            d._poll_once()
            self.assertTrue(wait_for(lambda: d._active_count() == 0))
        self.assertEqual(machine.oom_kills(), {})


if __name__ == '__main__':
    unittest.main()
