"""SN-4: the Sentinel reports the versions of its tools (``{tool: version}``, from the version probes it already runs at start) in its registration and
heartbeat info, so the server can tell a Sentinel on stale tools. The probe output here is the form each tool's own ``--version`` prints."""
import unittest
from unittest import mock

from client import daemon, tools
from client.tests.test_daemon import DaemonTestCase

OUTPUTS = {  # (stdout, stderr) of each tool's version probe
    'nmap': ('Nmap version 7.993 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu\n', ''),
    'naabu': ('', '[INF] Current Version: 2.7.0\n'),
    'nuclei': ('', '[INF] Nuclei Engine Version: v3.11.1\n[INF] Nuclei Config Directory: /root/.config/nuclei\n'),
    'testssl': ('testssl.sh version 3.2.5\n', ''),
    'wpscan': ('4.2.0\n', ''),
    'wafw00f': ('2.4.2\n', ''),
    'kingfisher': ('kingfisher 2.16.0\n', ''),
    'bbot': ('BBOT 3.1.0\n', ''),
}


def fake_run(argv, **kwargs):
    for name, probe in tools.VERSION_ARGS.items():
        if argv == probe:
            out, err = OUTPUTS[name]
            return mock.Mock(returncode=0, stdout=out.encode(), stderr=err.encode())
    raise AssertionError(argv)


class ToolVersionProbeTests(unittest.TestCase):
    def test_each_tool_that_ran_gives_its_version(self):
        with mock.patch('client.tools.subprocess.run', side_effect=fake_run), mock.patch('client.tools.gvm_available', return_value=False):
            names = tools.detect_tools()
            versions = tools.tool_versions()
        self.assertEqual(sorted(names), sorted(OUTPUTS))
        self.assertEqual(versions, {'nmap': '7.993', 'naabu': '2.7.0', 'nuclei': '3.11.1', 'testssl': '3.2.5', 'wpscan': '4.2.0', 'wafw00f': '2.4.2',
                                    'kingfisher': '2.16.0', 'bbot': '3.1.0'})

    def test_a_tool_that_did_not_run_or_printed_no_version_is_left_out_and_hostile_text_is_bounded(self):
        def run(argv, **kwargs):
            if argv == tools.VERSION_ARGS['nmap']:
                raise FileNotFoundError('nmap')
            if argv == tools.VERSION_ARGS['naabu']:
                return mock.Mock(returncode=0, stdout=b'no digits here', stderr=b'')
            if argv == tools.VERSION_ARGS['nuclei']:
                return mock.Mock(returncode=0, stdout=b'v' + b'1.' * 100 + b'2\x1b[31m', stderr=b'')
            return mock.Mock(returncode=0, stdout=mock.Mock(), stderr=mock.Mock())  # not even bytes
        with mock.patch('client.tools.subprocess.run', side_effect=run), mock.patch('client.tools.gvm_available', return_value=False):
            tools.detect_tools()
            versions = tools.tool_versions()
        self.assertNotIn('nmap', versions)
        self.assertNotIn('naabu', versions)
        self.assertLessEqual(len(versions['nuclei']), 40)
        self.assertTrue(all(v.isprintable() for v in versions.values()))


class ToolVersionReportTests(DaemonTestCase):
    def setUp(self):
        super().setUp()
        patch = mock.patch.dict(daemon._detected, {'tools': ['nmap', 'nuclei'], 'versions': {'nmap': '7.993', 'nuclei': '3.11.1'}})
        patch.start()
        self.addCleanup(patch.stop)

    def test_info_carries_the_versions(self):
        self.assertEqual(daemon.info()['tool_versions'], {'nmap': '7.993', 'nuclei': '3.11.1'})

    def test_registration_and_every_heartbeat_carry_them(self):
        daemon.register(self.fc, 'x', 1)
        self.assertEqual(self.fc.body_for('sentinel')['info']['tool_versions'], {'nmap': '7.993', 'nuclei': '3.11.1'})
        d = self.make()
        d._heartbeat_once()
        beats = [b for _m, p, b in self.fc.calls if p == 'sentinel/heartbeat']
        self.assertEqual(beats[0]['info']['tool_versions'], {'nmap': '7.993', 'nuclei': '3.11.1'})

    def test_a_sentinel_with_no_probed_version_sends_no_field(self):
        with mock.patch.dict(daemon._detected, {'versions': {}}):
            self.assertNotIn('tool_versions', daemon.info())

    def test_the_versions_are_probed_once_not_at_every_heartbeat(self):
        with mock.patch.dict(daemon._detected, clear=True), mock.patch('client.tools.detect_tools', return_value=['nmap']) as detect, \
                mock.patch('client.tools.tool_versions', return_value={'nmap': '7.993'}) as versions:
            daemon.info()
            daemon.info()
        self.assertEqual((detect.call_count, versions.call_count), (1, 1))


if __name__ == '__main__':
    unittest.main()
