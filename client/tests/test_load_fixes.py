"""The fixes the fresh install's load found: memory admission (D1), 429 handling and claim pacing (D2), the screenshot proxy's thread failure (D3), and
the AppArmor refusal of Chromium's sandbox (D11). Each test fails on the code before the fix."""
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import requests

from client import admission, config, daemon, httpclient, shot_child, shotproxy, tools
from client.tests.test_daemon import FakeClient

MB = admission.MB


def reader(files):
    return lambda path: files.get(path, '')


class AdmissionTests(unittest.TestCase):
    def test_the_budget_comes_from_the_container_limit_not_the_host(self):
        two_gb = reader({'/sys/fs/cgroup/memory.max': str(2048 * MB), '/proc/meminfo': 'MemTotal: 131072000 kB\n'})
        four_gb = reader({'/sys/fs/cgroup/memory.max': str(4096 * MB)})
        self.assertEqual(admission.budget_mb(two_gb), int(2048 * 0.85) - admission.DAEMON_MB)
        self.assertGreater(admission.budget_mb(four_gb), 2 * admission.budget_mb(two_gb) - 400)

    def test_no_cgroup_limit_falls_back_to_the_hosts_memory(self):
        host = reader({'/sys/fs/cgroup/memory.max': 'max', '/proc/meminfo': 'MemTotal:  8388608 kB\n'})
        self.assertEqual(admission.budget_mb(host), int(8192 * 0.85) - admission.DAEMON_MB)
        v1 = reader({'/sys/fs/cgroup/memory/memory.limit_in_bytes': '9223372036854771712', '/proc/meminfo': 'MemTotal: 4194304 kB\n'})
        self.assertEqual(admission.budget_mb(v1), int(4096 * 0.85) - admission.DAEMON_MB)

    def test_the_mix_that_was_killed_is_not_admitted_at_a_two_gb_limit(self):
        a = admission.Admission(admission.budget_mb(reader({'/sys/fs/cgroup/memory.max': str(2048 * MB)})))
        running = ['nuclei_deep']
        self.assertTrue(a.can_start('nuclei_light', running))  # two runs fit
        running.append('nuclei_light')
        self.assertFalse(a.can_start('nuclei_light', running))  # a third, with the browser's weight on top, never
        self.assertFalse(a.can_start('nuclei_light', running + ['web_screenshot']))
        self.assertTrue(a.can_start('web_screenshot', running))
        running.append('web_screenshot')
        self.assertFalse(a.can_start('nuclei_light', running))
        self.assertFalse(a.can_start('web_screenshot', running))
        self.assertTrue(a.can_start('http_probe', running))  # a small probe costs next to nothing and is never starved
        self.assertLessEqual(a.used(running), a.budget)

    def test_a_task_alone_is_always_admitted_even_past_a_tiny_budget(self):
        a = admission.Admission(100)
        self.assertTrue(a.can_start('nuclei_deep', []))
        self.assertFalse(a.can_start('nuclei_deep', ['nuclei_deep']))

    def test_the_poll_asks_only_for_kinds_that_fit(self):
        d = daemon.Daemon('https://cve.example.test', 'tok', client=FakeClient(), max_concurrent=6)
        d.admission = admission.Admission(1100)
        d._in_flight = {1: {'kind': 'nuclei_deep'}, 2: {'kind': 'nuclei_light'}}
        with mock.patch.object(daemon, 'runnable_kinds', return_value=['nuclei_light', 'nuclei_deep', 'web_screenshot', 'http_probe', 'nmap_full']):
            plan = d._poll_plan()
        self.assertNotIn('nuclei_light', plan)
        self.assertNotIn('nuclei_deep', plan)
        self.assertNotIn('web_screenshot', plan)
        self.assertIn('http_probe', plan)

    def test_a_task_that_no_longer_fits_when_it_arrives_is_released_not_run(self):
        fc = FakeClient()
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc, max_concurrent=6)
        d.admission = admission.Admission(600)
        d._in_flight = {1: {'kind': 'nuclei_deep'}}
        d._start_task({'id': 9, 'kind': 'nuclei_light', 'target': {'targets': ['192.0.2.1']}}, ['nuclei_light'])
        self.assertNotIn(('POST', 'sentinel/tasks/9/accept'), fc.paths())
        self.assertIn(('POST', 'sentinel/tasks/9/release'), fc.paths())

    def test_nuclei_concurrency_and_rate_scale_down_with_the_budget(self):
        from cvengine_scanner.flags import NUCLEI_FLAGS
        small = tools.nuclei_flags_for_budget(NUCLEI_FLAGS, 300)
        big = tools.nuclei_flags_for_budget(NUCLEI_FLAGS, 4000)
        self.assertLess(int(small[small.index('-c') + 1]), 40)
        self.assertLess(int(small[small.index('-rl') + 1]), 150)
        self.assertEqual(big[big.index('-c') + 1], '40')  # never raised past the flags' own value
        self.assertEqual(tools.nuclei_env()['GOMEMLIMIT'], f'{admission.NUCLEI_GOMEMLIMIT_MB}MiB')

    KILL = [sys.executable, '-c', 'import os, signal; os.kill(os.getpid(), signal.SIGKILL)']

    def test_a_tool_killed_by_the_system_says_out_of_memory_retry_later(self):
        with mock.patch('client.tools._oom_events', side_effect=[0, 1]), self.assertRaises(tools.ToolOOMError) as ctx:  # the cgroup counted a kill
            tools._run(self.KILL, 30)
        self.assertTrue(str(ctx.exception).startswith('out of memory, retry later'))
        self.assertNotIn('status -9', str(ctx.exception))
        with mock.patch('client.tools._oom_events', return_value=None), self.assertRaises(tools.ToolOOMError):  # a host that cannot say is taken as memory
            tools._run(self.KILL, 30)
        with self.assertRaises(tools.ToolExitError) as other:  # an ordinary failure keeps its own words
            tools._run([sys.executable, '-c', 'raise SystemExit(3)'], 30)
        self.assertNotIsInstance(other.exception, tools.ToolOOMError)

    def test_a_kill_the_cgroup_did_not_count_and_the_daemons_own_stop_are_not_called_out_of_memory(self):
        with mock.patch('client.tools._oom_events', side_effect=[4, 4]), self.assertRaises(tools.ToolExitError) as ctx:
            tools._run(self.KILL, 30)
        self.assertNotIsInstance(ctx.exception, tools.ToolOOMError)
        handles = []
        with mock.patch('client.tools._oom_events', return_value=None), self.assertRaises(tools.ToolExitError) as stopped:
            tools._run([sys.executable, '-c', 'import time; time.sleep(30)'], 30, register=lambda h: (handles.append(h), threading.Timer(0.3, h.kill).start()))
        self.assertNotIsInstance(stopped.exception, tools.ToolOOMError)


class ClaimTests(unittest.TestCase):
    def make(self, fc, mc=4):
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc, max_concurrent=mc)
        d.stop_event.wait = mock.Mock(return_value=False)
        return d

    def test_retry_after_is_parsed_from_the_header_and_capped(self):
        self.assertEqual(httpclient.parse_retry_after('7'), 7.0)
        self.assertEqual(httpclient.parse_retry_after('99999'), httpclient.MAX_RETRY_AFTER)
        self.assertIsNone(httpclient.parse_retry_after('soon'))
        resp = mock.Mock(status_code=429, content=b'{"error": "too many claim calls"}', headers={'Retry-After': '9'})
        resp.iter_content.return_value = [resp.content]  # ``call`` reads the answer in chunks, up to a size limit
        resp.json.return_value = {'error': 'too many claim calls'}
        client = httpclient.Client('https://cve.example.test', 'tok', session=mock.Mock(request=mock.Mock(return_value=resp)))
        with self.assertRaises(httpclient.ApiError) as ctx:
            client.call('POST', 'sentinel/tasks/next', {})
        self.assertEqual(ctx.exception.retry_after, 9.0)

    def test_a_429_on_the_poll_waits_the_retry_after_not_the_next_poll(self):
        fc = FakeClient()
        fc.script[('POST', 'sentinel/tasks/next')] = [httpclient.ApiError(429, 'too many claim calls', retry_after=20.0)]
        d = self.make(fc)
        d._poll_once()
        waits = [c.args[0] for c in d.stop_event.wait.call_args_list]
        self.assertTrue(waits and waits[-1] >= 20.0, waits)

    def test_a_429_on_accept_is_waited_out_and_the_task_still_runs(self):
        fc = FakeClient()
        fc.script[('POST', 'sentinel/tasks/5/accept')] = [httpclient.ApiError(429, 'too many claim calls', retry_after=3.0)]
        fc.next_responses = [{'task': {'id': 5, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.10']}}}]
        d = self.make(fc)
        with mock.patch.dict(tools.RUNNERS, {'nmap': mock.Mock(return_value={'hosts': []})}):
            d._poll_once()
            deadline = time.monotonic() + 3
            while d._active_count() and time.monotonic() < deadline:
                time.sleep(0.02)
        self.assertEqual(fc.count('sentinel/tasks/5/accept'), 2)
        self.assertEqual(fc.count('sentinel/tasks/5/result'), 1)
        self.assertEqual(fc.count('sentinel/tasks/5/release'), 0)

    def test_an_accept_that_never_gets_through_releases_the_task(self):
        fc = FakeClient()
        fc.script[('POST', 'sentinel/tasks/6/accept')] = [httpclient.ApiError(429, 'x', retry_after=1.0)] * 10
        d = self.make(fc)
        self.assertFalse(d._accept(6))
        fc_calls = fc.count('sentinel/tasks/6/accept')
        self.assertEqual(fc_calls, d.ACCEPT_TRIES)
        self.assertEqual(fc.count('sentinel/tasks/6/release'), 1)

    def test_the_claim_rate_scales_with_max_concurrent_and_stays_under_the_servers_limit(self):
        self.assertEqual(config.claim_limit(1), 60)
        self.assertGreater(config.claim_limit(10), config.claim_limit(2))
        clock = [0.0]
        pacer = admission.ClaimPacer(config.claim_limit(10), 60, clock=lambda: clock[0])
        calls = 0
        for _ in range(3000):  # a client with instant tasks, as fast as it can ask, for ten minutes
            wait = pacer.wait_needed()
            if wait > 0:
                clock[0] += wait
                continue
            pacer.note()
            calls += 1
            clock[0] += 0.01
            if clock[0] > 600:
                break
        window_max = max(sum(1 for t in pacer._calls if clock[0] - t < 60), 0)
        self.assertLessEqual(window_max, config.claim_limit(10))
        self.assertGreater(calls / (clock[0] / 60), config.claim_limit(10) * 0.5)  # and it still uses most of what it may

    def test_pacing_holds_the_poll_back_before_the_server_would_refuse_it(self):
        fc = FakeClient()
        d = self.make(fc, mc=1)
        d.pacer = admission.ClaimPacer(60, 60, share=0.75)
        for _ in range(45):
            d.pacer.note()
        d._poll_once()
        self.assertEqual(fc.count('sentinel/tasks/next'), 0)


class ShotProxyTests(unittest.TestCase):
    def test_accept_survives_a_refused_thread_and_gives_its_slot_back(self):
        proxy = shotproxy.VettingProxy(lambda *a: None, lambda *a: None, 'secret')
        real_start = threading.Thread.start
        refused = []

        def start(thread):
            if thread.name == 'shot-proxy-conn' and not refused:
                refused.append(1)
                raise RuntimeError("can't start new thread")
            return real_start(thread)
        with mock.patch.object(threading.Thread, 'start', start):
            port = proxy.start()
            try:
                for _ in range(2):  # the first connection is dropped, the proxy still answers the second
                    with socket.create_connection(('127.0.0.1', port), timeout=5) as s:
                        s.sendall(b'GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n')
                        s.settimeout(5)
                        try:
                            s.recv(100)
                        except OSError:
                            pass
                deadline = time.monotonic() + 3
                while proxy._open and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(refused, [1])
                self.assertEqual(proxy._open, 0)  # nothing leaked: the dropped connection's slot came back
                self.assertTrue(proxy._listener is not None)
                self.assertTrue(any(t.name == 'shot-proxy' and t.is_alive() for t in threading.enumerate()))
            finally:
                proxy.stop()

    def test_all_proxies_of_a_process_share_a_bounded_thread_budget(self):
        proxy = shotproxy.VettingProxy(lambda *a: None, lambda *a: None, 'secret')
        taken = [shotproxy._GLOBAL.acquire(blocking=False) for _ in range(shotproxy.GLOBAL_THREADS)]
        try:
            a, b = socket.socketpair()
            self.assertFalse(proxy._admit(a))
            b.close()
        finally:
            for ok in taken:
                if ok:
                    shotproxy._GLOBAL.release()


class AppArmorTests(unittest.TestCase):
    LOG = ('browserType.launch: Target page, context or browser has been closed\nBrowser logs:\n\n<launching> /ms-playwright/chromium/chrome\n'
           '[0107/101010.123:FATAL:credentials.cc(131)] Check failed: . : Permission denied (13)\n')

    def test_the_chromium_log_line_is_named_in_plain_words(self):
        words = shot_child.apparmor_words(self.LOG)
        self.assertIn('AppArmor', words)
        self.assertIn('user namespaces', words)
        self.assertNotIn('Target page', words)
        self.assertEqual(shot_child.apparmor_words('net::ERR_CONNECTION_REFUSED'), '')

    def test_a_launch_that_dies_of_it_raises_the_plain_sandbox_error(self):
        playwright = mock.Mock()
        playwright.chromium.launch.side_effect = Exception(self.LOG)
        with self.assertRaises(shot_child.SandboxError) as ctx:
            shot_child.launch(playwright)
        self.assertIn('AppArmor', str(ctx.exception))

    def test_a_failing_proof_withdraws_web_screenshot_and_a_passing_one_restores_it(self):
        d = daemon.Daemon('https://cve.example.test', 'tok', client=FakeClient())
        self.addCleanup(daemon._shot_state.__setitem__, 'blocked', None)
        reason = shot_child.APPARMOR
        with mock.patch.object(daemon.shot, 'sandbox_probe', return_value=(False, reason, '')), \
                mock.patch.object(config, 'poll_kinds', return_value=['http_probe', 'web_screenshot']), \
                mock.patch.object(daemon.shot, 'available', return_value=True), \
                mock.patch.object(config, 'server_knows', return_value=True):
            d.stop_event.wait = mock.Mock(side_effect=lambda t: d.stop_event.set() or True)
            d._check_screenshot_sandbox()
            self.assertEqual(daemon.shot_blocked_reason(), reason)
            self.assertNotIn('web_screenshot', daemon.runnable_kinds())
            self.assertNotIn('web_screenshot', daemon.declared_kinds())
            self.assertIn('http_probe', daemon.runnable_kinds())
            d.stop_event.clear()
            with mock.patch.object(daemon.shot, 'sandbox_probe', return_value=(True, '', '156')):
                d._check_screenshot_sandbox()
            self.assertIn('web_screenshot', daemon.runnable_kinds())


if __name__ == '__main__':
    unittest.main()
