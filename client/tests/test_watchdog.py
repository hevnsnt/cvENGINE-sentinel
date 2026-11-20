"""The Sentinel watchdog (client/watchdog.py): one test class per rule. Real ``sleep`` process groups prove the group kill and the zombie reaping; a fake
clock drives the deadlines; the memory simulation reproduces the owner's Scanners page (two 520 MB nuclei holders for 15 minutes, a budget of 1540 MB)."""
import io
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from client import admission, config, control, daemon, tools, watchdog
from client.tests.test_daemon import FakeClient

NUCLEI_LINE = json.dumps({'template-id': 'demo', 'info': {'name': 'Demo', 'severity': 'low'}, 'host': 'example.com', 'matched-at': 'https://example.com/'})


class FakeTime:
    """The ``time`` module as the daemon sees it, with a monotonic clock a test moves."""

    def __init__(self):
        self.now = 10_000.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds

    def __getattr__(self, name):
        return getattr(time, name)


def make_daemon(budget=1540, max_concurrent=6):
    d = daemon.Daemon('https://cve.example.test', 'tok', client=FakeClient(), max_concurrent=max_concurrent)
    d.admission = admission.Admission(budget)
    d.stop_event.wait = mock.Mock(return_value=False)
    return d


def group_alive(pgid):
    row = watchdog.scan_proc().get(pgid)
    return bool(row and watchdog.live_pids(row))


def wait_until(check, seconds=8.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.02)
    return check()


def results(d, task_id):
    return [b for _m, p, b in d.client.calls if p == f'sentinel/tasks/{task_id}/result']


class Env(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patch = mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_TOKEN_FILE': os.path.join(self.dir.name, 'token.json')})
        patch.start()
        self.addCleanup(patch.stop)
        self.procs = []
        self.threads = []
        self.addCleanup(self.reap)

    def reap(self):
        # the fake tools' process groups first, then the task threads that waited on them: a task thread left running writes into this test's
        # directory and logs while the next test (or the interpreter's shutdown) runs, which failed the directory clean-up and aborted
        # the interpreter at exit ("could not acquire lock for <stderr> at interpreter shutdown, possibly due to daemon threads")
        for proc in self.procs:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
            except Exception:  # noqa: BLE001
                pass
        for state, thread in self.threads:
            for pgid in list(state.get('pgids') or ()):
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except OSError:
                    pass
            thread.join(10)
            self.assertFalse(thread.is_alive(), 'a task thread outlived its test')

    def run_task(self, d, kind, argv, task_id=7, target=None, secret=None):
        """Run a fake tool (a real process group) as a real task thread of ``d``; returns its state and the thread."""
        def runner(*_a, register=None, **_k):
            return {'findings': tools.parse_nuclei_jsonl(tools._run(argv, 3600, register))}
        tools.RUNNERS[kind] = runner
        self.addCleanup(lambda: tools.RUNNERS.update({kind: tools.run_nuclei}) if kind.startswith('nuclei') else None)
        state = {'proc': None, 'done': threading.Event(), 'started': time.monotonic(), 'dropped': False, 'finishing': False, 'kind': kind, 'runnable': True, 'pgids': set()}
        with d._lock:
            d._in_flight[task_id] = state
        thread = threading.Thread(target=d._run_task, args=({'id': task_id, 'kind': kind, 'target': target or {'targets': ['example.com']}}, state), daemon=True)
        state['thread'] = thread
        self.threads.append((state, thread))
        thread.start()
        self.assertTrue(wait_until(lambda: state['pgids']), 'the tool never started')
        return state, thread


class DeadlineTableTests(unittest.TestCase):
    def test_every_deadline_is_above_the_tool_own_budget(self):
        for kind, budget in watchdog.TOOL_BUDGET_SECONDS.items():
            self.assertGreaterEqual(watchdog.deadline_seconds(kind), budget + watchdog.GRACE_SECONDS, kind)
        self.assertEqual(watchdog.deadline_seconds('nuclei_deep'), 3900)  # 60 minutes of nuclei plus 5 of grace
        self.assertEqual(watchdog.deadline_seconds('some_probe'), 1200)

    def test_the_owner_can_raise_a_deadline_but_never_put_it_under_the_tool_budget(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DEADLINE_NUCLEI_DEEP_MIN': '240'}):
            self.assertEqual(watchdog.deadline_seconds('nuclei_deep'), 240 * 60)
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DEADLINE_NUCLEI_DEEP_MIN': '5', 'CVENGINE_SENTINEL_DEADLINE_DEFAULT_MIN': '5'}):
            self.assertGreaterEqual(watchdog.deadline_seconds('nuclei_deep'), 3600)
            self.assertGreaterEqual(watchdog.deadline_seconds('testssl'), 900)

    def test_a_task_that_carries_its_own_time_limit_is_never_stopped_before_it(self):
        self.assertGreaterEqual(watchdog.deadline_seconds('wpscan_thorough', 20 * 3600), 20 * 3600 + 600)
        self.assertGreaterEqual(watchdog.deadline_seconds('bbot_discovery', 86400), 86400 + 600)


class DeadlineKillTests(Env):
    def test_a_hung_tool_group_is_killed_at_its_deadline_reported_and_its_memory_released(self):
        d = make_daemon()
        wd = watchdog.Watchdog(d)
        state, thread = self.run_task(d, 'nuclei_deep', ['sh', '-c', 'sleep 600 & sleep 600'])  # a tool and a child it started
        pgid = next(iter(state['pgids']))
        self.assertTrue(group_alive(pgid))
        self.assertEqual(d.admission.used(['nuclei_deep']), 520)
        wd.tick()
        self.assertTrue(group_alive(pgid))  # not yet: neither the deadline nor the no-progress limit has passed
        state['started'] -= watchdog.deadline_seconds('nuclei_deep') + 60  # the task is now past its deadline
        wd.tick()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertTrue(wait_until(lambda: not group_alive(pgid)), 'the whole process group (the tool and its child) must be gone')
        sent = results(d, 7)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]['outcome'], 'error')  # the contract's own vocabulary
        self.assertRegex(sent[0]['error'], r'timed out after \d+ minutes')
        self.assertNotIn(7, d._in_flight)
        self.assertEqual(d.admission.used([s.get('kind') for s in d._in_flight.values()]), 0)  # its reservation is free again
        self.assertEqual(wd.kills['nuclei_deep'].__len__(), 1)
        self.assertEqual(daemon._watchdog_report['kills'], 1)

    def test_a_stopped_nuclei_run_delivers_the_findings_it_had_already_printed(self):
        d = make_daemon()
        wd = watchdog.Watchdog(d)
        state, thread = self.run_task(d, 'nuclei_light', ['sh', '-c', f"echo '{NUCLEI_LINE}'; sleep 600"])
        time.sleep(0.4)  # the line is read
        state['started'] -= 9999
        wd.tick()
        thread.join(10)
        sent = results(d, 7)
        self.assertEqual(sent[0]['outcome'], 'done')
        self.assertEqual([f['template_id'] for f in sent[0]['findings']], ['demo'])

    def test_a_stopped_run_with_nothing_is_an_error_never_an_empty_done(self):
        d = make_daemon()
        wd = watchdog.Watchdog(d)
        state, thread = self.run_task(d, 'nuclei_light', ['sleep', '600'])
        state['started'] -= 9999
        wd.tick()
        thread.join(10)
        self.assertEqual(results(d, 7)[0]['outcome'], 'error')

    def test_a_task_that_cannot_be_killed_is_still_reported_and_given_up(self):
        d = make_daemon()
        wd = watchdog.Watchdog(d)
        release = threading.Event()
        proc = mock.Mock()
        proc.poll.return_value = None
        state = {'proc': proc, 'done': threading.Event(), 'started': time.monotonic() - 99999, 'dropped': False, 'finishing': False, 'kind': 'http_probe',
                 'pgids': set(), 'thread': threading.Thread(target=release.wait, daemon=True)}
        state['thread'].start()  # an in-process probe stuck in a socket call
        self.addCleanup(release.set)
        d._in_flight[9] = state
        wd.tick()
        self.assertIn('wd', state)
        proc.terminate.assert_called_once()
        state['wd']['at'] -= watchdog.ABANDON_SECONDS + 1
        wd.tick()
        self.assertTrue(wait_until(lambda: results(d, 9)))
        self.assertEqual(results(d, 9)[0]['outcome'], 'error')
        self.assertNotIn(9, d._in_flight)  # its slot and weight are free though its thread never returned


class NoProgressTests(Env):
    def test_a_silent_idle_group_is_stopped_after_its_limit_and_a_working_one_is_not(self):
        d = make_daemon()
        fake = FakeTime()
        wd = watchdog.Watchdog(d, clock=fake.monotonic)
        with mock.patch.object(daemon, 'time', fake):
            idle_state, idle_thread = self.run_task(d, 'testssl', ['sleep', '600'], task_id=1)
            busy_state, busy_thread = self.run_task(d, 'testssl', ['sh', '-c', 'while :; do :; done'], task_id=2)
            for state in (idle_state, busy_state):
                state['started'] = fake.now
            wd.tick()
            for _ in range(watchdog.no_progress_seconds('testssl') // 60 + 2):
                time.sleep(0.15)  # the busy loop burns real CPU between ticks
                fake.advance(60)
                wd.tick()
            idle_thread.join(10)
        self.assertEqual(results(d, 1)[0]['outcome'], 'error')
        self.assertRegex(results(d, 1)[0]['error'], r'no output and no CPU for \d+ minutes')
        self.assertFalse(group_alive(next(iter(idle_state['pgids']))))
        self.assertTrue(group_alive(next(iter(busy_state['pgids']))), 'a group that uses CPU is working, whatever it prints')
        self.assertNotIn('wd', busy_state)

    def test_openvas_and_thorough_wpscan_have_no_idle_rule(self):
        self.assertIsNone(watchdog.no_progress_seconds('openvas'))
        self.assertIsNone(watchdog.no_progress_seconds('wpscan_thorough'))

    def test_the_limit_has_its_own_variable(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_NOPROGRESS_NMAP_MIN': '7'}):
            self.assertEqual(watchdog.no_progress_seconds('nmap'), 420)


class MemoryDeadlockTests(unittest.TestCase):
    """The owner's Scanners page: a budget of 1540 MB, two nuclei runs of 520 MB for 15 minutes, the next ones waiting 8 minutes with 500 MB free."""

    LIMIT_MB = 2048

    def sim(self, with_watchdog, waiters, holders=(('nuclei_deep', 300.0), ('nuclei_targeted', 300.0), ('secrets_scan', 100.0)), seconds=900):
        fake = FakeTime()
        real = {}  # fake pgid -> real MB the simulated tool uses
        d = make_daemon()
        wd = watchdog.Watchdog(d, clock=fake.monotonic, wall=lambda: 1_700_000_000 + fake.now, mem=lambda: {'limit_mb': self.LIMIT_MB, 'avail_mb': self.LIMIT_MB - 200 - sum(real.values())},
                               disk=lambda: 10_000)
        scans = {}
        admitted = []
        self.max_over = 0

        def add(task_id, kind, mb, age):
            state = {'proc': mock.Mock(), 'done': threading.Event(), 'started': fake.now - age, 'dropped': False, 'finishing': False, 'kind': kind, 'pgids': {task_id + 100_000}}
            d._in_flight[task_id] = state
            real[task_id + 100_000] = mb
            scans[task_id + 100_000] = {'rss_mb': mb, 'cpu': 1, 'io': 1, 'pids': [task_id], 'zombies': [], 'parents': {}}
            return state
        with mock.patch.object(daemon, 'time', fake), mock.patch.object(watchdog, 'scan_proc', lambda root='/proc': scans), \
                mock.patch.object(watchdog.Watchdog, '_publish', lambda *a: None):
            for i, (kind, mb) in enumerate(holders, start=1):
                add(i, kind, mb, 900)  # they have run 15 minutes already
            for step in range(0, seconds, 10):
                fake.advance(10)
                for st in d._in_flight.values():  # the holders keep working (the no-progress rule is not what this test is about)
                    scans[next(iter(st['pgids']))]['cpu'] += 1
                if with_watchdog:
                    wd.tick()
                    self.max_over = max(self.max_over, d.admission.overcommit_mb)
                plan = d._poll_plan()
                for kind in waiters:
                    if kind in plan and kind not in [k for _t, k in admitted]:
                        tid = 100 + len(admitted)
                        mb = {'nuclei_light': 480.0, 'nuclei_targeted': 480.0, 'web_screenshot': 224.0}.get(kind, 100.0)  # what they really use (measured peaks)
                        add(tid, kind, mb, 0)
                        admitted.append((fake.now - 10_000, kind))
                        break
        return d, admitted, real, wd

    def test_without_the_watchdog_the_big_waiters_starve_for_the_whole_run(self):
        d, admitted, real, _wd = self.sim(False, ['nuclei_light', 'nuclei_targeted', 'web_screenshot'])
        self.assertEqual([k for _t, k in admitted if k.startswith('nuclei')], [])  # 15 minutes, nobody gets in: the screenshot
        self.assertEqual(d.admission.used([s['kind'] for s in d._in_flight.values()]), 520 + 520 + 150 + sum(admission.weight(k) for _t, k in admitted))

    def test_with_the_watchdog_a_waiter_is_admitted_within_minutes_and_real_memory_stays_above_the_floor(self):
        d, admitted, real, wd = self.sim(True, ['nuclei_light', 'nuclei_targeted', 'web_screenshot'])
        self.assertTrue(admitted, 'nobody was admitted')
        first_after = min(t for t, _k in admitted)
        self.assertLessEqual(first_after, 240, f'admitted after {first_after}s')  # waited 3 minutes, plus a tick and a poll
        floor = max(300, int(self.LIMIT_MB * 0.15))
        used_real = 200 + sum(real.values())  # the daemon and every tool: the real memory of the container
        self.assertLessEqual(used_real, self.LIMIT_MB - floor, f'real use {used_real} MB is over the floor ({floor} MB free)')
        self.assertLess(len(admitted), 3, 'the overcommit is bounded by the real room: not everyone gets in')
        self.assertGreater(self.max_over, 0)
        self.assertLessEqual(self.max_over, int(1540 * 0.25))

    def test_the_overcommit_never_exceeds_a_quarter_of_the_budget(self):
        d, _admitted, _real, wd = self.sim(True, ['nuclei_light', 'nuclei_targeted'], holders=(('nuclei_deep', 10.0), ('nuclei_targeted', 10.0)))
        self.assertLessEqual(d.admission.overcommit_mb, int(1540 * 0.25))

    def test_no_overcommit_when_real_memory_is_not_there(self):
        # the same two long holders, but they really use 700 MB each: the room is under the floor and nobody is let in
        d, admitted, real, wd = self.sim(True, ['nuclei_light', 'nuclei_targeted'], holders=(('nuclei_deep', 700.0), ('nuclei_targeted', 700.0)))
        self.assertEqual(admitted, [])
        self.assertEqual(d.admission.overcommit_mb, 0)

    def test_nothing_is_overcommitted_before_the_waiters_have_waited_or_the_holders_have_run(self):
        d = make_daemon()
        wd = watchdog.Watchdog(d, mem=lambda: {'limit_mb': 2048, 'avail_mb': 1500}, disk=lambda: 10_000)
        now = time.monotonic()
        for i, kind in enumerate(('nuclei_deep', 'nuclei_targeted')):
            d._in_flight[i] = {'proc': None, 'done': threading.Event(), 'started': now - 60, 'dropped': False, 'finishing': False, 'kind': kind, 'pgids': set()}
        d._blocked_since['nuclei_light'] = now - 600  # waited long, but the holders are young: no fair share yet
        wd._rule_memory(now, {})
        self.assertEqual(wd.overcommit_mb, 0)
        for st in d._in_flight.values():
            st['started'] = now - 900
        d._blocked_since['nuclei_light'] = now - 10  # holders old, waiter fresh
        wd._rule_memory(now, {})
        self.assertEqual(wd.overcommit_mb, 0)

    def test_the_last_resort_stop_is_off_unless_asked_for(self):
        d = make_daemon()
        wd = watchdog.Watchdog(d, mem=lambda: {'limit_mb': 2048, 'avail_mb': 10}, disk=lambda: 10_000)
        now = time.monotonic()
        d._in_flight[1] = {'proc': mock.Mock(), 'done': threading.Event(), 'started': now - 900, 'dropped': False, 'finishing': False, 'kind': 'nuclei_deep', 'pgids': set()}
        wd._rule_memory(now, {})
        self.assertNotIn('wd', d._in_flight[1])
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_WATCHDOG_MEM_KILL': '1'}):
            wd = watchdog.Watchdog(d, mem=lambda: {'limit_mb': 2048, 'avail_mb': 10}, disk=lambda: 10_000)
        wd._rule_memory(now, {})
        self.assertIn('wd', d._in_flight[1])
        self.assertIn('out of memory, retry later', d._in_flight[1]['wd']['text'])


class OrphanTests(Env):
    def test_a_group_that_outlived_its_task_is_killed_and_its_zombie_reaped(self):
        d = make_daemon()
        fake = FakeTime()
        wd = watchdog.Watchdog(d, clock=fake.monotonic)
        proc = subprocess.Popen(['sh', '-c', 'sleep 600 & sleep 600'], start_new_session=True)
        self.procs.append(proc)
        pgid = proc.pid
        self.assertTrue(wait_until(lambda: len(watchdog.scan_proc().get(pgid, {}).get('pids', [])) >= 2))
        wd.task_ended({'pgids': {pgid}})  # its task thread is over; the tool is not
        wd.tick()
        self.assertTrue(group_alive(pgid))  # inside the grace
        fake.advance(16)
        wd.tick()
        self.assertTrue(wait_until(lambda: not group_alive(pgid)))
        self.assertTrue(any(a['code'] == 'orphans' for a in wd.actions))
        row = watchdog.scan_proc().get(pgid)
        self.assertTrue(row and row['zombies'], 'the killed direct child is a zombie until it is reaped')
        wd.tick()  # the next tick reaps it
        self.assertTrue(wait_until(lambda: pgid not in watchdog.scan_proc()))
        self.assertEqual(wd.reaped_zombies, 1)
        self.assertNotIn(pgid, wd.watch)

    def test_a_group_a_running_task_owns_is_never_touched(self):
        d = make_daemon()
        fake = FakeTime()
        wd = watchdog.Watchdog(d, clock=fake.monotonic)
        proc = subprocess.Popen(['sleep', '600'], start_new_session=True)
        self.procs.append(proc)
        d._in_flight[1] = {'proc': None, 'done': threading.Event(), 'started': time.monotonic(), 'dropped': False, 'finishing': False, 'kind': 'naabu', 'pgids': {proc.pid}}
        wd.task_ended({'pgids': {proc.pid}})
        fake.advance(60)
        wd.tick()
        self.assertTrue(group_alive(proc.pid))


class LivenessTests(Env):
    def setUp(self):
        super().setUp()
        patch = mock.patch.object(watchdog.Watchdog, '_hard_exit', lambda self: None)  # never end the test process
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_killed_heartbeat_thread_is_restarted(self):
        d = make_daemon()
        d.heartbeat_seconds = 0.05
        d.stop_event = threading.Event()
        beats = []

        def once():
            beats.append(threading.current_thread().name)
            if len(beats) == 1:
                raise SystemExit  # the thread dies, whatever the daemon's own catch-all says
        d._heartbeat_once = once
        wd = watchdog.Watchdog(d)
        wd.cfg['hb_stale'] = 0.4
        first = threading.Thread(target=d._heartbeat_loop, args=(d._hb_gen,), name='sentinel-heartbeat', daemon=True)
        first.start()
        first.join(3)
        self.assertFalse(first.is_alive())
        d.poll_beat_at = time.monotonic() + 1000  # the poll loop is fine
        time.sleep(0.5)
        wd._rule_liveness(time.monotonic(), {})
        self.assertTrue(wait_until(lambda: len(beats) >= 3), 'the replacement heartbeat thread never ran')
        self.assertTrue(any(a['code'] == 'heartbeat_restart' for a in wd.actions))
        self.assertEqual(d.exit_code, 0)
        d.stop_event.set()

    def test_a_stuck_heartbeat_that_cannot_be_revived_ends_the_process_with_the_wedged_code(self):
        d = make_daemon()
        d.stop_event = threading.Event()
        wd = watchdog.Watchdog(d)
        d.poll_beat_at = time.monotonic() + 1000
        wd.cfg['hb_stale'] = 100
        d.hb_beat_at = time.monotonic() - 200
        with mock.patch.object(d, 'restart_heartbeat', return_value=True) as restart:
            wd._rule_liveness(time.monotonic(), {})
            restart.assert_called_once()
            self.assertEqual(d.exit_code, 0)
            d.hb_beat_at = time.monotonic() - 200  # stale again after the restart
            wd._rule_liveness(time.monotonic(), {})
        self.assertEqual(d.exit_code, daemon.WEDGED)
        self.assertTrue(d.stop_event.is_set())

    def test_a_stuck_poll_loop_ends_the_process_for_every_sentinel_not_only_the_built_in_one(self):
        d = make_daemon()
        d.stop_event = threading.Event()
        self.assertFalse(config.builtin())
        wd = watchdog.Watchdog(d)
        d.hb_beat_at = time.monotonic()
        d.poll_beat_at = time.monotonic() - wd.cfg['poll_stale'] - 5  # a DNS lookup that never returns
        wd._rule_liveness(time.monotonic(), {})
        self.assertEqual(d.exit_code, daemon.WEDGED)

    def test_a_dead_watchdog_thread_is_started_again_by_the_poll_loop(self):
        d = make_daemon()
        d.stop_event = threading.Event()
        d.guard.thread = threading.Thread(target=lambda: None)
        d.guard.thread.start()
        d.guard.thread.join()
        self.assertFalse(d.guard.alive())
        d.guard.tick_seconds = 0.05
        d.guard.start()
        self.assertTrue(wait_until(d.guard.alive))
        d.stop_event.set()


class HealthCheckTests(Env):
    def status(self, **liveness):
        now = int(time.time())
        control.write_status('v', 0, None, now=now, liveness={'wd': now, 'hb': now, 'poll': now, **liveness})
        return now

    def test_fresh_loops_are_healthy(self):
        self.status()
        self.assertEqual(control.health()[0], True)

    def test_each_stale_loop_makes_the_container_unhealthy_with_the_reason(self):
        now = int(time.time())
        for key, age, word in (('wd', control.WATCHDOG_STALE + 5, 'watchdog'), ('hb', control.HEARTBEAT_LOOP_STALE + 5, 'heartbeat'), ('poll', control.POLL_LOOP_STALE + 5, 'poll')):
            self.status(**{key: now - age})
            ok, why = control.health()
            self.assertFalse(ok, key)
            self.assertIn(word, why)

    def test_the_cli_exits_non_zero_when_unhealthy_and_zero_when_healthy(self):
        env = {**os.environ, 'PYTHONPATH': os.getcwd()}
        self.status()
        ok = subprocess.run([sys.executable, '-m', 'client.control', 'health'], env=env, capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.status(poll=int(time.time()) - 10_000)
        bad = subprocess.run([sys.executable, '-m', 'client.control', 'health'], env=env, capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn('poll loop', bad.stderr)

    def test_a_status_without_the_liveness_block_is_judged_as_before(self):
        control.write_status('v', 0, None)
        self.assertTrue(control.health()[0])

    def test_the_daemon_writes_the_liveness_it_is_judged_by(self):
        d = make_daemon()
        d._write_control()
        live = control.read_status()['liveness']
        self.assertEqual(sorted(live), ['hb', 'poll', 'wd'])


class DiskTests(Env):
    def test_low_disk_stops_taking_work_cleans_only_its_own_files_and_says_so(self):
        d = make_daemon()
        free = [100]
        wd = watchdog.Watchdog(d, disk=lambda: free[0])
        tmp = os.path.join(self.dir.name, 'tmp')
        os.makedirs(tmp)
        old_dir = os.path.join(tmp, 'cvengine-bbot-old')
        os.makedirs(old_dir)
        with open(os.path.join(old_dir, 'x'), 'w') as f:
            f.write('a' * 5000)
        fresh = os.path.join(tmp, 'cvengine-bbot-new')
        os.makedirs(fresh)
        other = os.path.join(tmp, 'users-file.txt')
        open(other, 'w').close()
        for path in (old_dir, os.path.join(old_dir, 'x'), other):
            os.utime(path, (1, 1))  # old
        with mock.patch.object(tempfile, 'tempdir', tmp):
            wd.tick()
            self.assertTrue(wd.low_disk)
            self.assertEqual(wd.filter_kinds(['nmap', 'naabu']), [])
            self.assertFalse(os.path.exists(old_dir))
            self.assertTrue(os.path.exists(fresh))
            self.assertTrue(os.path.exists(other))  # not ours by name: never touched
            self.assertTrue(daemon._watchdog_report['low_disk'])
            self.assertTrue(any('low disk' in r for r in daemon._watchdog_report['reasons']))
            free[0] = 1000
            wd.tick()
            self.assertFalse(wd.low_disk)
            self.assertEqual(wd.filter_kinds(['nmap']), ['nmap'])

    def test_the_state_volume_is_never_in_the_cleaned_places(self):
        d = make_daemon()
        wd = watchdog.Watchdog(d)
        state = os.path.dirname(config.token_path())
        os.makedirs(os.path.join(state, 'spool'), exist_ok=True)
        keep = os.path.join(state, 'spool', 'cvengine-old.json')
        open(keep, 'w').close()
        os.utime(keep, (1, 1))
        wd.clean_own_files(time.time())
        self.assertTrue(os.path.exists(keep))


class RateLimitTests(Env):
    def test_a_kind_stopped_too_often_is_withheld_then_offered_again(self):
        d = make_daemon()
        fake = FakeTime()
        wd = watchdog.Watchdog(d, clock=fake.monotonic)
        for _ in range(wd.cfg['kill_limit']):
            wd._count_kill(fake.now, 'nuclei_deep')
            fake.advance(60)
        self.assertEqual(wd.filter_kinds(['nuclei_deep', 'nmap']), ['nmap'])
        self.assertTrue(any(a['code'] == 'withheld' for a in wd.actions))
        fake.advance(wd.cfg['withhold'] + 1)
        wd.tick()
        self.assertEqual(wd.filter_kinds(['nuclei_deep', 'nmap']), ['nuclei_deep', 'nmap'])

    def test_stops_older_than_an_hour_do_not_count(self):
        d = make_daemon()
        fake = FakeTime()
        wd = watchdog.Watchdog(d, clock=fake.monotonic)
        for _ in range(wd.cfg['kill_limit'] - 1):
            wd._count_kill(fake.now, 'nmap')
        fake.advance(3700)
        wd._count_kill(fake.now, 'nmap')
        self.assertNotIn('nmap', wd.withheld)

    def test_the_poll_plan_drops_a_withheld_kind(self):
        d = make_daemon()
        d.guard.withheld['nuclei_deep'] = time.monotonic() + 600
        with mock.patch.object(d, '_poll_kinds', return_value=['nuclei_deep', 'nmap']):
            self.assertEqual(d._poll_plan(), ['nmap'])


class KillSwitchTests(Env):
    def test_off_means_no_watchdog_no_report_and_the_old_health_rules(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_WATCHDOG': '0'}):
            self.assertFalse(watchdog.enabled())
            daemon._watchdog_report.clear()
            d = make_daemon()
            self.assertIsNone(d.guard)
            self.assertNotIn('watchdog', daemon.info())
            d._write_control()
            self.assertNotIn('liveness', control.read_status())
            self.assertTrue(control.health()[0])
            self.assertEqual(d._poll_plan().__class__, list)

    def test_the_default_is_on(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('CVENGINE_SENTINEL_WATCHDOG', None)
            self.assertTrue(watchdog.enabled())
        for value in ('false', 'off', 'no', '0'):
            with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_WATCHDOG': value}):
                self.assertFalse(watchdog.enabled(), value)


class ReportAndLogTests(Env):
    SECRET = 'S3cr3t-token-value-123456'

    def test_the_heartbeat_field_is_optional_present_after_a_tick_and_carries_no_secret(self):
        daemon._watchdog_report.clear()
        self.assertNotIn('watchdog', daemon.info())
        d = make_daemon()
        wd = watchdog.Watchdog(d, disk=lambda: 10_000)
        wd.tick()
        report = daemon.info()['watchdog']
        for key in ('last_tick', 'actions_last_hour', 'kills', 'overcommit_active', 'reasons'):
            self.assertIn(key, report)
        self.assertEqual(report['kills'], 0)

    def test_no_secret_reaches_the_log_or_the_report(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        logging.getLogger().setLevel(logging.INFO)
        d = make_daemon()
        wd = watchdog.Watchdog(d, disk=lambda: 10_000)
        state, thread = self.run_task(d, 'nuclei_deep', ['sleep', '600'], target={'targets': ['example.com'], 'token': self.SECRET, 'secret': self.SECRET})
        state['started'] -= 99999
        wd.tick()
        thread.join(10)
        wd.tick()
        text = stream.getvalue() + json.dumps(daemon._watchdog_report) + json.dumps(results(d, 7))
        self.assertNotIn(self.SECRET, text)
        lines = [line for line in stream.getvalue().splitlines() if 'watchdog' in line]
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line, r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d', 'one line per action, with a timestamp')
        self.assertTrue(any('stopped_deadline' in line for line in lines))

    def test_a_server_that_does_not_know_the_field_is_not_asked_to(self):
        d = make_daemon()
        wd = watchdog.Watchdog(d, disk=lambda: 10_000)
        wd.tick()
        d._heartbeat_once()  # the fake server answers {}: nothing breaks
        body = d.client.body_for('sentinel/heartbeat')
        self.assertIn('watchdog', body['info'])
        self.assertEqual(daemon.config.CONTRACT_VERSION, body['info']['contract_version'])


class MemStateTests(unittest.TestCase):
    FILES = {'/proc/meminfo': 'MemTotal:  131072000 kB\nMemAvailable:  100000000 kB\n', '/sys/fs/cgroup/memory.max': '2147483648\n',
             '/sys/fs/cgroup/memory.current': '1073741824\n', '/sys/fs/cgroup/memory.stat': 'anon 1\ninactive_file 268435456\n'}

    def test_the_container_limit_and_working_set_are_read_from_the_cgroup_files_as_they_are_written(self):
        # the kernel's files end in a newline: a limit that is not parsed would fall back to the host's memory, 64 times too large
        state = watchdog.mem_state(lambda path: self.FILES.get(path, ''))
        self.assertEqual(state['limit_mb'], 2048)
        self.assertEqual(state['avail_mb'], 2048 - (1024 - 256))  # the limit less usage without the reclaimable page cache

    def test_a_real_read_strips_the_newline(self):
        with tempfile.NamedTemporaryFile('w', suffix='.max', delete=False) as handle:
            handle.write('2147483648\n')
        self.addCleanup(os.unlink, handle.name)
        self.assertEqual(watchdog._read(handle.name), '2147483648')

    def test_the_live_host_gives_a_limit_and_available_memory(self):
        state = watchdog.mem_state()
        self.assertGreater(state['limit_mb'], 0)
        self.assertGreater(state['avail_mb'], 0)


class ProcTests(Env):
    def test_scan_proc_reads_the_group_of_a_real_tool(self):
        proc = subprocess.Popen(['sh', '-c', 'sleep 600 & sleep 600'], start_new_session=True)
        self.procs.append(proc)
        self.assertTrue(wait_until(lambda: len(watchdog.scan_proc().get(proc.pid, {}).get('pids', [])) >= 2))
        row = watchdog.scan_proc()[proc.pid]
        self.assertGreater(row['rss_mb'], 0)

    def test_pgid_of_a_handle_without_a_process_is_none(self):
        self.assertIsNone(watchdog.pgid_of(mock.Mock()))
        self.assertIsNone(watchdog.pgid_of(None))



class AdmissionAction(Env):
    def test_a_task_started_inside_the_overcommit_is_recorded_as_an_action(self):
        d = make_daemon()
        d.admission.overcommit_mb = 385
        now = time.monotonic()
        for i, kind in enumerate(('nuclei_deep', 'nuclei_targeted')):
            d._in_flight[i] = {'proc': None, 'done': threading.Event(), 'started': now - 900, 'dropped': False, 'finishing': False, 'kind': kind, 'pgids': set()}
        with mock.patch.object(d, '_accept', return_value=False):
            d._start_task({'id': 55, 'kind': 'nuclei_light', 'target': {}}, ['nuclei_light'])
        self.assertTrue(any(a['code'] == 'overcommit' and a['kind'] == 'nuclei_light' for a in d.guard.actions))


if __name__ == '__main__':
    unittest.main()
