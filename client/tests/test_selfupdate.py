"""cvENGINE asks a Sentinel to update: the drain-and-exit path, run against a fake supervisor (no Docker, no server)."""
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from client import config, control, daemon, selfupdate
from client.tests.test_daemon import FakeClient

OLD = 'a' * 12
NEW = 'b' * 40


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        env = {'CVENGINE_SENTINEL_TOKEN_FILE': os.path.join(self.dir.name, 'token.json'), 'CVENGINE_SENTINEL_UPDATE_EXIT': '1'}
        patch = mock.patch.dict('os.environ', env)
        patch.start()
        self.addCleanup(patch.stop)
        for name in ('CVENGINE_SENTINEL_UPDATE', 'CVENGINE_SCANNER_BUILTIN', 'CVENGINE_SENTINEL_BUILTIN'):
            os.environ.pop(name, None)


def reply(**over):
    return {'setting': 'automatic', 'mode': 'auto', 'requested': True, 'target': NEW, 'reason': 'newest', **over}


class DecisionTests(Base):
    def test_a_request_with_a_newer_target_leaves(self):
        self.assertEqual(selfupdate.should_exit(reply(), OLD), (True, NEW))

    def test_nothing_without_the_opt_in(self):
        del os.environ['CVENGINE_SENTINEL_UPDATE_EXIT']
        self.assertFalse(selfupdate.should_exit(reply(), OLD)[0])

    def test_nothing_when_nobody_asked_or_no_target(self):
        self.assertFalse(selfupdate.should_exit(reply(requested=False), OLD)[0])
        self.assertFalse(selfupdate.should_exit(reply(target=''), OLD)[0])
        self.assertFalse(selfupdate.should_exit(reply(target='not a commit; rm -rf /'), OLD)[0])
        self.assertFalse(selfupdate.should_exit(None, OLD)[0])
        self.assertFalse(selfupdate.should_exit('x', OLD)[0])

    def test_never_when_self_update_is_off_here_or_there(self):
        self.assertFalse(selfupdate.should_exit(reply(setting='off'), OLD)[0])
        os.environ['CVENGINE_SENTINEL_UPDATE'] = 'off'  # this machine's own ceiling
        self.assertFalse(selfupdate.should_exit(reply(), OLD)[0])

    def test_never_to_the_build_it_already_runs(self):
        self.assertFalse(selfupdate.should_exit(reply(target=OLD), OLD)[0])
        self.assertFalse(selfupdate.should_exit(reply(target=OLD + 'cccc'), OLD)[0])
        self.assertFalse(selfupdate.should_exit(reply(target=NEW[:12]), NEW)[0])

    def test_the_built_in_scanner_never_leaves(self):
        with mock.patch.object(config, 'builtin', return_value=True):
            self.assertFalse(selfupdate.should_exit(reply(), OLD)[0])  # its local ceiling is off: the host replaces its image

    def test_the_same_target_is_not_tried_again_within_six_hours(self):
        selfupdate.remember(NEW, now=1000)
        self.assertFalse(selfupdate.should_exit(reply(), OLD, now=1000 + 60)[0])
        self.assertTrue(selfupdate.should_exit(reply(), OLD, now=1000 + selfupdate.RETRY_AFTER + 1)[0])
        self.assertTrue(selfupdate.should_exit(reply(target='c' * 40), OLD, now=1060)[0])  # another target is a new question


class DrainAndExitTests(Base):
    def make(self):
        d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        d.exit_code = 0
        return d

    def test_it_waits_for_the_running_task_then_exits_with_the_documented_code(self):
        d = self.make()
        d._in_flight = {7: {'done': threading.Event(), 'kind': 'nmap'}}
        t = threading.Thread(target=d._drain_and_exit, args=(NEW,), kwargs={'timeout': 30})
        with mock.patch.object(config, 'version', return_value=OLD):
            t.start()
            time.sleep(1.3)
            self.assertTrue(control.is_draining())  # it takes nothing new while it waits
            self.assertEqual(d.exit_code, 0)  # the task still runs: nothing is cut off
            self.assertFalse(d.stop_event.is_set())
            d._in_flight = {}
            t.join(10)
        self.assertEqual(d.exit_code, selfupdate.UPDATE_EXIT)
        self.assertTrue(d.stop_event.is_set())
        self.assertEqual(selfupdate.last()['target'], NEW)
        self.assertEqual(control.read_update()['status'], 'updating')

    def test_a_task_that_outlasts_the_drain_limit_keeps_the_sentinel_working(self):
        d = self.make()
        d._in_flight = {7: {'done': threading.Event(), 'kind': 'openvas'}}
        with mock.patch.object(config, 'version', return_value=OLD):
            d._drain_and_exit(NEW, timeout=0.2)
        self.assertEqual(d.exit_code, 0)
        self.assertFalse(d.stop_event.is_set())
        self.assertFalse(control.is_draining())  # back to work
        self.assertEqual(control.read_update()['status'], 'waiting')
        self.assertFalse(selfupdate.should_exit(reply(), OLD)[0])  # and not asked again for six hours

    def test_the_heartbeat_starts_one_drain_and_only_one(self):
        d = self.make()
        with mock.patch.object(config, 'version', return_value=OLD), mock.patch.object(d, '_drain_and_exit') as drain:
            d._consider_update_exit(reply())
            d._consider_update_exit(reply())
        drain.assert_called_once_with(NEW)

    def test_a_poll_in_flight_holds_the_exit_back(self):
        d = self.make()
        d._polling = True
        t = threading.Thread(target=d._drain_and_exit, args=(NEW,), kwargs={'timeout': 30})
        with mock.patch.object(config, 'version', return_value=OLD):
            t.start()
            time.sleep(1.3)
            self.assertEqual(d.exit_code, 0)  # a long poll may still hand over a task
            d._polling = False
            t.join(10)
        self.assertEqual(d.exit_code, selfupdate.UPDATE_EXIT)


class FakeSupervisor:
    """What a puller does: run the Sentinel, and when it exits with ``UPDATE_EXIT`` bring the newest image and start it again."""

    def __init__(self, image):
        self.image, self.newest, self.starts = image, image, []

    def run_once(self, make_daemon, beats):
        self.starts.append(self.image)
        d = make_daemon(self.image)
        for _ in range(beats):
            d._consider_update_exit(reply(target=self.newest))
            time.sleep(0.1)
            if d.stop_event.is_set():
                break
        d.stop_event.wait(5)
        if d.exit_code == selfupdate.UPDATE_EXIT:
            self.image = self.newest  # docker compose pull && up -d
        return d.exit_code


class SupervisorTests(Base):
    def test_it_leaves_with_76_comes_back_on_the_newer_image_and_does_not_leave_again(self):
        sup = FakeSupervisor(OLD)
        sup.newest = NEW[:12]

        def make(image):
            d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
            d.exit_code = 0
            return d

        with mock.patch.object(config, 'version', side_effect=lambda: sup.image):
            self.assertEqual(sup.run_once(make, 60), selfupdate.UPDATE_EXIT)
            self.assertEqual(sup.image, NEW[:12])
            self.assertEqual(sup.run_once(make, 5), 0)  # running the target: the request names its own build and nothing happens
        self.assertEqual(sup.starts, [OLD, NEW[:12]])

    def test_a_supervisor_that_brings_nothing_newer_is_not_a_restart_loop(self):
        sup = FakeSupervisor(OLD)  # newest stays the old image: a puller with nothing to pull
        sup.newest = OLD

        def make(image):
            d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
            d.exit_code = 0
            return d

        selfupdate.remember(NEW)  # it already left once for NEW
        with mock.patch.object(config, 'version', side_effect=lambda: OLD):
            d = make(OLD)
            d._consider_update_exit(reply())
            self.assertFalse(d.stop_event.is_set())


if __name__ == '__main__':
    unittest.main()
