"""bbot discovery as a streamed task (client/bbot.py): the command, the scope, the batches and how the run ends."""
import base64
import io
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from jsonschema import Draft202012Validator

from client import bbot, httpclient
from cvengine_scanner import contract

TARGET = json.loads((contract.FIXTURES / 'targets' / 'bbot_discovery.json').read_text(encoding='utf-8'))
PNG = base64.b64decode(json.loads((contract.FIXTURES / 'partials' / 'bbot_discovery.json').read_text(encoding='utf-8'))['screenshots'][0]['data'])


def event(etype, data, host='', **extra):
    return {'type': etype, 'data': data, 'host': host, 'scope_distance': 0, **extra}


class FakeClient:
    def __init__(self, answers=None, keys=None):
        self.calls, self.answers, self.keys = [], list(answers or []), keys

    def call(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, json.loads(json.dumps(body)) if body is not None else None))
        if path.endswith('/secret'):
            return {'bbot_config': self.keys, 'task_id': 7}
        if self.answers:
            answer = self.answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
        return {'accepted': True}

    def batches(self):
        return [body for _m, path, body in self.calls if path.endswith('/partial')]


class FakeProc:
    """A bbot that prints ``lines`` (JSON events) and exits with ``code``."""

    pid = 999999

    def __init__(self, lines, code=0, stderr=''):
        self.stdout = io.StringIO(''.join(json.dumps(line) + '\n' if isinstance(line, dict) else line for line in lines))
        self.stderr = io.StringIO(stderr)
        self.returncode, self._code = None, code

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = self._code
        return self._code


class PolicyTests(unittest.TestCase):
    def test_the_scope_keeps_the_target_and_drops_excluded_names_and_denied_ranges(self):
        policy = bbot.Policy(TARGET['scope'])
        self.assertEqual(policy.name('WWW.Example.com.'), 'www.example.com')
        for name in ('example.org', 'badexample.com', 'intranet.example.com', 'a.intranet.example.com', 'old.example.com', '../x'):
            self.assertIsNone(policy.name(name), name)
        self.assertEqual(policy.name('a.old.example.com'), 'a.old.example.com')  # only the name itself was excluded
        self.assertIsNone(policy.address('10.20.1.1'))
        self.assertEqual(policy.address('2001:0db8::1'), '2001:db8::1')
        self.assertIsNone(policy.url('https://u:p@www.example.com/'))
        self.assertIsNone(bbot.Policy({**TARGET['scope'], 'exact_host': True}).name('www.example.com'))

    def test_bbots_blacklist_holds_the_denied_ranges_every_exclusion_and_the_floor(self):
        external, internal = bbot.Policy(TARGET['scope']).blacklist(), bbot.Policy(TARGET['scope'], internal=True).blacklist()
        for entry in ('10.20.0.0/16', '198.51.100.7/32', 'intranet.example.com', 'old.example.com', '127.0.0.0/8', '169.254.0.0/16', 'localhost'):
            self.assertIn(entry, external)
        self.assertIn('192.168.0.0/16', external)
        self.assertNotIn('192.168.0.0/16', internal)  # private space only for an internal Sentinel

    def test_a_task_with_no_domain_in_scope_is_refused(self):
        with self.assertRaises(bbot.RunError):
            bbot.Policy({'in_scope_domains': ['../etc']})


class CommandTests(unittest.TestCase):
    def test_the_command_is_the_servers_mode_and_nothing_free_form(self):
        cmd = bbot.build_command(TARGET, '/w/scans', '/w/blacklist.txt', '/w/keys.yml')
        self.assertEqual(cmd[:8], [bbot.BBOT_BIN, '-t', 'example.com', '-p', 'subdomain-enum', 'web', 'web-screenshots', '/w/keys.yml'])
        for part in (['-em', 'trufflehog'], ['-rf', 'safe'], ['--force'], ['-b', '/w/blacklist.txt'], ['-o', '/w/scans'], ['--json', '-y', '--no-color']):
            self.assertTrue(any(cmd[i:i + len(part)] == part for i in range(len(cmd))), part)
        odd = {**TARGET, 'presets': ['subdomain-enum', '; rm -rf /'], 'exclude_modules': ['x y'], 'require_flags': ['aggressive'], 'force': 'yes',
               'trufflehog': True, 'strict_scope': True}
        cmd = bbot.build_command(odd, '/o', '/b')
        self.assertNotIn('; rm -rf /', cmd)
        self.assertNotIn('x y', cmd)
        self.assertNotIn('-rf', cmd)
        self.assertNotIn('--force', cmd)
        self.assertIn('--strict-scope', cmd)
        self.assertNotIn('trufflehog', cmd)  # the task allows it
        bounty = {**odd, 'scope': {**TARGET['scope'], 'bounty': True}}
        self.assertIn('trufflehog', bbot.build_command(bounty, '/o', '/b'))  # never for a bug bounty project, whatever the task says
        for bad in ('-x.example.com', '--help', 'localhost', '192.0.2.1', 'a b.example.com'):
            with self.assertRaises(bbot.RunError, msg=bad):
                bbot.build_command({**TARGET, 'domain': bad}, '/o', '/b')


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(self.dir, ignore_errors=True))

    def test_events_become_a_batch_in_contract_held_to_the_scope(self):
        os.makedirs(os.path.join(self.dir, 'demo_scan', 'gowitness'))
        with open(os.path.join(self.dir, 'demo_scan', 'gowitness', 'shot.png'), 'wb') as handle:
            handle.write(PNG)
        with open(os.path.join(self.dir, 'secret.png'), 'wb') as handle:
            handle.write(PNG)
        c = bbot.Collector(bbot.Policy(TARGET['scope']), self.dir)
        for e in (event('SCAN', {'name': 'demo_scan'}),
                  event('DNS_NAME', 'www.example.com', 'www.example.com', id='1', resolved_hosts=['192.0.2.10', '10.20.0.5']),
                  event('DNS_NAME', 'mail.example.org', 'mail.example.org'),
                  event('DNS_NAME', 'ns.example.com', 'ns.example.com', scope_distance=1),
                  event('OPEN_TCP_PORT', 'www.example.com:443', 'www.example.com', parent='1'),
                  event('URL', 'https://www.example.com/', 'www.example.com', tags=['status-200']),
                  event('TECHNOLOGY', {'host': 'www.example.com', 'technology': 'nginx'}, 'www.example.com'),
                  event('HTTP_RESPONSE', {'url': 'https://www.example.com/', 'status_code': 200, 'title': 'Hi', 'header': {'server': 'nginx'}}, 'www.example.com'),
                  event('FINDING', {'description': 'Possible takeover: x', 'host': 'www.example.com', 'severity': 'MEDIUM'}, 'www.example.com', module='baddns'),
                  event('WEBSCREENSHOT', {'path': 'gowitness/shot.png', 'url': 'https://www.example.com/'}, 'www.example.com'),
                  event('WEBSCREENSHOT', {'path': '../secret.png', 'url': 'https://www.example.com/'}, 'www.example.com')):
            c.add(e)
        batch = c.take(1)
        self.assertEqual(list(Draft202012Validator(contract.partial_schema('bbot_discovery')).iter_errors(batch)), [])
        self.assertEqual(batch['subdomains'], ['www.example.com'])
        self.assertEqual((batch['ips'], batch['resolutions']), (['192.0.2.10'], [{'name': 'www.example.com', 'ip': '192.0.2.10'}]))
        self.assertEqual(batch['ports'], [{'host': 'www.example.com', 'port': 443}])
        self.assertEqual(batch['urls'], [{'url': 'https://www.example.com/', 'status': 200}])
        self.assertEqual(batch['http'][0]['webserver'], 'nginx')
        self.assertEqual((batch['findings'][0]['name'], batch['findings'][0]['severity']), ('Possible takeover', 2))
        self.assertEqual(len(batch['screenshots']), 1)
        self.assertEqual(base64.b64decode(batch['screenshots'][0]['data']), PNG)
        self.assertEqual(batch['scan_name'], 'demo_scan')
        self.assertEqual(c.waiting(), 0)

    def test_a_list_over_its_cap_spills_into_the_next_batch(self):
        c = bbot.Collector(bbot.Policy(TARGET['scope']), self.dir)
        for i in range(bbot.LIMITS['subdomains'] + 5):
            c.add(event('DNS_NAME', f'h{i}.example.com', f'h{i}.example.com'))
        self.assertEqual(len(c.take(1)['subdomains']), bbot.LIMITS['subdomains'])
        self.assertEqual(len(c.take(2)['subdomains']), 5)

    def test_the_caps_equal_the_contracts(self):
        props = contract.load()['$defs']['partials']['bbot_discovery']['properties']
        self.assertEqual({k: props[k]['maxItems'] for k in bbot.LIMITS}, bbot.LIMITS)
        self.assertEqual(tuple(props['events']['items']['properties']['type']['enum']), bbot.INTERESTING)


class SenderTests(unittest.TestCase):
    def test_a_batch_is_retried_until_taken_and_a_409_stops_the_run(self):
        client = FakeClient([httpclient.ApiError(503, 'busy'), httpclient.ApiError(429, 'later')])
        sender = bbot.Sender(client, 7, sleep=lambda s: False)
        sender.send({'subdomains': []})
        self.assertEqual(sender.seq, 1)
        self.assertEqual([b['seq'] for b in client.batches()], [1, 1, 1])
        sender = bbot.Sender(FakeClient([httpclient.ApiError(409, 'stop')]), 7, sleep=lambda s: False)
        with self.assertRaises(bbot.Stopped):
            sender.send({})
        with self.assertRaises(bbot.RunError):
            bbot.Sender(FakeClient([httpclient.ApiError(400, 'bad')]), 7, sleep=lambda s: False).send({})


class RunTests(unittest.TestCase):
    LINES = [event('SCAN', {'name': 'demo_scan'}), event('DNS_NAME', 'www.example.com', 'www.example.com'),
             event('DNS_NAME', 'api.example.com', 'api.example.com')]

    def run_with(self, proc, client=None, target=None):
        client = client or FakeClient()
        seen = {}

        def popen(cmd, **kwargs):
            seen['cmd'] = cmd
            work = os.path.dirname(cmd[cmd.index('-b') + 1])
            with open(cmd[cmd.index('-b') + 1], encoding='utf-8') as handle:
                seen['blacklist'] = handle.read()
            seen['keys'] = None
            if os.path.exists(os.path.join(work, 'keys.yml')):
                with open(os.path.join(work, 'keys.yml'), encoding='utf-8') as handle:
                    seen['keys'] = handle.read()
            seen['work'] = work
            return proc
        with mock.patch.object(bbot, '_stop'):
            result = bbot.run_bbot_discovery(target or TARGET, client, 7, halted=threading.Event(), popen=popen)
        return result, client, seen

    def test_a_whole_run_posts_its_batches_and_closes_with_their_count(self):
        result, client, seen = self.run_with(FakeProc(self.LINES))
        self.assertEqual(client.batches()[0]['subdomains'], ['www.example.com', 'api.example.com'])
        self.assertEqual(result['partials'], len(client.batches()))
        self.assertEqual((result['outcome'], result['mode'], result['incomplete'], result['scan_name']), ('done', 'standard', '', 'demo_scan'))
        self.assertEqual(list(Draft202012Validator(contract.result_schema('bbot_discovery')).iter_errors(result)), [])
        self.assertIn('10.20.0.0/16', seen['blacklist'])
        self.assertIsNone(seen['keys'])
        self.assertFalse(os.path.exists(seen['work']))  # the private directory goes with the run

    def test_keys_are_read_once_and_reach_bbot_only_through_the_private_file(self):
        client = FakeClient(keys={'modules': {'shodan_dns': {'api_key': 'KEY-1234567'}}})
        stderr = 'Setup soft-failed for shodan_dns: Error with API (401) key KEY-1234567\n'
        result, client, seen = self.run_with(FakeProc(self.LINES, stderr=stderr), client=client, target={**TARGET, 'api_keys': True})
        self.assertEqual([p for _m, p, _b in client.calls if p.endswith('/secret')], ['sentinel/tasks/7/secret'])
        self.assertIn('KEY-1234567', seen['keys'])
        self.assertNotIn('KEY-1234567', json.dumps(seen['cmd']))
        self.assertEqual(result['problems'][0]['module'], 'shodan_dns')
        self.assertNotIn('KEY-1234567', json.dumps(result))

    def test_a_run_that_fails_part_way_is_incomplete_and_one_that_found_nothing_is_an_error(self):
        result, _client, _seen = self.run_with(FakeProc(self.LINES, code=-9))
        self.assertIn('memory', result['incomplete'])
        with self.assertRaises(bbot.RunError):
            self.run_with(FakeProc([], code=1, stderr='Traceback\nValueError: boom\n'))

    def test_a_stop_from_the_server_ends_the_run(self):
        client = FakeClient([httpclient.ApiError(409, 'the scan was stopped')])
        with self.assertRaises(bbot.Stopped):
            self.run_with(FakeProc(self.LINES), client=client)


if __name__ == '__main__':
    unittest.main()
