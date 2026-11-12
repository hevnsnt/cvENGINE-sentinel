"""bbot discovery as a streamed task (client/bbot.py): the command, the scope, the batches and how the run ends."""
import base64
import io
import ipaddress
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
        for entry in ('10.20.0.0/16', '198.51.100.7', 'intranet.example.com', 'old.example.com', '127.0.0.0/8', '169.254.0.0/16', 'localhost'):
            self.assertIn(entry, external)
        self.assertIn('192.168.0.0/16', external)
        self.assertNotIn('192.168.0.0/16', internal)  # private space only for an internal Sentinel

    def test_no_single_address_is_written_as_a_slash_32_or_slash_128(self):
        # bbot sorts its blacklist by (size, text); a one-address network has size 0, the same as the (0, 0) of the regex entry the kitchen-sink preset
        # adds, and the tie compares text with 0: ``TypeError: '<' not supported between instances of 'int' and 'str'`` before anything is scanned (a
        # deep discovery, which always runs kitchen-sink, died in under a second). Bare addresses sort as size -1.
        for internal in (False, True):
            for entry in bbot.Policy({**TARGET['scope'], 'deny_ranges': ['203.0.113.9/32', '2001:db8:1::5/128']}, internal=internal).blacklist():
                if '/' in entry:
                    net = ipaddress.ip_network(entry)
                    self.assertLess(net.prefixlen, net.max_prefixlen, entry)
        entries = bbot.Policy({'in_scope_domains': ['example.com'], 'deny_ranges': ['203.0.113.9/32']}).blacklist()
        for entry in ('::1', '::', '203.0.113.9'):
            self.assertIn(entry, entries)
        self.assertIn('fe80::/10', entries)  # a real range stays a range

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

    def test_a_wildcard_zone_adds_no_made_up_host_and_no_resolution(self):
        """bbot tags a name that only resolves through a wildcard with ``wildcard`` and can emit ``_wildcard.<parent>``. Neither is a host (review M5)."""
        c = bbot.Collector(bbot.Policy(TARGET['scope']), self.dir)
        for e in (event('DNS_NAME', 'www.example.com', 'www.example.com', resolved_hosts=['192.0.2.10']),
                  event('DNS_NAME', 'random-a1b2.example.com', 'random-a1b2.example.com', tags=['a-record', 'wildcard'], resolved_hosts=['192.0.2.55']),
                  event('DNS_NAME', '_wildcard.example.com', '_wildcard.example.com', resolved_hosts=['192.0.2.55']),
                  event('DNS_NAME', 'mail.example.com', 'mail.example.com', tags=['wildcard'], resolved_hosts=['192.0.2.55']),
                  event('DNS_NAME', 'example.com', 'example.com', tags=['wildcard-domain'])):  # the zone that has the wildcard is a real name
            c.add(e)
        batch = c.take(1)
        self.assertEqual(sorted(batch['subdomains']), ['example.com', 'www.example.com'])
        self.assertEqual(batch['resolutions'], [{'name': 'www.example.com', 'ip': '192.0.2.10'}])
        self.assertNotIn('192.0.2.55', batch['ips'])

    def test_an_ipv6_resolution_is_kept_in_its_canonical_form(self):
        """SN-5: a name's AAAA answer is a resolution like an A answer; an IPv6-only host is not left without an address. A denied one is still dropped."""
        c = bbot.Collector(bbot.Policy({**TARGET['scope'], 'deny_ranges': [*TARGET['scope']['deny_ranges'], 'fd00::/8']}), self.dir)
        c.add(event('DNS_NAME', 'www.example.com', 'www.example.com', resolved_hosts=['2001:0db8::1', '192.0.2.10', 'fd00::5', '::ffff:10.20.0.1']))
        c.add(event('DNS_NAME', 'v6.example.com', 'v6.example.com', resolved_hosts=['2001:db8::2']))
        batch = c.take(1)
        self.assertEqual(sorted(batch['ips']), ['192.0.2.10', '2001:db8::1', '2001:db8::2'])
        self.assertEqual(sorted((r['name'], r['ip']) for r in batch['resolutions']),
                         [('v6.example.com', '2001:db8::2'), ('www.example.com', '192.0.2.10'), ('www.example.com', '2001:db8::1')])
        self.assertEqual(list(Draft202012Validator(contract.partial_schema('bbot_discovery')).iter_errors(batch)), [])

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

    def test_the_builtin_scanners_proxy_reaches_bbot_only_through_the_private_file(self):
        with mock.patch.object(bbot.egress, 'for_tool', return_value=['http://user:pw-secret@proxy.example:3128']):
            result, _client, seen = self.run_with(FakeProc(self.LINES))
        self.assertEqual(json.loads(seen['keys'])['config']['web']['http_proxy'], 'http://user:pw-secret@proxy.example:3128')
        self.assertNotIn('pw-secret', json.dumps(seen['cmd']))
        with mock.patch.object(bbot.egress, 'for_tool', side_effect=bbot.egress.ProxyUnavailable('no proxy suits bbot')):
            with self.assertRaises(bbot.RunError):
                self.run_with(FakeProc(self.LINES))

    def test_a_run_that_fails_part_way_is_incomplete_and_one_that_found_nothing_is_an_error(self):
        result, _client, _seen = self.run_with(FakeProc(self.LINES, code=-9))
        self.assertIn('memory', result['incomplete'])
        with self.assertRaises(bbot.RunError):
            self.run_with(FakeProc([], code=1, stderr='Traceback\nValueError: boom\n'))

    def test_bbot_never_installs_dependencies_in_a_running_sentinel(self):
        # bbot keys its record of installed dependencies by hostname, so the one written at image build never matches in a container, and bbot then
        # wants root (sudo -K) to install again. The image installs them at build; the command must say not to look.
        self.assertIn('--no-deps', bbot.build_command(TARGET, '/o', '/b'))
        self.assertIn('--no-deps', bbot.build_command({**TARGET, 'presets': ['kitchen-sink'], 'require_flags': []}, '/o', '/b'))

    def test_a_bbot_that_cannot_start_for_want_of_root_says_so_in_plain_words(self):
        traceback = ('Traceback (most recent call last):\n  File "installer.py", line 437, in ensure_root\n'
                     "PermissionError: [Errno 13] Permission denied: 'sudo'\n")
        with self.assertRaises(bbot.RunError) as caught:
            self.run_with(FakeProc([], code=1, stderr=traceback))
        message = str(caught.exception)
        self.assertIn('bbot cannot start', message)
        self.assertIn('needs root', message)
        self.assertNotIn('Permission denied', message)
        self.assertLessEqual(len(message), 300)
        self.assertEqual(bbot.start_failure(['ValueError: boom']), '')

    def test_a_bbot_that_dies_at_start_names_the_exception_and_where_it_came_from(self):
        traceback = ('[INFO] Reading blacklist from file: /tmp/b.txt\n[ERRR] Unhandled exception: \'<\' not supported between instances of \'str\' and \'int\'\n'
                     '[CRIT] Unhandled exception: \'<\' not supported between instances of \'str\' and \'int\'\n[DBUG] Traceback (most recent call last):\n'
                     '  File "/opt/bbot-venv/lib/python3.14/site-packages/bbot/cli.py", line 429, in main\n'
                     '  File "/opt/bbot-venv/lib/python3.14/site-packages/bbot/scanner/target.py", line 117, in add\n'
                     "TypeError: '<' not supported between instances of 'str' and 'int'\n")
        with self.assertLogs('sentinel.bbot', 'ERROR') as logged, self.assertRaises(bbot.RunError) as caught:
            self.run_with(FakeProc([], code=1, stderr=traceback))
        message = str(caught.exception)
        self.assertIn("TypeError: '<' not supported", message)
        self.assertIn('bbot/scanner/target.py:117 in add', message)
        self.assertLessEqual(len(message), 300)
        self.assertIn('Reading blacklist from file', logged.output[0])  # the whole tail is in the log, not only its last line
        self.assertIn('[module paramminer_headers.handle_event]', bbot.crash_summary(['[ERRR] Error in paramminer_headers.handle_event', 'ValueError: x']))
        self.assertEqual(bbot.crash_summary(['just a log line']), '')

    def test_a_stop_from_the_server_ends_the_run(self):
        client = FakeClient([httpclient.ApiError(409, 'the scan was stopped')])
        with self.assertRaises(bbot.Stopped):
            self.run_with(FakeProc(self.LINES), client=client)

class KeyHandlingTests(unittest.TestCase):
    """A key value reaches bbot only through the 0600 file; it is in no batch, no result, no error, no log, and its directory is gone afterwards."""

    LINES = RunTests.LINES
    run_with = RunTests.run_with
    KEY = 'FAKE-KEY-0123456789abcdef'
    KEYS = {'modules': {'shodan_dns': {'api_key': KEY}, 'censys': {'api_id': 'FAKE-ID-aaaa1111', 'api_secret': 'FAKE-SECRET-bbbb2222'}}}

    def leaky_lines(self):
        k = self.KEY
        return [event('SCAN', {'name': 'demo_scan'}), event('DNS_NAME', 'www.example.com', 'www.example.com'),
                event('FINDING', {'description': f'shodan_dns said key={k} was bad', 'host': 'www.example.com', 'severity': 'LOW'}, 'www.example.com', module='shodan_dns'),
                event('TECHNOLOGY', {'technology': f'Thing {k}', 'host': 'www.example.com'}, 'www.example.com'),
                event('HTTP_RESPONSE', {'url': f'https://www.example.com/?apikey={k}', 'host': 'www.example.com', 'title': f'T {k}', 'status_code': 200},
                      'www.example.com')]

    def test_no_key_value_in_any_batch_or_result_or_error(self):
        client = FakeClient(keys=self.KEYS)
        stderr = f'Setup soft-failed for shodan_dns: 401 for key {self.KEY} and FAKE-SECRET-bbbb2222\n'
        with self.assertLogs('sentinel.bbot', 'ERROR') as logged:
            result, client, seen = self.run_with(FakeProc(self.leaky_lines(), code=1, stderr=stderr + f'ValueError: bad {self.KEY}\n'), client=client,
                                                 target={**TARGET, 'api_keys': True})
            logging_text = '\n'.join(logged.output)
        self.assertIn(self.KEY, seen['keys'])  # the file bbot reads has them
        wire = json.dumps(client.batches()) + json.dumps(result) + logging_text + json.dumps(seen['cmd'])
        for value in ('FAKE-KEY-0123456789abcdef', 'FAKE-ID-aaaa1111', 'FAKE-SECRET-bbbb2222'):
            self.assertNotIn(value, wire)
        self.assertTrue(client.batches())
        self.assertIn('***', json.dumps(client.batches()))  # masked, not dropped

    def test_a_run_error_message_carries_no_key(self):
        client = FakeClient(keys=self.KEYS)
        with self.assertRaises(bbot.RunError) as caught:
            self.run_with(FakeProc([], code=1, stderr=f'ValueError: refused for {self.KEY}\n'), client=client, target={**TARGET, 'api_keys': True})
        self.assertNotIn(self.KEY, str(caught.exception))

    def test_the_key_file_is_private_and_the_directory_is_removed_on_every_path(self):
        modes = {}

        def popen(cmd, **kwargs):
            work = os.path.dirname(cmd[cmd.index('-b') + 1])
            modes['dir'], modes['file'] = os.stat(work).st_mode & 0o777, os.stat(os.path.join(work, 'keys.yml')).st_mode & 0o777
            modes['work'] = work
            return FakeProc(self.leaky_lines())
        with mock.patch.object(bbot, '_stop'):
            bbot.run_bbot_discovery({**TARGET, 'api_keys': True}, FakeClient(keys=self.KEYS), 7, halted=threading.Event(), popen=popen)
        self.assertEqual((modes['dir'], modes['file']), (0o700, 0o600))
        self.assertFalse(os.path.exists(modes['work']))
        # a crash inside the run (the server stopped the task) removes it too
        modes.clear()

        def popen2(cmd, **kwargs):
            modes['work'] = os.path.dirname(cmd[cmd.index('-b') + 1])
            return FakeProc(self.leaky_lines())
        with mock.patch.object(bbot, '_stop'), self.assertRaises(bbot.Stopped):
            bbot.run_bbot_discovery({**TARGET, 'api_keys': True}, FakeClient([httpclient.ApiError(409, 'stopped')], keys=self.KEYS), 7,
                                    halted=threading.Event(), popen=popen2)
        self.assertFalse(os.path.exists(modes['work']))

    def test_the_secret_is_read_once_and_a_task_without_the_flag_reads_none(self):
        client = FakeClient(keys=self.KEYS)
        self.run_with(FakeProc(self.LINES), client=client, target=TARGET)
        self.assertEqual([p for _m, p, _b in client.calls if p.endswith('/secret')], [])

    def test_an_unreadable_secret_runs_without_keys(self):
        client = FakeClient(keys=None)
        result, _c, seen = self.run_with(FakeProc(self.LINES), client=client, target={**TARGET, 'api_keys': True})
        self.assertIsNone(seen['keys'])
        self.assertEqual(result['outcome'], 'done')

    def test_scrub_masks_nested_text_and_leaves_image_data_alone(self):
        body = {'a': [{'b': f'x {self.KEY} y'}], 'screenshots': [{'content_type': 'image/png', 'data': 'AAAA' + self.KEY[:8], 'filename': self.KEY + '.png'}], 'n': 3}
        out = bbot.scrub(body, bbot.secrets_of(self.KEYS))
        self.assertNotIn(self.KEY, json.dumps(out))
        self.assertEqual(out['screenshots'][0]['data'], 'AAAA' + self.KEY[:8])
        self.assertEqual(out['n'], 3)

    def test_stale_work_directories_are_swept_at_start(self):
        with tempfile.TemporaryDirectory() as root:
            stale = os.path.join(root, bbot.WORK_PREFIX + 'abc')
            os.mkdir(stale, 0o700)
            with open(os.path.join(stale, 'keys.yml'), 'w', encoding='utf-8') as handle:
                handle.write('FAKE-KEY')
            other = os.path.join(root, 'something-else')
            os.mkdir(other)
            link = os.path.join(root, bbot.WORK_PREFIX + 'link')
            os.symlink(other, link)
            plain = os.path.join(root, bbot.WORK_PREFIX + 'file')
            open(plain, 'w').close()
            self.assertEqual(bbot.sweep_stale(root), 1)
            self.assertFalse(os.path.exists(stale))
            self.assertTrue(os.path.isdir(other) and os.path.islink(link) and os.path.exists(plain))
            self.assertEqual(bbot.sweep_stale(os.path.join(root, 'missing')), 0)


if __name__ == '__main__':
    unittest.main()
