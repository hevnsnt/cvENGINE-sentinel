"""Every tool kind refuses a denied address before it connects (``scope`` deny list: ``CVENGINE_SENTINEL_DENY_RANGES`` and the task's own).

For each kind in ``tools.RUNNERS`` one case calls the runner the way the daemon does, twice:

* as a control, with no deny list: the case must reach a connection or a process (so the case really is aimed at the network, and the recorder
  below really sees it);
* with the whole address space denied: nothing may connect, send or start. The addresses the case names are public ones, so nothing but the deny list can
  be what stops it.

A kind added to ``RUNNERS`` with no case here fails ``RegistryTests`` until someone writes one, so a new wrapper cannot skip the check."""
import json
import os
import socket
import tempfile
import unittest
from unittest import mock

from client import bbot, config, daemon, rdp, scope, tools
from cvengine_scanner import contract

PUBLIC = '93.184.215.14'
NAMES = {'www.example.com': [PUBLIC], 'api.example.com': [PUBLIC], 'mail.example.com': [PUBLIC], 'static.example.com': [PUBLIC],
         'old.example.com': [PUBLIC], 'gone.example.com': [PUBLIC], 'slow.example.com': [PUBLIC], 'example.com': [PUBLIC],
         'cdnjs.cloudflare.com': [PUBLIC], 'www.example.test': [PUBLIC]}
EVERYTHING = '0.0.0.0/0,::/0'


def fake_getaddrinfo(name, port=None, *args, **kwargs):
    if name in NAMES:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, port or 0)) for a in NAMES[name]]
    try:
        socket.inet_pton(socket.AF_INET, name)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (name, port or 0))]
    except OSError:
        raise socket.gaierror('no such host') from None


class Attempt(OSError):
    """What the recorder raises instead of connecting."""


class Recorder:
    """Everything that would have touched the network: a process started, a socket connected or written to, an HTTP request made, a name looked up.
    Each entry is ``(what, destination)``. A name lookup and a datagram to this machine's own resolver are not contact with a target: they are
    recorded (so a control can see a case run) but ignored in the verdict (``contact``)."""
    RESOLVER = '127.0.0.53'  # systemd-resolved's stub, and the one this test always allowed; a runner that is not set up that way names others (``resolvers``)

    def __init__(self):
        self.attempts = []

    def note(self, what, dest=None):
        self.attempts.append((what, dest))

    @property
    def contact(self):
        own = resolvers()
        return [(w, d) for w, d in self.attempts if w != 'resolve' and not (w == 'sendto' and (d is None or d in own))]

    def stop(self, what):
        def refuse(*args, **kwargs):
            self.note(what, _destination(what, args))
            raise Attempt(f'recorded, not sent: {what}')
        return refuse


def resolvers():
    """The addresses this machine sends its name lookups to: the stub every Linux with systemd-resolved has, and whatever /etc/resolv.conf names. A CI runner image
    names others (an Azure resolver, a loopback address of its own) and which one it has changes from one runner to the next, so a datagram to any of them is the
    machine's own lookup (the probes that read TXT records use dnspython, which sends it), never contact with a target. The test used to allow only 127.0.0.53,
    and failed on the runners that name another."""
    found = {Recorder.RESOLVER}
    try:
        with open('/etc/resolv.conf', encoding='utf-8') as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == 'nameserver':
                    found.add(parts[1].split('%')[0])
    except OSError:
        pass
    return found


def _destination(what, args):
    """The host of what a recorded call was about, when it can be told."""
    for arg in reversed(args):
        if isinstance(arg, tuple) and arg and isinstance(arg[0], str):
            return arg[0]
        if what == 'http' and hasattr(arg, 'url'):
            from urllib.parse import urlsplit
            return urlsplit(arg.url).hostname
    return None


def recording(rec):
    """Patches that record (and refuse) every way out of this process."""
    import requests.adapters

    def lookup(name, *args, **kwargs):
        rec.note('resolve', name)
        return fake_getaddrinfo(name, *args, **kwargs)
    patches = [mock.patch('subprocess.Popen', side_effect=rec.stop('process')),
               mock.patch('socket.create_connection', side_effect=rec.stop('create_connection')),
               mock.patch.object(socket.socket, 'connect', rec.stop('connect')),
               mock.patch.object(socket.socket, 'connect_ex', rec.stop('connect_ex')),
               mock.patch.object(socket.socket, 'sendto', rec.stop('sendto')),
               mock.patch.object(requests.adapters.HTTPAdapter, 'send', rec.stop('http')),
               mock.patch('socket.getaddrinfo', side_effect=lookup),
               mock.patch.object(scope, 'own_addresses', return_value=frozenset()),
               mock.patch.object(scope, 'ALWAYS_DENIED', ()),  # the documentation addresses of the fixtures are the floor's business, not this test's
               mock.patch.object(scope, 'internal_allowed', return_value=True),
               mock.patch.object(config, '_local_internal', return_value=True),
               mock.patch.object(config, 'builtin', return_value=True),
               mock.patch.object(tools, 'sshamble_ready', return_value=True),
               mock.patch.object(tools, 'badkeys_ready', return_value=False),
               mock.patch.object(rdp, 'available', return_value=True),
               mock.patch.object(rdp, 'capture', side_effect=rec.stop('rdp')),
               mock.patch.object(tools.time, 'sleep')]
    return patches


def fixture(kind):
    path = contract.FIXTURES / 'targets' / f'{kind}.json'
    return json.loads(path.read_text(encoding='utf-8'))


PAGE_READ = {'reads': [{'id': '1', 'op': 'head', 'host': 'www.example.com', 'url': 'https://www.example.com/'}],
             'scope': {'hosts': ['www.example.com'], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False, 'addresses': [], 'blocked': []}}
TEMPLATE = fixture('nuclei_validate')['template']
SIGNED_TARGET = {'hosts': [{'host': 'www.example.com', 'urls': ['https://www.example.com/', 'https://www.example.com/account']}], 'scope': PAGE_READ['scope']}


def SIGN_IN():
    from cvengine_scanner.probes import routes_signed
    return routes_signed.SignIn.parse({'headers': [['Authorization', 'Bearer lab-token-0000']], 'target': 'example.com', 'host': 'www.example.com',
                                       'origins': ['https:443'], 'host_scoped': False, 'allow_untrusted_certificate': False, 'expires_at': None})


def screenshot_connection(target):
    """What the screenshot browser can reach: it connects nowhere itself, only through the vetting proxy, whose two steps (``shot.Guard.admit`` and
    ``transport.open_socket``) are exactly the ones ``shot.run`` wires in. The browser process itself is not a way out."""
    from client import shot
    from cvengine_scanner.probes import transport
    job = shot.lib.parse_target(target)
    for page in job.pages:
        addresses, why = shot.Guard(job.policy, page.host).admit(page.host, 443)
        if addresses:
            transport.open_socket(addresses, 5, job.policy, host=page.host)


def run_nuclei_set(kind):
    return lambda: tools.RUNNERS[kind](['https://www.example.com/', 'www.example.com'], tags=['cve'], severities=['high'])


# One case per kind: a call the way the daemon makes it (daemon._execute), aimed at a public name or address.
CASES = {
    'nmap': lambda: tools.RUNNERS['nmap'](['www.example.com', PUBLIC]),
    'naabu': lambda: tools.RUNNERS['naabu'](['www.example.com', PUBLIC]),
    'nuclei_light': run_nuclei_set('nuclei_light'),
    'nuclei_targeted': run_nuclei_set('nuclei_targeted'),
    'nuclei_deep': run_nuclei_set('nuclei_deep'),
    'testssl': lambda: tools.RUNNERS['testssl']('www.example.com', PUBLIC, 443),
    'nmap_udp': lambda: tools.RUNNERS['nmap_udp'](PUBLIC),
    'wpscan': lambda: tools.RUNNERS['wpscan']('https://www.example.com/'),
    'wpscan_thorough': lambda: tools.RUNNERS['wpscan_thorough']('https://www.example.com/', '', 600),
    'openvas': lambda: tools.RUNNERS['openvas']({PUBLIC: 'www.example.com'}, [], 1, preferences={}),
    'discover': lambda: tools.RUNNERS['discover']('10.0.0.0/28'),
    'waf': lambda: tools.RUNNERS['waf']('www.example.com', PUBLIC, 443, 'https'),
    'nmap_full': lambda: tools.RUNNERS['nmap_full'](PUBLIC),
    'nmap_verify': lambda: tools.RUNNERS['nmap_verify'](PUBLIC, [80, 443]),
    'node2shell': lambda: tools.RUNNERS['node2shell']('https://www.example.com/'),
    'rdp_shot': lambda: tools.RUNNERS['rdp_shot'](PUBLIC, 3389),
    'db_probe': lambda: tools.RUNNERS['db_probe'](PUBLIC, 6379, 'redis'),
    'path_probe': lambda: tools.RUNNERS['path_probe']([{'ip': PUBLIC, 'port': 81}], pause=0),
    'nuclei_validate': lambda: tools.RUNNERS['nuclei_validate']('test', TEMPLATE, ['https://www.example.com/']),
    # the in-process probes take the whole target, scope policy included
    'http_probe': lambda: tools.RUNNERS['http_probe'](fixture('http_probe')),
    'dns_resolve': lambda: tools.RUNNERS['dns_resolve'](fixture('dns_resolve')),
    'alive_check': lambda: tools.RUNNERS['alive_check'](fixture('alive_check')),
    'bucket_check': lambda: tools.RUNNERS['bucket_check'](fixture('bucket_check')),
    'vhost_probe': lambda: tools.RUNNERS['vhost_probe'](fixture('vhost_probe')),
    'subdir_probe': lambda: tools.RUNNERS['subdir_probe'](fixture('subdir_probe')),
    'route_probe': lambda: tools.RUNNERS['route_probe'](fixture('route_probe')),
    'route_probe_signed': lambda: tools.RUNNERS['route_probe_signed'](SIGNED_TARGET, SIGN_IN()),
    'supplier_check': lambda: tools.RUNNERS['supplier_check'](fixture('supplier_check')),
    'hygiene_check': lambda: tools.RUNNERS['hygiene_check'](fixture('hygiene_check')),
    'dangling_dns_check': lambda: tools.RUNNERS['dangling_dns_check'](fixture('dangling_dns_check')),
    'identity_check': lambda: tools.RUNNERS['identity_check'](fixture('identity_check')),
    'page_read': lambda: tools.RUNNERS['page_read'](PAGE_READ),
    'web_screenshot': lambda: screenshot_connection(fixture('web_screenshot')),
    'ssh_probe': lambda: tools.RUNNERS['ssh_probe'](fixture('ssh_probe')),
    'secrets_scan': lambda: tools.RUNNERS['secrets_scan'](fixture('secrets_scan')),
}
# bbot is not a connection of this process: it is a program that connects by itself, held by the blacklist it is started with (BbotTests below).
BBOT = {'bbot_discovery'}


def attempts_of(kind, deny):
    """What the case of ``kind`` tried to reach with ``deny`` as the operator's list ('' is none). Whatever the runner raises is its own business."""
    rec = Recorder()
    env = {'CVENGINE_SENTINEL_DENY_RANGES': deny} if deny else {}
    patches = recording(rec)
    with mock.patch.dict(os.environ, env, clear=False):
        if not deny:
            os.environ.pop('CVENGINE_SENTINEL_DENY_RANGES', None)
        for patcher in patches:
            patcher.start()
        try:
            try:
                CASES[kind]()
            except BaseException as exc:  # noqa: BLE001 - a refusal, a recorded attempt, a tool that cannot run here: the recorder is the verdict
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
        finally:
            for patcher in reversed(patches):
                patcher.stop()
    return rec


class RegistryTests(unittest.TestCase):
    def test_every_kind_in_the_registry_has_a_deny_case(self):
        missing = sorted(set(tools.RUNNERS) - set(CASES) - BBOT)
        self.assertEqual(missing, [], f'a new tool kind needs a case in CASES that proves it refuses a denied address before it connects: {missing}')

    def test_no_case_is_left_for_a_kind_that_is_gone(self):
        self.assertEqual(sorted(set(CASES) - set(tools.RUNNERS)), [])

    def test_every_kind_the_daemon_can_dispatch_is_in_the_registry(self):
        listed = set(contract.load()['kind_since'])
        self.assertEqual(sorted(listed - set(tools.RUNNERS) - {'ssh_probe'}), [])


class EveryKindRefusesTests(unittest.TestCase):
    pass


def _make(kind):
    def test(self):
        control = attempts_of(kind, '')
        self.assertTrue(control.attempts, f'{kind}: the case never reached a connection, a lookup or a process even with nothing denied, so it proves nothing; fix the case')
        denied = attempts_of(kind, EVERYTHING)
        self.assertEqual(denied.contact, [], f'{kind} connected, sent or started something although every address was denied: {denied.contact}')
    return test


for _kind in sorted(CASES):
    setattr(EveryKindRefusesTests, f'test_{_kind}_refuses_before_it_connects', _make(_kind))


class RefusedNotFailedTests(unittest.TestCase):
    """A deny-list refusal is a ``Refused`` whose text starts ``refused:`` (the contract's outcomes are done and error, so the text carries it)."""

    def run_case(self, call, deny='93.184.215.0/24'):
        rec = Recorder()
        patches = recording(rec)
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DENY_RANGES': deny}):
            for patcher in patches:
                patcher.start()
            try:
                with self.assertRaises(tools.Refused) as raised:
                    call()
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
        self.assertEqual(rec.contact, [])
        self.assertTrue(str(raised.exception).startswith('refused: '), str(raised.exception))
        return raised.exception

    def test_the_address_tools_raise_refused(self):
        for name, call in {'nmap': lambda: tools.run_nmap([PUBLIC]), 'naabu': lambda: tools.run_naabu(['www.example.com']),
                           'nuclei': lambda: tools.run_nuclei(['https://www.example.com/']), 'nmap_full': lambda: tools.run_nmap_full(PUBLIC),
                           'testssl': lambda: tools.run_testssl('www.example.com', PUBLIC, 443), 'waf': lambda: tools.run_waf('www.example.com', PUBLIC, 80, 'http'),
                           'wpscan': lambda: tools.run_wpscan('https://www.example.com/'), 'node2shell': lambda: tools.run_node2shell('https://www.example.com/'),
                           'db_probe': lambda: tools.run_db_probe(PUBLIC, 6379, 'redis'), 'rdp_shot': lambda: tools.run_rdp_shot(PUBLIC, 3389),
                           'discover': lambda: tools.run_discover('10.0.0.0/28')}.items():
            with self.subTest(tool=name):
                with mock.patch.object(config, '_local_internal', return_value=True):
                    self.run_case(call, '93.184.215.0/24,10.0.0.0/24')

    def test_a_refused_task_is_reported_as_an_error_with_the_refusal_in_its_text(self):
        d = daemon.Daemon.__new__(daemon.Daemon)
        reported = []
        d._report_unless_dropped = lambda task_id, state, result: reported.append(result)
        d._lock = mock.MagicMock()
        d._in_flight, d._write_control = {}, lambda: None
        d._register_proc = lambda state: None
        d._execute = mock.Mock(side_effect=tools.Refused('refused: not a usable target'))
        state = {'runnable': True, 'done': mock.Mock(), 'started': 0}
        d._run_task({'id': 't1', 'kind': 'nmap'}, state)
        self.assertEqual(reported[0]['outcome'], 'error')
        self.assertTrue(reported[0]['error'].startswith('refused:'))


class OperatorListTests(unittest.TestCase):
    def test_the_environment_variable_is_read_at_every_call(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DENY_RANGES': '93.184.215.0/24'}):
            with self.assertRaises(scope.Denied):
                scope.check_ip(PUBLIC, internal=True)
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DENY_RANGES': ''}):
            self.assertEqual(scope.check_ip(PUBLIC, internal=True), PUBLIC)

    def test_unset_denies_nothing_extra(self):
        env = {k: v for k, v in os.environ.items() if k != 'CVENGINE_SENTINEL_DENY_RANGES'}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(config.deny_ranges(), ((), []))

    def test_several_networks_and_both_families(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DENY_RANGES': ' 93.184.215.0/24 , 2001:4860::/32,198.18.5.5 '}):
            nets, bad = config.deny_ranges()
            self.assertEqual((bad, sorted(str(n) for n in nets)), ([], ['198.18.5.5/32', '2001:4860::/32', '93.184.215.0/24']))
            for address in (PUBLIC, '2001:4860:4860::1', '198.18.5.5'):
                with self.assertRaises(scope.Denied, msg=address):
                    scope.check_ip(address, internal=True)

    def test_a_bad_entry_refuses_every_tool_and_never_starts_one(self):
        rec = Recorder()
        patches = recording(rec)
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DENY_RANGES': '93.184.216.0/24,garbage'}):
            for patcher in patches:
                patcher.start()
            try:
                with self.assertRaises(tools.Refused):
                    tools.run_nmap([PUBLIC])
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
        self.assertEqual(rec.contact, [])


class BbotTests(unittest.TestCase):
    """bbot connects by itself: it is held by the blacklist file it starts with, which carries the task's deny list and the operator's."""
    TARGET = fixture('bbot_discovery')

    def blacklist_of(self, env, target=None):
        seen = {}

        def popen(argv, **kwargs):
            seen['argv'] = argv
            with open(argv[argv.index('-b') + 1], encoding='utf-8') as handle:
                seen['blacklist'] = handle.read().split()
            raise Attempt('bbot not started in a unit test')
        client = mock.Mock()
        with mock.patch.dict(os.environ, env):
            if not env:
                os.environ.pop('CVENGINE_SENTINEL_DENY_RANGES', None)
            with self.assertRaises(Attempt):
                bbot.run_bbot_discovery(target or self.TARGET, client, 't1', internal=False, popen=popen)
        return seen['blacklist']

    def test_the_task_list_is_in_the_blacklist(self):
        listed = self.blacklist_of({})
        self.assertIn('10.20.0.0/16', listed)
        self.assertIn('198.51.100.7', listed)

    def test_the_operators_list_joins_it_when_the_server_sends_none(self):
        target = json.loads(json.dumps(self.TARGET))
        target['scope']['deny_ranges'] = []
        listed = self.blacklist_of({'CVENGINE_SENTINEL_DENY_RANGES': '93.184.216.0/24,2001:4860::/32,203.0.114.7'}, target)
        for entry in ('93.184.216.0/24', '2001:4860::/32', '203.0.114.7'):
            self.assertIn(entry, listed)

    def test_a_process_that_imports_only_bbot_still_holds_the_operators_list(self):
        """The first run of this fix missed it: bbot imported alone never loaded the client's configuration, so the list was never read."""
        import subprocess
        import sys
        code = ("from client import bbot\n"
                "p = bbot.Policy({'in_scope_domains': ['example.com'], 'exact_host': False, 'exclusions': [], 'deny_ranges': [], 'bounty': False})\n"
                "print(' '.join(p.blacklist()))")
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        out = subprocess.run([sys.executable, '-c', code], cwd=root, capture_output=True, text=True, check=True,
                             env={**os.environ, 'CVENGINE_SENTINEL_DENY_RANGES': '93.184.216.0/24'}).stdout.split()
        self.assertIn('93.184.216.0/24', out)

    def test_a_bad_operator_list_refuses_the_task_before_bbot_starts(self):
        popen = mock.Mock()
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DENY_RANGES': 'nonsense'}):
            with self.assertRaises(bbot.RunError) as raised:
                bbot.run_bbot_discovery(self.TARGET, mock.Mock(), 't1', popen=popen)
        popen.assert_not_called()
        self.assertTrue(str(raised.exception).startswith('refused: '))

    def test_what_bbot_reports_is_held_to_the_same_list(self):
        policy = bbot.Policy({**self.TARGET['scope'], 'deny_ranges': ['93.184.216.0/24', '2001:4860::/32']})
        for address in ('93.184.216.5', '2001:4860::1', '::ffff:93.184.216.5'):
            self.assertIsNone(policy.address(address), address)
        self.assertEqual(policy.address('8.8.8.8'), '8.8.8.8')
        self.assertIsNone(policy.url('http://93.184.216.5/x'))


class DiscoverTests(unittest.TestCase):
    def test_a_sweep_overlapping_a_denied_range_is_refused(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DENY_RANGES': '10.0.0.8/29'}), mock.patch.object(config, '_local_internal', return_value=True):
            with self.assertRaises(tools.Refused):
                tools.validate_cidr('10.0.0.0/24')
            self.assertEqual(tools.validate_cidr('10.0.1.0/24'), '10.0.1.0/24')


if __name__ == '__main__':
    unittest.main()
