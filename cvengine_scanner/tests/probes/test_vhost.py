"""The vhost_probe kind (``probes.vhost``): the default response and each name asked at the address, the verdict rules, the pace and the policy."""
import unittest
from unittest import mock
from urllib.parse import urlsplit

from cvengine_scanner.probes import vhost

ADDRESS = '93.184.215.14'  # a public address the scanner's floor lets through (a documentation range is refused by it)
SCOPE = {'hosts': [ADDRESS, 'portal.example.com', 'app.example.com', 'wiki.example.com', 'files.example.com'], 'domains': [], 'excluded': [],
         'excluded_trees': [], 'private': False, 'addresses': [], 'blocked': []}


def answer(status=200, title='', length=100, location='', server='nginx/1.25.3', challenge_body='', powered_by=''):
    headers = {k: v for k, v in (('server', server), ('x-powered-by', powered_by)) if v}
    return {'url': 'https://x/', 'status': status, 'title': title, 'body': challenge_body or '<html>' + 'x' * max(0, length - 13), 'bytes': length,
            'location': location, 'server': server, 'powered_by': powered_by, 'content_type': 'text/html', 'headers': headers, 'raw_headers': headers}


DEFAULT = dict(status=200, title='Welcome to nginx!', length=615)
PORTAL = dict(status=200, title='Portal login', length=4200, powered_by='PHP/8.1.2')
WIKI = dict(status=200, title='Wiki', length=3000)


class Network:
    """A fake network keyed by (host, connect_ip). A key that is not there raises OSError. Every request is recorded."""

    def __init__(self, table):
        self.table, self.calls = table, []

    def __call__(self, url, policy, max_bytes=None, connect_ip=None, **kw):
        host = urlsplit(url).hostname
        self.calls.append((host, connect_ip, max_bytes))
        policy.check_host(host)
        if host[0].isdigit() or ':' in host:
            policy.check_address(host, literal=True)  # what the real transport asks of an address it is given
        if connect_ip:
            policy.check_address(connect_ip, literal=True)
        policy.touch(host)
        key = (host, connect_ip)
        if key not in self.table:
            raise OSError('unreachable')
        value = self.table[key]
        if isinstance(value, Exception):
            raise value
        return value


def task(names=('portal.example.com',), own=None, scope=None, gap=0.2, address=ADDRESS):
    return {'addresses': [{'id': address, 'address': address, 'scheme': 'https', 'port': 443,
                           'names': [{'name': n, **({'own': own[n]} if own and n in own else {})} for n in names]}],
            'gap': gap, 'scope': scope or SCOPE}


def run(target, table, **kw):
    net = Network(table)
    kw.setdefault('sleep', lambda s: None)
    return vhost.run_batch(target, probe=net, **kw), net


class VerdictTests(unittest.TestCase):
    def fp(self, *args, **kw):
        return vhost.fingerprint_of(answer(*args, **kw))

    def test_an_address_that_ignores_the_name_serves_its_default_site(self):
        self.assertEqual(vhost.classify(self.fp(**DEFAULT), self.fp(**DEFAULT), None), 'default_site')
        self.assertEqual(vhost.classify(self.fp(**{**DEFAULT, 'length': 640}), self.fp(**DEFAULT), None), 'default_site')

    def test_another_title_or_a_much_longer_page_is_another_application(self):
        default = self.fp(**DEFAULT)
        self.assertEqual(vhost.classify(self.fp(**PORTAL), default, None), 'distinct')
        self.assertEqual(vhost.classify(self.fp(**{**DEFAULT, 'length': 9000}), default, None), 'distinct')

    def test_the_name_s_own_site_served_here_is_the_same_app(self):
        self.assertEqual(vhost.classify(self.fp(**WIKI), self.fp(**DEFAULT), self.fp(**{**WIKI, 'length': 3010})), 'same_app')

    def test_no_site_here_is_no_answer_and_a_protected_site_is_a_site(self):
        self.assertEqual(vhost.classify(self.fp(404, 'Not Found', 150), self.fp(**DEFAULT), None), 'no_answer')
        self.assertEqual(vhost.classify(self.fp(401, 'Sign in', 200), self.fp(**DEFAULT), None), 'distinct')

    def test_redirects_are_compared_by_where_they_lead_not_by_host(self):
        a = self.fp(302, location='https://203.0.113.10/login')
        b = self.fp(302, location='https://portal.example.com/login')
        c = self.fp(302, location='https://portal.example.com/other')
        self.assertTrue(vhost.similar(a, b))
        self.assertFalse(vhost.similar(a, c))

    def test_a_fingerprint_is_five_facts_never_the_body(self):
        fp = self.fp(**PORTAL)
        self.assertEqual(sorted(fp), ['length', 'location', 'server', 'status', 'title'])
        self.assertEqual(fp['length'], 4200)


class RunTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.table = {(ADDRESS, None): answer(**DEFAULT),
                      ('portal.example.com', ADDRESS): answer(**PORTAL),
                      ('app.example.com', ADDRESS): answer(**DEFAULT),
                      ('files.example.com', ADDRESS): answer(404, 'Not Found', 150),
                      ('wiki.example.com', ADDRESS): answer(**WIKI)}

    def test_the_default_response_then_each_name_with_the_name_as_the_host_at_the_address(self):
        got, net = run(task(('portal.example.com', 'app.example.com')), self.table)
        self.assertEqual([(h, ip) for h, ip, _ in net.calls], [(ADDRESS, None), ('portal.example.com', ADDRESS), ('portal.example.com', None),
                                                              ('app.example.com', ADDRESS)])  # the portal differs from the default: its own site is asked too
        self.assertEqual({max_bytes for _h, _ip, max_bytes in net.calls}, {64 * 1024})
        report = got['addresses'][0]
        self.assertEqual(report['id'], ADDRESS)
        self.assertEqual(report['default'], {'state': 'answered', 'fingerprint': vhost.fingerprint_of(answer(**DEFAULT))})
        self.assertEqual([n['name'] for n in report['names']], ['portal.example.com', 'app.example.com'])
        self.assertEqual(got['refused'], [])
        self.assertIn('portal.example.com', got['touched'])

    def test_only_a_distinct_name_sends_its_page_back(self):
        got, _net = run(task(('portal.example.com', 'app.example.com')), self.table)
        portal, app = got['addresses'][0]['names']
        self.assertEqual(portal['page']['title'], 'Portal login')
        self.assertEqual(portal['page']['powered_by'], 'PHP/8.1.2')
        self.assertEqual(portal['page']['headers'], {'server': 'nginx/1.25.3', 'x-powered-by': 'PHP/8.1.2'})
        self.assertNotIn('page', app)
        self.assertNotIn('own', app)

    def test_the_stored_own_site_is_used_and_not_asked_again(self):
        own = {'wiki.example.com': {'status': 200, 'title': 'Wiki', 'length': 3010, 'location': '', 'server': ''}}
        got, net = run(task(('wiki.example.com',), own=own), self.table)
        self.assertEqual(net.calls, [(ADDRESS, None, 65536), ('wiki.example.com', ADDRESS, 65536)])
        row = got['addresses'][0]['names'][0]
        self.assertNotIn('own', row)
        self.assertNotIn('page', row)  # the same application it serves elsewhere: nothing distinct to read

    def test_without_a_stored_own_site_the_name_is_asked_once_at_its_own_address(self):
        self.table[('wiki.example.com', None)] = answer(**WIKI)
        got, net = run(task(('wiki.example.com',)), self.table)
        self.assertEqual(net.calls.count(('wiki.example.com', None, 65536)), 1)
        row = got['addresses'][0]['names'][0]
        self.assertEqual(row['own']['title'], 'Wiki')
        self.assertNotIn('page', row)

    def test_an_own_site_that_does_not_answer_is_reported_as_none(self):
        got, _net = run(task(('wiki.example.com',)), self.table)
        row = got['addresses'][0]['names'][0]
        self.assertIsNone(row['own'])
        self.assertIn('page', row)  # no own site to match: another application

    def test_a_name_with_no_site_is_no_answer_and_an_unreachable_one_too(self):
        del self.table[('portal.example.com', ADDRESS)]
        got, _net = run(task(('portal.example.com', 'files.example.com')), self.table)
        rows = got['addresses'][0]['names']
        self.assertEqual(rows[0], {'name': 'portal.example.com', 'state': 'no_answer'})
        self.assertEqual((rows[1]['state'], rows[1]['fingerprint']['status']), ('answered', 404))

    def test_an_address_that_does_not_answer_its_default_asks_no_name(self):
        del self.table[(ADDRESS, None)]
        got, net = run(task(), self.table)
        self.assertEqual(got['addresses'][0], {'id': ADDRESS, 'default': {'state': 'no_answer'}, 'names': []})
        self.assertEqual(len(net.calls), 1)

    def test_a_challenge_ends_the_address_and_is_never_retried(self):
        self.table[('portal.example.com', ADDRESS)] = answer(403, '', 100, server='cloudflare', challenge_body='<html>Just a moment... cloudflare _cf_chl_opt</html>')
        got, net = run(task(('portal.example.com', 'app.example.com')), self.table)
        rows = got['addresses'][0]['names']
        self.assertEqual([(r['name'], r['state'], r.get('challenge')) for r in rows], [('portal.example.com', 'challenged', 'Cloudflare')])
        self.assertEqual(len(net.calls), 2)

    def test_a_challenged_default_asks_no_name(self):
        self.table[(ADDRESS, None)] = answer(403, '', 100, server='cloudflare', challenge_body='<html>cf-browser-verification</html>')
        got, net = run(task(), self.table)
        self.assertEqual((got['addresses'][0]['default']['state'], got['addresses'][0]['names']), ('challenged', []))
        self.assertEqual(len(net.calls), 1)

    def test_a_busy_server_is_not_a_result_and_ends_the_address(self):
        self.table[('portal.example.com', ADDRESS)] = answer(503, 'Busy', 50, server='')
        got, net = run(task(('portal.example.com', 'app.example.com')), self.table)
        self.assertEqual([(r['name'], r['state']) for r in got['addresses'][0]['names']], [('portal.example.com', 'busy')])
        self.assertEqual(len(net.calls), 2)

    def test_a_name_the_policy_refuses_is_not_asked_and_not_reported(self):
        scope = {**SCOPE, 'hosts': [ADDRESS, 'app.example.com'], 'excluded': ['app.example.com']}
        got, net = run(task(('portal.example.com', 'app.example.com'), scope=scope), self.table)
        self.assertEqual(got['addresses'][0]['names'], [])
        self.assertEqual([h for h, _ip, _m in net.calls], [ADDRESS, 'portal.example.com', 'app.example.com'])  # the fake records before it judges
        self.assertEqual(sorted(got['refused']), ['app.example.com', 'portal.example.com'])

    def test_an_address_outside_the_policy_is_not_reported_at_all(self):
        scope = {**SCOPE, 'hosts': ['portal.example.com']}
        got, _net = run(task(), self.table, **{})
        self.assertEqual(len(got['addresses']), 1)
        got, _net = run(task(scope=scope), self.table)
        self.assertEqual(got['addresses'], [])
        self.assertIn(ADDRESS, got['refused'])

    def test_a_private_address_is_refused_whatever_the_task_says(self):
        scope = {**SCOPE, 'hosts': ['10.1.2.3', 'portal.example.com']}
        got, net = run(task(address='10.1.2.3', scope=scope), self.table)
        self.assertEqual(got['addresses'], [])
        self.assertEqual(net.calls[0][0], '10.1.2.3')

    def test_requests_wait_the_gap_of_the_task(self):
        sleeps, clock = [], iter(range(0, 1000))
        own = {'portal.example.com': {'status': 200, 'title': 'Other', 'length': 10, 'location': '', 'server': ''}}
        run(task(('portal.example.com', 'app.example.com'), gap=2.0, own=own), self.table, sleep=sleeps.append, clock=lambda: next(clock) * 0.01)
        self.assertEqual(len(sleeps), 2)
        self.assertTrue(all(1.9 < s <= 2.0 for s in sleeps))

    def test_the_gap_is_clamped(self):
        self.assertEqual((vhost.clamp_gap(0), vhost.clamp_gap(1000), vhost.clamp_gap(2), vhost.clamp_gap('x')), (0.2, 60.0, 2.0, 60.0))

    def test_malformed_tasks_are_refused(self):
        for bad in ({}, {'addresses': []}, {'addresses': [{'id': 'a'}]},
                    {'addresses': [{'id': 'a', 'address': 'not-an-ip', 'scheme': 'https', 'port': 443, 'names': [{'name': 'x.example.com'}]}]},
                    {'addresses': [{'id': 'a', 'address': ADDRESS, 'scheme': 'ftp', 'port': 443, 'names': [{'name': 'x.example.com'}]}]},
                    {'addresses': [{'id': 'a', 'address': ADDRESS, 'scheme': 'https', 'port': 0, 'names': [{'name': 'x.example.com'}]}]},
                    {'addresses': [{'id': 'a', 'address': ADDRESS, 'scheme': 'https', 'port': 443, 'names': [{'name': 'bad name'}]}]},
                    {'addresses': [{'id': 'a', 'address': ADDRESS, 'scheme': 'https', 'port': 443, 'names': [{'name': 'x.example.com', 'own': {'status': 'x'}}]}]},
                    {'addresses': [task()['addresses'][0]] * 11}):
            with self.subTest(bad=str(bad)[:60]):
                with self.assertRaises(ValueError):
                    vhost.run_batch({**bad, 'scope': SCOPE, 'gap': 1}, probe=Network(self.table))

    def test_an_ipv6_address_is_asked_as_itself(self):
        net = Network({('2606:2800:21f:cb07:6820:80da:af6b:8b2c', None): answer(**DEFAULT)})
        scope = {**SCOPE, 'hosts': ['2606:2800:21f:cb07:6820:80da:af6b:8b2c', 'portal.example.com']}
        vhost.run_batch(task(address='2606:2800:21f:cb07:6820:80da:af6b:8b2c', scope=scope), probe=net, sleep=lambda s: None)
        self.assertEqual(net.calls[0][0], '2606:2800:21f:cb07:6820:80da:af6b:8b2c')


class ContractShapeTests(unittest.TestCase):
    def test_a_result_validates_against_the_contract(self):
        from jsonschema import Draft202012Validator

        from cvengine_scanner import contract
        table = {(ADDRESS, None): answer(**DEFAULT), ('portal.example.com', ADDRESS): answer(**PORTAL), ('gone.example.com', ADDRESS): answer(404, 'x', 10)}
        with mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset()):
            got, _net = run(task(('portal.example.com', 'gone.example.com'), scope={**SCOPE, 'hosts': [*SCOPE['hosts'], 'gone.example.com']}), table)
        got = {'outcome': 'done', **got}
        schema = contract.result_schema('vhost_probe')
        self.assertEqual(sorted(Draft202012Validator(schema).iter_errors(got), key=str), [])
        target = task(('portal.example.com',))
        self.assertEqual(sorted(Draft202012Validator(contract.target_schema('vhost_probe')).iter_errors(target), key=str), [])


if __name__ == '__main__':
    unittest.main()
