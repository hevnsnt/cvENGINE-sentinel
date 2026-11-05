"""The scope policy a probe task carries (``policy.ScopePolicy``), and that every hop of the http_probe and dns_resolve kinds is held to it."""
import socket
import unittest
from unittest import mock

from cvengine_scanner.probes import dns, version_probes
from cvengine_scanner.probes.policy import ScopePolicy

PUBLIC = '93.184.215.14'


def page(status=200, body='', headers=None, url='', location=''):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return {'status': status, 'headers': headers, 'body': body, 'title': '', 'content_type': 'text/html', 'server': headers.get('server', ''),
            'powered_by': '', 'url': url, 'location': location}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_missing_or_malformed_policy_allows_nothing(self):
        for doc in (None, 'everything', [], {}, {'hosts': 'www.example.com'}):
            self.assertTrue(ScopePolicy(doc).host_refusal('www.example.com'), doc)

    def test_names_domains_and_exclusions(self):
        policy = ScopePolicy({'hosts': ['api.example.org', '93.184.215.14'], 'domains': ['example.com'], 'excluded': ['old.example.com'],
                              'excluded_trees': ['legacy.example.com']}, internal=False)
        for allowed in ('example.com', 'WWW.Example.com.', 'a.b.example.com', 'api.example.org', '93.184.215.14', '[93.184.215.14]'):
            self.assertEqual(policy.host_refusal(allowed), '', allowed)
        self.assertEqual(policy.host_refusal('old.example.com'), 'excluded')
        self.assertEqual(policy.host_refusal('legacy.example.com'), 'excluded')
        self.assertEqual(policy.host_refusal('x.legacy.example.com'), 'excluded')  # an excluded tree wins over the domain
        for refused in ('notexample.com', 'example.com.evil.test', 'www.example.org', '93.184.215.15', ''):
            self.assertEqual(policy.host_refusal(refused), 'no host' if not refused else 'outside the scope policy', refused)

    def test_a_domain_never_covers_an_address(self):
        self.assertTrue(ScopePolicy({'domains': ['14']}, internal=False).host_refusal('93.184.215.14'))

    def test_the_floor_is_always_applied_and_the_policy_only_narrows_it(self):
        everything = ScopePolicy({'domains': ['example.com'], 'private': True, 'addresses': ['127.0.0.1', '169.254.169.254']}, internal=True)
        for never in ('127.0.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1', '224.0.0.1', '0.0.0.0'):
            self.assertTrue(everything.address_refusal(never, literal=True), never)
        self.assertEqual(everything.address_refusal(PUBLIC), '')
        blocked = ScopePolicy({'domains': ['example.com'], 'blocked': ['93.184.0.0/16']}, internal=False)
        self.assertEqual(blocked.address_refusal(PUBLIC), 'a range the server never scans')

    def test_private_space_needs_this_machine_and_the_server(self):
        self.assertTrue(ScopePolicy({'private': True}, internal=False).address_refusal('10.0.0.5'))  # an external Sentinel: never
        self.assertTrue(ScopePolicy({}, internal=True).address_refusal('10.0.0.5'))  # the server did not allow it
        self.assertEqual(ScopePolicy({'private': True}, internal=True).address_refusal('10.0.0.5'), '')

    def test_an_authorised_device_address_only_as_itself(self):
        policy = ScopePolicy({'hosts': ['100.101.102.103'], 'addresses': ['100.101.102.103']}, internal=True)
        self.assertEqual(policy.address_refusal('100.101.102.103', literal=True), '')
        self.assertTrue(policy.address_refusal('100.101.102.103'))  # a name that resolved into the tailnet never is
        self.assertTrue(policy.address_refusal('100.101.102.104', literal=True))

    def test_what_was_touched_is_kept_once_each(self):
        policy = ScopePolicy({'domains': ['example.com']})
        for host in ('www.example.com', 'WWW.example.com.', 'cdn.example.com'):
            policy.touch(host)
        self.assertEqual(policy.touched, ['www.example.com', 'cdn.example.com'])


def run(table, scope, probes, **kw):
    """Run an http_probe task whose network is ``table`` (URL -> answer), recording every URL asked."""
    asked = []

    def probe(url, policy, **_kw):
        asked.append(url)
        policy.touch(url.split('://', 1)[1].split('/', 1)[0])  # the transport records what it connects to
        return table.get(url, page(404, body='not found', url=url))
    result = version_probes.run_batch({'scope': scope, 'probes': probes}, probe=probe, sleep=lambda s: None, **kw)
    return result, asked


HEADERS = {'id': 'h1', 'host': 'www.example.com', 'probe': 'headers-root', 'base': 'https://www.example.com', 'allowed': ['example.com']}


class HttpProbeBatchTests(unittest.TestCase):
    def test_a_probe_reads_its_host_and_reports_what_it_touched(self):
        table = {'https://www.example.com/': page(200, headers={'Server': 'nginx/1.24.0'}, url='https://www.example.com/')}
        result, asked = run(table, {'domains': ['example.com']}, [HEADERS])
        self.assertEqual(asked, ['https://www.example.com/'])
        self.assertEqual(result['touched'], ['www.example.com'])
        self.assertIn(('nginx', '1.24.0'), {(o['product'], o['version']) for o in result['probes'][0]['observations']})

    def test_a_redirect_outside_the_policy_is_not_followed(self):
        table = {'https://www.example.com/': page(301, url='https://www.example.com/', location='https://example.com/')}
        policy = {'domains': ['example.com'], 'excluded': ['example.com']}  # the apex is excluded; www is not
        result, asked = run(table, policy, [HEADERS])
        self.assertEqual(asked, ['https://www.example.com/'])  # the hop to the excluded apex is never asked
        self.assertNotIn('example.com', result['touched'])
        self.assertEqual(result['refused'], ['example.com'])
        self.assertEqual(result['probes'][0]['observations'], [])  # a request that was not made says nothing, as on the server

    def test_a_redirect_inside_the_policy_but_outside_the_hosts_group_is_not_followed(self):
        table = {'https://www.example.com/': page(301, url='https://www.example.com/', location='https://other.example.com/')}
        result, asked = run(table, {'domains': ['example.com']}, [HEADERS])
        self.assertEqual(asked, ['https://www.example.com/'])  # other.example.com is in scope, but not this host's group
        self.assertEqual(result['touched'], ['www.example.com'])

    def test_a_redirect_to_another_domain_is_never_asked(self):
        entry = {**HEADERS, 'allowed': ['example.com', 'evil.example.net']}  # even a group that names it cannot widen the policy
        table = {'https://www.example.com/': page(302, url='https://www.example.com/', location='https://evil.example.net/')}
        result, asked = run(table, {'domains': ['example.com']}, [entry])
        self.assertEqual(asked, ['https://www.example.com/'])
        self.assertNotIn('evil.example.net', result['touched'])

    def test_a_host_the_policy_refuses_is_not_run(self):
        result, asked = run({}, {'domains': ['example.org']}, [HEADERS])
        self.assertEqual(asked, [])
        self.assertEqual(result['probes'][0]['error'], 'not run: the host is outside the scope policy')

    def test_scripts_are_read_only_from_hosts_the_policy_names(self):
        body = ('<script src="https://static.example.com/js/jquery-3.4.1.min.js"></script>'
                '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.0/jquery.min.js"></script>'
                '<script src="https://tracker.example.net/t.js"></script>')
        table = {'https://www.example.com/': page(200, body=body, url='https://www.example.com/')}
        entry = {**HEADERS, 'id': 'l1', 'probe': 'html-libraries'}
        result, asked = run(table, {'domains': ['example.com']}, [entry])  # neither the CDN nor the third party is named
        self.assertEqual(asked, ['https://www.example.com/', 'https://static.example.com/js/jquery-3.4.1.min.js'])
        self.assertEqual(result['refused'], ['cdnjs.cloudflare.com'])  # a third party is never even asked about
        _result, asked = run(table, {'hosts': ['www.example.com', 'cdnjs.cloudflare.com']}, [entry])  # host scoped, plus the CDN
        self.assertEqual(asked, ['https://www.example.com/', 'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.0/jquery.min.js'])

    def test_a_malformed_plan_is_refused_whole(self):
        for bad in ({**HEADERS, 'probe': 'nmap-version-all'}, {**HEADERS, 'base': 'https://other.example.com'}, {**HEADERS, 'base': 'ftp://www.example.com'},
                    {**HEADERS, 'base': 'https://www.example.com/admin'}, {**HEADERS, 'id': ''}, 'www.example.com'):
            with self.assertRaises(ValueError):
                version_probes.run_batch({'scope': {'domains': ['example.com']}, 'probes': [bad]}, probe=mock.Mock())
        with self.assertRaises(ValueError):
            version_probes.run_batch({'scope': {}, 'probes': [HEADERS] * (version_probes.MAX_ENTRIES + 1)}, probe=mock.Mock())

    def test_a_probe_after_the_time_budget_is_not_run(self):
        clock = iter([0, 0, 10_000, 10_000, 10_000])
        entries = [HEADERS, {**HEADERS, 'id': 'h2', 'probe': 'error-page'}]
        result, asked = run({}, {'domains': ['example.com']}, entries, clock=lambda: next(clock), workers=1, max_seconds=60)
        self.assertEqual([p.get('error', '') for p in result['probes']], ['', 'not run: the task ran out of time'])


class DnsResolveTests(unittest.TestCase):
    def resolver(self, answers):
        def resolve(name, *_args):
            got = answers[name]
            if isinstance(got, Exception):
                raise got
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, 0)) for a in got]
        return resolve

    def test_names_resolve_only_inside_the_policy(self):
        answers = {'www.example.com': [PUBLIC, PUBLIC, '10.0.0.5'], 'gone.example.com': socket.gaierror(socket.EAI_NONAME, 'no'),
                   'slow.example.com': socket.gaierror(socket.EAI_AGAIN, 'try again')}
        target = {'scope': {'domains': ['example.com'], 'excluded': ['secret.example.com']},
                  'names': ['WWW.example.com.', 'gone.example.com', 'slow.example.com', 'secret.example.com', 'www.example.org']}
        got = dns.run_batch(target, resolver=self.resolver(answers))
        self.assertEqual(got['resolved'], {'www.example.com': [PUBLIC, '10.0.0.5']})  # every address, as answered: the server judges them
        self.assertEqual(list(got['errors']), ['slow.example.com'])  # a resolver that could not answer is not "no address"
        self.assertEqual(sorted(got['refused']), ['secret.example.com', 'www.example.org'])

    def test_a_malformed_task_is_refused(self):
        for names in (['ok.example.com', 5], ['x' * 300], ['a.example.com'] * (dns.MAX_NAMES + 1)):
            with self.assertRaises(ValueError):
                dns.run_batch({'scope': {}, 'names': names}, resolver=mock.Mock())
