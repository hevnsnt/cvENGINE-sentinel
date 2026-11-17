"""The version_read kind's runner (cvengine_scanner.probes.version_read): GETs only, only the parts of an answer a request names, the scope
policy before anything is sent, and nothing a host says passed on unclipped."""
import json
import unittest

from cvengine_scanner import contract
from cvengine_scanner.probes import version_read
from cvengine_scanner.tests.probes.test_java_runtime import SCOPE, FakeWeb, answer

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - the test extra installs it
    Draft202012Validator = None


def entry(requests, host='app.example.com', base='https://app.example.com', ident=None):
    return {'id': ident or f'{host}|vsrc', 'host': host, 'base': base, 'requests': requests, 'allowed': [host]}


def json_request(path, *fields, headers=()):
    return {'path': path, 'read': 'json', 'fields': list(fields), 'headers': list(headers)}


CONSUL = json.dumps({'Config': {'Datacenter': 'dc1', 'NodeName': 'n1', 'Revision': 'a9f3b8e1', 'Server': True, 'Version': '1.17.1'},
                     'DebugConfig': {'ACLTokens': {'ACLDefaultToken': 'hidden'}, 'EncryptKey': 'c2VjcmV0c2VjcmV0c2VjcmV0'},
                     'Member': {'Name': 'n1', 'Addr': '10.0.0.5'}, 'Stats': {}})
METRICS = '\n'.join([
    '# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.',
    '# TYPE go_gc_duration_seconds summary',
    'go_gc_duration_seconds{quantile="0"} 2.6e-05',
    '# HELP go_info Information about the Go environment.',
    'go_info{version="go1.21.5"} 1',
    'jvm_info{runtime="OpenJDK Runtime Environment",vendor="Eclipse Adoptium",version="17.0.9+9"} 1.0',
    'node_exporter_build_info{branch="HEAD",goarch="amd64",goos="linux",goversion="go1.21.5",revision="7333465",tags="netgo osusergo",version="1.7.0"} 1',
    'node_uname_info{domainname="(none)",machine="x86_64",nodename="db-prod-7",release="5.15.0-91-generic",sysname="Linux",version="#101-Ubuntu SMP"} 1',
    'app_secret_info{api_key="sk_live_abcdef",version="2.1.0"} 1',
    'http_requests_total{code="200",handler="/api/v1/users?token=abc"} 1027',
])


class ReadTests(unittest.TestCase):
    def run_task(self, reads, table):
        fake = FakeWeb(table)
        result = version_read.run_batch({'reads': reads, 'scope': SCOPE}, probe=fake, sleep=lambda s: None)
        return result, fake

    def test_only_the_named_json_fields_come_back(self):
        result, fake = self.run_task([entry([json_request('/v1/agent/self', 'Config.Version', 'Config.Revision', 'DebugConfig', 'Missing.Field')])],
                                     {'/v1/agent/self': answer(200, CONSUL, {'Content-Type': 'application/json'})})
        got = result['reads'][0]['answers'][0]
        self.assertEqual(got['json'], {'Config.Version': '1.17.1', 'Config.Revision': 'a9f3b8e1', 'DebugConfig': {'type': 'object', 'size': 2}})
        self.assertNotIn('c2VjcmV0', json.dumps(result))  # nothing of the rest of the body leaves the Sentinel
        self.assertNotIn('body', got)
        self.assertEqual(len(fake.asked), 1)

    def test_a_page_that_is_not_json_reads_as_none(self):
        result, _fake = self.run_task([entry([json_request('/api/health', 'version')])], {'/api/health': answer(200, '<html>Sign in</html>')})
        self.assertIsNone(result['reads'][0]['answers'][0]['json'])

    def test_metrics_keep_only_info_samples_and_version_labels(self):
        result, _fake = self.run_task([entry([{'path': '/metrics', 'read': 'metrics'}], base='https://app.example.com:9100')],
                                      {'/metrics': answer(200, METRICS)})
        lines = result['reads'][0]['answers'][0]['lines']
        self.assertEqual(lines, ['go_info{version="go1.21.5"}',
                                 'jvm_info{runtime="OpenJDK Runtime Environment",vendor="Eclipse Adoptium",version="17.0.9+9"}',
                                 'node_exporter_build_info{goversion="go1.21.5",revision="7333465",version="1.7.0"}',
                                 'node_uname_info{}',  # nodename, release and the kernel build string are not version labels of ours: dropped
                                 'app_secret_info{version="2.1.0"}'])
        text = json.dumps(result)
        for secret in ('sk_live', 'db-prod-7', 'token=abc', '1027'):
            self.assertNotIn(secret, text)

    def test_a_hostile_label_never_costs_time_or_passes_through(self):
        line = 'evil_info{version="' + '\\"' * 50000 + '"} 1\nok_info{version="1.2.3"} 1'
        result, _fake = self.run_task([entry([{'path': '/metrics', 'read': 'metrics'}])], {'/metrics': answer(200, line)})
        self.assertEqual(result['reads'][0]['answers'][0]['lines'], ['ok_info{version="1.2.3"}'])

    def test_text_starts_at_the_literal_and_is_clean(self):
        body = '<html>' + 'x' * 5000 + '<b>Version Information:</b>\x00\x1b[31m Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.4718.0</html>'
        req = {'path': '/cvengine-probe-404.aspx', 'read': 'text', 'find': 'Microsoft .NET Framework Version:', 'headers': ['x-aspnet-version']}
        result, _fake = self.run_task([entry([req])], {'/cvengine-probe-404.aspx': answer(404, body, {'X-AspNet-Version': '4.0.30319'})})
        got = result['reads'][0]['answers'][0]
        self.assertTrue(got['text'].startswith('Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.4718.0'))
        self.assertEqual(got['headers'], {'x-aspnet-version': '4.0.30319'})
        missing, _fake = self.run_task([entry([req])], {'/cvengine-probe-404.aspx': answer(404, '<html>Runtime Error</html>')})
        self.assertEqual(missing['reads'][0]['answers'][0]['text'], '')

    def test_a_cookie_is_never_returned(self):
        req = {'path': '/login', 'read': 'headers', 'headers': ['x-jenkins', 'set-cookie']}
        with self.assertRaises(ValueError):
            self.run_task([entry([req])], {})
        req['headers'] = ['x-jenkins']
        result, _fake = self.run_task([entry([req])], {'/login': answer(403, 'denied', {'X-Jenkins': '2.426.1', 'Set-Cookie': 'JSESSIONID=abc'})})
        self.assertEqual(result['reads'][0]['answers'][0]['headers'], {'x-jenkins': '2.426.1'})
        self.assertNotIn('JSESSIONID', json.dumps(result))

    def test_one_hosts_requests_are_asked_in_order(self):
        reads = [entry([json_request('/api/v1/version', 'version'), json_request('/api/v1/cvengine-control-0123456789ab', 'version')]),
                 entry([{'path': '/metrics', 'read': 'metrics'}], ident='second')]
        _result, fake = self.run_task(reads, {})
        self.assertEqual([u.split('example.com', 1)[1] for u in fake.asked], ['/api/v1/version', '/api/v1/cvengine-control-0123456789ab', '/metrics'])

    def test_a_host_outside_the_policy_is_not_asked(self):
        result, fake = self.run_task([entry([json_request('/api/health', 'version')], 'blocked.example.com', 'https://blocked.example.com')], {})
        self.assertEqual(fake.asked, [])
        self.assertIn('not run', result['reads'][0]['error'])

    def test_a_malformed_task_fails(self):
        good = json_request('/api/health', 'version')
        for bad in ({**entry([good]), 'base': 'https://other.example.com'}, {**entry([good]), 'base': 'https://app.example.com/sub'},
                    entry([{**good, 'path': 'https://evil.example.net/'}]), entry([{**good, 'path': '//evil.example.net/x'}]),
                    entry([{**good, 'path': '/a/../../etc/passwd'}]), entry([{**good, 'path': '/a b'}]), entry([{**good, 'read': 'body'}]),
                    entry([{**good, 'method': 'POST'}]), entry([{**good, 'path': '/x\r\nX-Injected: 1'}]), entry([{**good, 'fields': []}]),
                    entry([{**good, 'fields': ['a' * 61]}]), entry([{'path': '/x', 'read': 'text', 'fields': ['version']}]),
                    entry([{'path': '/x', 'read': 'json', 'fields': ['v'], 'find': 'Version'}]), entry([good] * 5), entry([])):
            with self.subTest(bad=str(bad)[:80]):
                with self.assertRaises(ValueError):
                    version_read.run_batch({'reads': [bad], 'scope': SCOPE}, probe=FakeWeb({}), sleep=lambda s: None)
        with self.assertRaises(ValueError):
            version_read.run_batch({'reads': [], 'scope': SCOPE}, probe=FakeWeb({}))
        with self.assertRaises(ValueError):
            version_read.run_batch({'reads': [entry([good])] * 2, 'scope': SCOPE}, probe=FakeWeb({}))  # one id twice

    def test_a_failed_request_is_unknown_not_empty(self):
        def broken(url, policy, **kwargs):
            raise TimeoutError('probe exceeded its total time budget')
        result = version_read.run_batch({'reads': [entry([json_request('/api/health', 'version')])], 'scope': SCOPE}, probe=broken, sleep=lambda s: None)
        self.assertEqual(result['reads'][0]['answers'], [{'path': '/api/health', 'status': 0, 'error': 'TimeoutError'}])

    def test_the_result_is_in_contract(self):
        if Draft202012Validator is None:
            self.skipTest('jsonschema is not installed')
        reads = [entry([json_request('/v1/agent/self', 'Config.Version', 'DebugConfig'), {'path': '/metrics', 'read': 'metrics', 'headers': ['content-type']},
                        {'path': '/x.aspx', 'read': 'text', 'find': 'Version'}, {'path': '/login', 'read': 'headers', 'headers': ['x-jenkins']}])]
        result, _fake = self.run_task(reads, {'/v1/agent/self': answer(200, CONSUL), '/metrics': answer(200, METRICS)})
        errors = list(Draft202012Validator(contract.result_schema('version_read')).iter_errors({'outcome': 'done', **result}))
        self.assertEqual(errors, [])
        target = {'reads': reads, 'scope': SCOPE}
        self.assertEqual(list(Draft202012Validator(contract.target_schema('version_read')).iter_errors(target)), [])


if __name__ == '__main__':
    unittest.main()
