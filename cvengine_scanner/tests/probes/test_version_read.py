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


GZIP_HEAD = '1f8b080856ed7a6400037264785f656e'  # a gzip file named rdx_en... with its timestamp, as a NetScaler serves rdx_en.json.gz


def digest_answer(status=200, body='', headers=None, sha='ab' * 32, head=GZIP_HEAD, **extra):
    return {**answer(status, body, headers), 'sha256': sha, 'wire_head': head, 'bytes': len(body), **extra}


class DigestTests(unittest.TestCase):
    """The digest read (contract 8, kind version_digest): a static asset's SHA-256 and first bytes, never the asset."""

    def run_task(self, reads, table, kind=version_read.DIGEST_KIND):
        fake = FakeWeb(table)
        return version_read.run_batch({'reads': reads, 'scope': SCOPE}, probe=fake, sleep=lambda s: None, kind=kind), fake

    def test_a_digest_comes_back_and_the_body_never_does(self):
        req = {'path': '/vpn/js/rdx/core/lang/rdx_en.json.gz', 'read': 'digest', 'headers': ['etag', 'last-modified']}
        result, fake = self.run_task([entry([req])], {req['path']: digest_answer(200, 'SECRET-BODY', {'ETag': '"5a1-6493"', 'Last-Modified': 'x'})})
        got = result['reads'][0]['answers'][0]
        self.assertEqual(got['digest'], {'sha256': 'ab' * 32, 'head': GZIP_HEAD})
        self.assertEqual(got['headers'], {'etag': '"5a1-6493"', 'last-modified': 'x'})
        self.assertNotIn('SECRET-BODY', json.dumps(result))
        self.assertEqual(len(fake.asked), 1)

    def test_a_truncated_body_has_no_hash(self):
        req = {'path': '/a.js', 'read': 'digest'}
        result, _fake = self.run_task([entry([req])], {'/a.js': digest_answer(200, 'x', truncated=True)})
        self.assertEqual(result['reads'][0]['answers'][0]['digest'], {'head': GZIP_HEAD})

    def test_a_redirected_answer_carries_no_digest(self):
        req = {'path': '/a.js', 'read': 'digest'}
        table = {'/a.js': {**answer(302, ''), 'location': '/login'}, '/login': digest_answer(200, '<html>Sign in</html>')}
        result, fake = self.run_task([entry([req])], table)
        got = result['reads'][0]['answers'][0]
        self.assertTrue(got['redirected'])
        self.assertNotIn('digest', got)

    def test_version_read_never_runs_a_digest_read(self):
        with self.assertRaises(ValueError):
            self.run_task([entry([{'path': '/a.js', 'read': 'digest'}])], {}, kind=version_read.KIND)
        with self.assertRaises(ValueError):
            self.run_task([entry([{'path': '/a.js', 'read': 'digest'}])], {}, kind='nmap')

    def test_the_wire_head_is_read_before_decoding(self):
        import gzip
        import io

        from cvengine_scanner.probes import transport

        class Response:
            def __init__(self, raw, encoding):
                self.stream, self.encoding = io.BytesIO(raw), encoding

            def getheader(self, name, default=None):
                return self.encoding if name == 'Content-Encoding' else default

            def read(self, size=-1):
                return self.stream.read(size)

        raw = gzip.compress(b'{}', mtime=1685777750)
        wire = {}
        self.assertEqual(transport.read_body(Response(raw, 'gzip'), 1000, wire=wire), b'{}')
        self.assertEqual(wire['head'], raw[:16])
        wire = {}
        self.assertEqual(transport.read_body(Response(raw, None), 1000, wire=wire), raw)
        self.assertEqual(int.from_bytes(wire['head'][4:8], 'little'), 1685777750)

    def test_the_result_is_in_contract(self):
        if Draft202012Validator is None:
            self.skipTest('jsonschema is not installed')
        reads = [entry([{'path': '/vpn/js/rdx/core/lang/rdx_en.json.gz', 'read': 'digest', 'headers': ['etag']},
                        {'path': '/vpn/index.html', 'read': 'text', 'find': '?v='}, {'path': '/x.css', 'read': 'headers', 'headers': ['etag']}])]
        result, _fake = self.run_task(reads, {'/vpn/js/rdx/core/lang/rdx_en.json.gz': digest_answer(200, 'x'),
                                              '/vpn/index.html': answer(200, '<link href="/vpn/js/rdx/core/css/rdx.css?v=' + 'a' * 32 + '">')})
        errors = list(Draft202012Validator(contract.result_schema('version_digest')).iter_errors({'outcome': 'done', **result}))
        self.assertEqual(errors, [])
        self.assertEqual(list(Draft202012Validator(contract.target_schema('version_digest')).iter_errors({'reads': reads, 'scope': SCOPE})), [])


PAGES = __import__('pathlib').Path(__file__).with_name('pages')
PHPINFO_ROWS = ['PHP Version', 'OpenSSL Library Version', 'cURL Information', 'libXML Loaded Version', 'libXML Compiled Version',
                'PCRE Library Version', 'SQLite Library', 'Apache Version']
STATUS_ROWS = ['ServerVersion', 'ServerMPM', 'Server Built']  # the last two state no version: never returned


def rows_request(path, *names):
    return {'path': path, 'read': 'rows', 'fields': list(names), 'headers': ['server']}


class RowsTests(unittest.TestCase):
    """The rows read (contract 9, kind version_rows): only the named version rows of a status page, never the page."""

    def run_task(self, reads, table, kind=version_read.ROWS_KIND):
        fake = FakeWeb(table)
        return version_read.run_batch({'reads': reads, 'scope': SCOPE}, probe=fake, sleep=lambda s: None, kind=kind), fake

    def test_server_status_auto_gives_only_its_version_lines(self):
        body = (PAGES / 'server_status_auto.txt').read_text()
        result, fake = self.run_task([entry([rows_request('/server-status?auto', *STATUS_ROWS)])],
                                     {'/server-status?auto': answer(200, body, {'Content-Type': 'text/plain; charset=ISO-8859-1'})})
        got = result['reads'][0]['answers'][0]
        self.assertEqual(got['rows'], {'ServerVersion': 'Apache/2.4.57 (Debian) OpenSSL/3.0.11'})
        text = json.dumps(result)
        for other in ('48211', 'Scoreboard', 'www.example.com', 'SHMCB'):
            self.assertNotIn(other, text)
        self.assertNotIn('text', got)
        self.assertEqual(len(fake.asked), 1)

    def test_phpinfo_gives_its_version_rows_and_no_secret(self):
        body = (PAGES / 'phpinfo.html').read_text()
        result, _fake = self.run_task([entry([rows_request('/info.php', *PHPINFO_ROWS)])], {'/info.php': answer(200, body)})
        rows = result['reads'][0]['answers'][0]['rows']
        self.assertEqual(rows, {'PHP Version': '8.2.12', 'OpenSSL Library Version': 'OpenSSL 3.0.11 19 Sep 2023', 'cURL Information': '7.88.1',
                                'libXML Loaded Version': '20914', 'libXML Compiled Version': '2.9.14', 'PCRE Library Version': '10.42 2022-12-11',
                                'SQLite Library': '3.40.1', 'Apache Version': 'Apache/2.4.57 (Debian)'})
        text = json.dumps(result)
        for secret in ('hunter2', 'wJalrXUt', 'PHPSESSID', 'db-prod-7', 'configure', '5.15.0-91'):
            self.assertNotIn(secret, text)

    def test_a_named_row_whose_value_states_no_version_stays_here(self):
        body = (PAGES / 'phpinfo.html').read_text()
        result, _fake = self.run_task([entry([rows_request('/info.php', 'DB_PASSWORD', 'AWS_SECRET_ACCESS_KEY', 'HTTP_COOKIE')])],
                                      {'/info.php': answer(200, body)})
        # the server never names these; were one named, a value with no version in it (a password, a key, a cookie) is not returned all the same
        self.assertEqual(result['reads'][0]['answers'][0]['rows'], {})
        for secret in ('hunter2', 'wJalrXUt', 'PHPSESSID'):
            self.assertNotIn(secret, json.dumps(result))

    def test_a_value_with_markup_or_quotes_is_dropped(self):
        body = ('<table><tr><td class="e">PHP Version </td><td class="v"><i>8.2.12</i></td></tr>'
                '<tr><td class="e">SQLite Library </td><td class="v">3.40.1"; DROP</td></tr></table>')
        result, _fake = self.run_task([entry([rows_request('/info.php', 'PHP Version', 'SQLite Library')])], {'/info.php': answer(200, body)})
        self.assertEqual(result['reads'][0]['answers'][0]['rows'], {})

    def test_a_hostile_page_never_costs_time(self):
        body = '<tr>' * 200000 + '<td>' * 200000 + '\n' + ('ServerVersion' + ' ' * 5000 + ':') * 50
        result, _fake = self.run_task([entry([rows_request('/server-status?auto', 'ServerVersion')])], {'/server-status?auto': answer(200, body)})
        self.assertEqual(result['reads'][0]['answers'][0]['rows'], {})

    def test_version_read_and_version_digest_never_run_a_rows_read(self):
        for kind in (version_read.KIND, version_read.DIGEST_KIND):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.run_task([entry([rows_request('/server-status?auto', 'ServerVersion')])], {}, kind=kind)
        with self.assertRaises(ValueError):  # and the rows kind never runs a digest read
            self.run_task([entry([{'path': '/a.js', 'read': 'digest'}])], {})

    def test_a_rows_read_names_its_rows_and_only_row_names(self):
        for bad in ({'path': '/s', 'read': 'rows'}, {'path': '/s', 'read': 'rows', 'fields': ['<b>']}, {'path': '/s', 'read': 'rows', 'fields': ['x'] * 13},
                    {'path': '/s', 'read': 'rows', 'fields': ['ServerVersion'], 'find': 'x'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.run_task([entry([bad])], {})
        result, _fake = self.run_task([entry([rows_request('/s', 'ServerVersion'), json_request('/v', 'version')])],
                                      {'/v': answer(200, '{"version": "1.2.3"}')})
        self.assertEqual(result['reads'][0]['answers'][1]['json'], {'version': '1.2.3'})  # the version_read reads still run in this kind

    def test_the_result_is_in_contract(self):
        if Draft202012Validator is None:
            self.skipTest('jsonschema is not installed')
        reads = [entry([rows_request('/server-status?auto', *STATUS_ROWS)]),
                 entry([rows_request('/info.php', *PHPINFO_ROWS)], host='search.example.com', base='https://search.example.com')]
        result, _fake = self.run_task(reads, {'/server-status?auto': answer(200, (PAGES / 'server_status_auto.txt').read_text()),
                                              '/info.php': answer(200, (PAGES / 'phpinfo.html').read_text())})
        errors = list(Draft202012Validator(contract.result_schema('version_rows')).iter_errors({'outcome': 'done', **result}))
        self.assertEqual(errors, [])
        self.assertEqual(list(Draft202012Validator(contract.target_schema('version_rows')).iter_errors({'reads': reads, 'scope': SCOPE})), [])


if __name__ == '__main__':
    unittest.main()
