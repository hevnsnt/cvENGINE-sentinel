"""The java_runtime kind's runner (cvengine_scanner.probes.java_runtime): the fixed GETs per check, the stop at the first reading, the scope policy,
and the JDWP exchange, which never sends anything but the handshake and VirtualMachine.Version."""
import json
import struct
import unittest

from cvengine_scanner import contract, java
from cvengine_scanner.probes import java_runtime
from cvengine_scanner.tests.test_java import DESCRIPTION, version_reply

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - the test extra installs it
    Draft202012Validator = None

ADDRESS = '93.184.215.14'  # a public address the scanner's floor lets through (a documentation range is refused by it)
SCOPE = {'hosts': ['app.example.com', 'search.example.com', ADDRESS], 'domains': [], 'excluded': ['blocked.example.com'],
         'excluded_trees': [], 'private': False, 'addresses': [], 'blocked': []}


def answer(status=200, body='', headers=None):
    headers = headers or {}
    return {'status': status, 'body': body, 'title': '', 'location': '', 'headers': headers, 'raw_headers': {k.lower(): v for k, v in headers.items()},
            'server': headers.get('Server', ''), 'powered_by': headers.get('X-Powered-By', '')}


class FakeWeb:
    """Stands in for ``http.probe_url``: answers by path, 404 for the rest, and records every URL asked."""

    def __init__(self, table):
        self.table, self.asked = table, []

    def __call__(self, url, policy, **kwargs):
        policy.touch(url.split('://', 1)[1].split('/', 1)[0].split(':', 1)[0])
        self.asked.append(url)
        path = '/' + url.split('://', 1)[1].split('/', 1)[1] if url.count('/') > 2 else '/'
        return {**self.table.get(path, answer(404, '<html>Not Found</html>')), 'url': url}


class FakeSocket:
    def __init__(self, replies):
        self.replies, self.sent, self.closed = list(replies), [], False

    def sendall(self, data):
        self.sent.append(bytes(data))

    def settimeout(self, value):
        pass

    def recv(self, size):
        if not self.replies:
            return b''
        head = self.replies[0]
        chunk, rest = head[:size], head[size:]
        if rest:
            self.replies[0] = rest
        else:
            self.replies.pop(0)
        return chunk

    def close(self):
        self.closed = True


def web_entry(checks, host='app.example.com', base='https://app.example.com'):
    return {'id': f'{host}|java', 'host': host, 'base': base, 'checks': checks, 'allowed': [host]}


INFO = json.dumps({'java': {'version': '17.0.9', 'vendor': {'name': 'Eclipse Adoptium'}, 'runtime': {'name': 'OpenJDK Runtime Environment',
                                                                                                      'version': '17.0.9+9'}}})


class WebTests(unittest.TestCase):
    def run_task(self, web, table, jdwp=()):
        fake = FakeWeb(table)
        result = java_runtime.run_batch({'web': web, 'jdwp': list(jdwp), 'scope': SCOPE}, probe=fake, sleep=lambda s: None)
        return result, fake

    def test_actuator_stops_at_its_first_reading(self):
        result, fake = self.run_task([web_entry(['actuator'])], {'/actuator/env/java.version': answer(401, '{"error":"unauthorized"}'),
                                                                  '/actuator/info': answer(200, INFO)})
        readings = result['web'][0]['readings']
        self.assertEqual([(r['version'], r['vendor'], r['source']) for r in readings], [('17.0.9', 'Eclipse Temurin', 'actuator')])
        self.assertEqual([u.split('example.com', 1)[1] for u in fake.asked], ['/actuator/env/java.version', '/actuator/info'])  # never the metric or /env
        self.assertEqual([a['status'] for a in result['web'][0]['asked']], [401, 200])

    def test_every_path_asked_is_a_get_from_the_fixed_list(self):
        _result, fake = self.run_task([web_entry(['actuator', 'jolokia', 'solr', 'geoserver', 'druid', 'elasticsearch'])], {})
        paths = {u.split('example.com', 1)[1] for u in fake.asked}
        fixed = {p for check in java_runtime.CHECKS.values() for p, _r in check}
        self.assertTrue(paths <= fixed, paths - fixed)
        self.assertNotIn('/actuator/env', paths)  # the whole environment (secrets) is never fetched
        self.assertFalse(any(p.startswith('/jolokia/read') for p in paths))  # no read before Jolokia answered its version

    def test_jolokia_reads_follow_only_its_own_answer(self):
        table = {'/jolokia/version': answer(200, json.dumps({'value': {'agent': '1.7.2'}, 'status': 200})),
                 java_runtime.JOLOKIA_READS[0]: answer(200, json.dumps({'value': '25.392-b08', 'status': 200})),
                 java_runtime.JOLOKIA_READS[1]: answer(200, json.dumps({'value': 'Oracle Corporation', 'status': 200}))}
        result, fake = self.run_task([web_entry(['jolokia'])], table)
        self.assertEqual([(r['version'], r['source']) for r in result['web'][0]['readings']], [('8u392', 'jolokia')])
        self.assertEqual(len(fake.asked), 3)

    def test_a_catch_all_page_gives_nothing(self):
        page = answer(200, '<html><title>Welcome</title></html>')
        table = {p: page for check in java_runtime.CHECKS.values() for p, _r in check}
        result, _fake = self.run_task([web_entry(['actuator', 'solr'])], table)
        self.assertEqual(result['web'][0]['readings'], [])

    def test_headers_of_any_answer_are_read(self):
        result, _fake = self.run_task([web_entry(['solr'])], {'/solr/admin/info/system?wt=json': answer(
            403, 'forbidden', {'X-Powered-By': 'Servlet/4.0 JSP/2.3 (Payara Server 5.2022.5 Java/Azul Systems, Inc./17)'})})
        self.assertEqual([(r['version'], r['source'], r['line_only']) for r in result['web'][0]['readings']], [('17', 'header', True)])

    def test_elasticsearch(self):
        body = json.dumps({'nodes': {'n': {'jvm': {'version': '21.0.1', 'vm_vendor': 'Oracle Corporation', 'vm_version': '21.0.1+12-29'}}}})
        result, fake = self.run_task([web_entry(['elasticsearch'], 'search.example.com', 'https://search.example.com:9200')],
                                     {f'/_nodes/jvm?filter_path={java_runtime.ES_FIELDS}': answer(200, body)})
        self.assertEqual(result['web'][0]['readings'][0]['version'], '21.0.1')

    def test_a_host_outside_the_policy_is_not_asked(self):
        result, fake = self.run_task([web_entry(['actuator'], 'blocked.example.com', 'https://blocked.example.com')], {})
        self.assertEqual(fake.asked, [])
        self.assertIn('not run', result['web'][0]['error'])

    def test_a_malformed_entry_fails_the_task(self):
        for bad in ({**web_entry(['actuator']), 'base': 'https://other.example.com'}, {**web_entry(['actuator']), 'checks': ['heapdump']},
                    {**web_entry(['actuator']), 'base': 'https://app.example.com/actuator'}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    java_runtime.run_batch({'web': [bad], 'scope': SCOPE}, probe=FakeWeb({}), sleep=lambda s: None)
        with self.assertRaises(ValueError):
            java_runtime.run_batch({'web': [], 'jdwp': [], 'scope': SCOPE}, probe=FakeWeb({}))

    def test_the_result_is_in_contract(self):
        if Draft202012Validator is None:
            self.skipTest('jsonschema is not installed')
        sock = FakeSocket([b'JDWP-Handshake', version_reply(DESCRIPTION, '17.0.9', 'OpenJDK 64-Bit Server VM')])
        fake = FakeWeb({'/actuator/info': answer(200, INFO)})
        result = java_runtime.run_batch({'web': [web_entry(['actuator', 'jolokia'])], 'jdwp': [{'id': 'j', 'address': ADDRESS, 'port': 5005}],
                                         'scope': SCOPE}, probe=fake, connect=lambda addr, timeout: sock, sleep=lambda s: None)
        errors = list(Draft202012Validator(contract.result_schema('java_runtime')).iter_errors({'outcome': 'done', **result}))
        self.assertEqual(errors, [])


class JdwpTests(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_one(self, replies, address=ADDRESS):
        sock = FakeSocket(replies)
        connected = []

        def connect(addr, timeout):
            connected.append(addr)
            return sock
        result = java_runtime.run_batch({'jdwp': [{'id': 'e', 'address': address, 'port': 5005}], 'scope': SCOPE}, connect=connect,
                                        sleep=lambda s: None)
        return result['jdwp'][0], sock, connected

    def test_a_debuggee_is_asked_its_version_and_nothing_else(self):
        row, sock, connected = self.run_one([b'JDWP-Handshake', version_reply(DESCRIPTION, '17.0.9', 'OpenJDK 64-Bit Server VM')])
        self.assertEqual(connected, [(ADDRESS, 5005)])
        self.assertTrue(row['speaks'])
        self.assertEqual((row['reading']['version'], row['reading']['port']), ('17.0.9', 5005))
        self.assertEqual(sock.sent, [java.HANDSHAKE, java.version_command(1)])  # exactly two writes: the handshake and VirtualMachine.Version
        self.assertTrue(sock.closed)
        command_sets = {struct.unpack('>IIBBB', packet)[3:] for packet in sock.sent[1:]}
        self.assertEqual(command_sets, {(1, 1)})

    def test_another_service_is_not_sent_the_command(self):
        row, sock, _c = self.run_one([b'HTTP/1.1 400 Bad Request\r\n'])
        self.assertIs(row['speaks'], False)
        self.assertEqual(sock.sent, [java.HANDSHAKE])

    def test_silence_is_unknown(self):
        row, _sock, _c = self.run_one([])
        self.assertIsNone(row['speaks'])

    def test_an_address_outside_the_policy_is_never_connected(self):
        row, sock, connected = self.run_one([b'JDWP-Handshake'], address='203.0.113.9')
        self.assertEqual(connected, [])
        self.assertIsNone(row['speaks'])
        self.assertIn('not run', row['error'])

    def test_a_private_address_is_refused_by_the_floor(self):
        scope = {**SCOPE, 'hosts': SCOPE['hosts'] + ['10.0.0.5']}
        connected = []
        result = java_runtime.run_batch({'jdwp': [{'id': 'p', 'address': '10.0.0.5', 'port': 5005}], 'scope': scope},
                                        connect=lambda a, timeout: connected.append(a), sleep=lambda s: None)
        self.assertEqual(connected, [])
        self.assertIn('not run', result['jdwp'][0]['error'])


if __name__ == '__main__':
    unittest.main()
