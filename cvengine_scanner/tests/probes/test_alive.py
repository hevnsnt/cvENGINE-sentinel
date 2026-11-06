"""The alive_check kind (``probes.alive``): a retired name's last known addresses, asked as themselves under the task's scope policy."""
import unittest
from unittest import mock

from cvengine_scanner.probes import alive

SCOPE = {'hosts': ['93.184.215.14', '2606:2800:21f:cb07:6820:80da:af6b:8b2c'], 'domains': [], 'excluded': [], 'excluded_trees': [],
         'private': False, 'addresses': [], 'blocked': []}


def check(ident='c1', host='old.example.test', ip='93.184.215.14', port=443, scheme='https'):
    return {'id': ident, 'host': host, 'ip': ip, 'port': port, 'scheme': scheme}


class AliveTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_web_check_asks_the_address_as_the_old_name_and_any_answer_counts(self):
        asked = []

        def probe(url, policy, **kw):
            asked.append((url, kw['headers'], kw['max_bytes']))
            policy.touch('93.184.215.14')
            return {'status': 404}
        got = alive.run_batch({'scope': SCOPE, 'checks': [check()]}, probe=probe)
        self.assertEqual(asked, [('https://93.184.215.14:443/', {'Host': 'old.example.test'}, 4096)])
        self.assertEqual(got, {'checks': [{'id': 'c1', 'alive': True}], 'touched': ['93.184.215.14'], 'refused': []})

    def test_nothing_answering_is_not_alive(self):
        def probe(url, policy, **kw):
            raise OSError('refused')
        got = alive.run_batch({'scope': SCOPE, 'checks': [check(scheme='http', port=80)]}, probe=probe)
        self.assertEqual(got['checks'], [{'id': 'c1', 'alive': False}])

    def test_a_connect_sends_nothing_and_closes(self):
        sock = mock.Mock()
        connect = mock.Mock(return_value=sock)
        got = alive.run_batch({'scope': SCOPE, 'checks': [check(port=22, scheme='tcp')]}, connect=connect)
        self.assertEqual(got['checks'], [{'id': 'c1', 'alive': True}])
        sock.close.assert_called_once_with()
        sock.sendall.assert_not_called()
        self.assertEqual(connect.call_args[1]['literal'], True)  # asked as itself
        refused = mock.Mock(side_effect=OSError('refused'))
        self.assertEqual(alive.run_batch({'scope': SCOPE, 'checks': [check(port=22, scheme='tcp')]}, connect=refused)['checks'][0]['alive'], False)

    def test_an_address_outside_the_policy_is_never_asked_and_says_so(self):
        probe, connect = mock.Mock(), mock.Mock()
        got = alive.run_batch({'scope': SCOPE, 'checks': [check(ip='93.184.215.15'), check('c2', ip='93.184.215.15', port=22, scheme='tcp')]},
                              probe=probe, connect=connect)
        probe.assert_not_called()
        connect.assert_not_called()
        self.assertTrue(all(not c['alive'] and c['error'].startswith('not run:') for c in got['checks']))
        self.assertEqual(got['refused'], ['93.184.215.15'])

    def test_the_floor_holds_whatever_the_policy_lists(self):
        scope = {**SCOPE, 'hosts': ['127.0.0.1', '169.254.169.254'], 'private': True, 'addresses': ['127.0.0.1']}
        got = alive.run_batch({'scope': scope, 'checks': [check(ip='127.0.0.1', port=22, scheme='tcp'), check('c2', ip='169.254.169.254', scheme='http', port=80)]})
        self.assertEqual([c['alive'] for c in got['checks']], [False, False])
        self.assertTrue(all('error' in c for c in got['checks']))
        self.assertEqual(got['touched'], [])

    def test_a_malformed_task_is_refused_whole(self):
        for bad in (check(scheme='ftp'), check(port=0), check(port=True), check(ip='not-an-ip'), check(host='a b'), check(ident=''), 'x'):
            with self.assertRaises(ValueError):
                alive.run_batch({'scope': SCOPE, 'checks': [bad]}, probe=mock.Mock())
        with self.assertRaises(ValueError):
            alive.run_batch({'scope': SCOPE, 'checks': [check()] * (alive.MAX_CHECKS + 1)}, probe=mock.Mock())
