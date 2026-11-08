"""The deny list of the scope floor: ranges this Sentinel never touches, whatever a task asks (``scope.denied_ranges``, ``scope.denied_by``,
``scope._judge``). The same function judges every address a tool or a probe is about to connect to, so these cases are the contract of all of them."""
import ipaddress
import unittest

from cvengine_scanner import scope
from cvengine_scanner.probes import policy

DENIED = '93.184.216.0/24, 2001:4860:4860::/48 ;203.0.114.7'  # one text, three separators, a bare address


def getaddrinfo_of(table):
    def resolve(name, port=None, *args, **kwargs):
        if name not in table:
            raise OSError('no such host')
        return [(2, 1, 6, '', (address, 0)) for address in table[name]]
    return resolve


class DenyTestCase(unittest.TestCase):
    denied = DENIED

    def setUp(self):
        text = self.denied
        scope.use_denied_ranges(lambda: scope.parse_denied_ranges(text))
        self.addCleanup(scope.use_denied_ranges, None)
        self.internal = True  # private space is not what these cases are about

    def refused(self, address):
        try:
            scope._judge(ipaddress.ip_address(address), self.internal)
        except scope.Denied:
            return True
        except scope.ScopeError:
            return False  # refused by the floor for another reason: not the deny list
        return False


class ParseTests(unittest.TestCase):
    def test_commas_semicolons_and_spaces_separate_and_a_bare_address_is_one_host(self):
        nets, bad = scope.parse_denied_ranges(DENIED)
        self.assertEqual(bad, [])
        self.assertEqual([str(n) for n in nets], ['93.184.216.0/24', '2001:4860:4860::/48', '203.0.114.7/32'])

    def test_host_bits_are_ignored_and_brackets_stripped(self):
        nets, bad = scope.parse_denied_ranges('93.184.216.77/24,[2001:db8::1]')
        self.assertEqual((bad, [str(n) for n in nets]), ([], ['93.184.216.0/24', '2001:db8::1/128']))

    def test_junk_is_reported_not_dropped_and_nothing_is_denied_silently(self):
        nets, bad = scope.parse_denied_ranges('93.184.216.0/24,not-a-net,300.1.1.1/8,')
        self.assertEqual(bad, ['not-a-net', '300.1.1.1/8'])
        self.assertEqual(len(nets), 1)

    def test_empty_is_empty(self):
        self.assertEqual(scope.parse_denied_ranges(''), ((), []))
        self.assertEqual(scope.parse_denied_ranges(None), ((), []))


class AddressTests(DenyTestCase):
    def test_v4_inside_and_outside(self):
        self.assertTrue(self.refused('93.184.216.34'))
        self.assertFalse(self.refused('93.184.217.34'))
        self.assertFalse(self.refused('8.8.8.8'))

    def test_cidr_edges(self):
        self.assertFalse(self.refused('93.184.215.255'))  # one before
        self.assertTrue(self.refused('93.184.216.0'))  # network address
        self.assertTrue(self.refused('93.184.216.255'))  # broadcast address
        self.assertFalse(self.refused('93.184.217.0'))  # one after

    def test_a_single_address_denies_exactly_that_host(self):
        self.assertTrue(self.refused('203.0.114.7'))
        self.assertFalse(self.refused('203.0.114.6'))
        self.assertFalse(self.refused('203.0.114.8'))

    def test_v6_compressed_and_expanded_are_one_address(self):
        for form in ('2001:4860:4860::8888', '2001:4860:4860:0:0:0:0:8888', '2001:4860:4860:0000:0000:0000:0000:8888', '2001:4860:4860::0:8888',
                     '2001:4860:4860::8888'.upper()):
            with self.subTest(form=form):
                self.assertTrue(self.refused(form))

    def test_v6_edges(self):
        self.assertTrue(self.refused('2001:4860:4860::'))
        self.assertTrue(self.refused('2001:4860:4860:ffff:ffff:ffff:ffff:ffff'))
        self.assertFalse(self.refused('2001:4860:4861::'))
        self.assertFalse(self.refused('2001:4860:485f:ffff:ffff:ffff:ffff:ffff'))

    def test_ipv4_hidden_in_ipv6_is_the_ipv4_it_is(self):
        self.assertTrue(self.refused('::ffff:93.184.216.34'))  # mapped
        self.assertTrue(self.refused('::ffff:5db8:d822'))  # mapped, hex form
        self.assertTrue(self.refused('64:ff9b::5db8:d822'))  # NAT64
        self.assertTrue(self.refused('2002:5db8:d822::1'))  # 6to4
        self.assertFalse(self.refused('::ffff:93.184.217.34'))

    def test_a_denied_v6_range_does_not_touch_v4_and_the_reverse(self):
        self.assertFalse(self.refused('1.2.3.4'))
        self.assertFalse(self.refused('2001:4860:4861::1'))

    def test_check_ip_check_host_and_check_url_all_refuse_as_denied(self):
        resolver = getaddrinfo_of({'a.example.test': ['93.184.216.9']})
        with self.assertRaises(scope.Denied):
            scope.check_ip('93.184.216.9', internal=True)
        with self.assertRaises(scope.Denied):
            scope.check_host('93.184.216.9', internal=True)
        with self.assertRaises(scope.Denied):
            scope.check_url('http://[2001:4860:4860::1]/', internal=True, resolver=resolver)
        with self.assertRaises(scope.Denied):
            scope.check_url('https://a.example.test/x', internal=True, resolver=resolver)

    def test_the_message_names_the_reason_and_no_more(self):
        with self.assertRaises(scope.Denied) as raised:
            scope.check_ip('93.184.216.9', internal=True)
        self.assertIn('never touches', str(raised.exception))
        self.assertNotIn('93.184.216', str(raised.exception))  # which range is the operator's business


class HostnameTests(DenyTestCase):
    def check(self, table, name):
        return scope.check_host(name, internal=True, resolver=getaddrinfo_of(table))

    def test_a_name_that_resolves_into_the_range_is_refused(self):
        with self.assertRaises(scope.Denied):
            self.check({'www.example.test': ['93.184.216.34']}, 'www.example.test')

    def test_one_denied_answer_among_allowed_ones_refuses_the_name(self):
        with self.assertRaises(scope.Denied):
            self.check({'www.example.test': ['8.8.8.8', '93.184.216.34', '1.1.1.1']}, 'www.example.test')

    def test_an_allowed_name_passes(self):
        self.assertEqual(self.check({'www.example.test': ['8.8.8.8']}, 'www.example.test'), 'www.example.test')

    def test_a_denied_v6_answer_refuses_the_name(self):
        with self.assertRaises(scope.Denied):
            self.check({'www.example.test': ['8.8.8.8', '2001:4860:4860::8844']}, 'www.example.test')

    def test_a_cname_chain_is_judged_by_the_addresses_it_ends_in(self):
        # getaddrinfo follows the chain a -> b -> c and answers with c's addresses: the chain's last name is what matters, however long it is
        table = {'a.example.test': ['93.184.216.40'], 'b.example.test': ['93.184.216.40'], 'c.example.test': ['93.184.216.40']}
        for name in table:
            with self.subTest(name=name), self.assertRaises(scope.Denied):
                self.check(table, name)

    def test_a_name_that_does_not_resolve_has_nothing_to_reach(self):
        self.assertEqual(self.check({}, 'nowhere.example.test'), 'nowhere.example.test')

    def test_an_address_spelled_as_a_name_is_still_an_address(self):
        with self.assertRaises(scope.ScopeError):
            self.check({}, '0x5db8d822')  # a numeric shortcut is refused as a name


class RedirectTests(DenyTestCase):
    """A hop (a redirect, a script) is judged like the first request: by the addresses its host resolves to, in the probes' policy."""

    def policy(self, blocked=()):
        doc = {'hosts': [], 'domains': ['example.test'], 'excluded': [], 'excluded_trees': [], 'private': False, 'addresses': [], 'blocked': list(blocked)}
        return policy.ScopePolicy(doc, internal=True)

    def test_a_redirect_to_an_address_in_the_range_is_refused(self):
        self.assertIn('never touches', self.policy().address_refusal('93.184.216.200'))

    def test_a_redirect_whose_host_resolves_into_the_range_is_refused_at_the_address(self):
        for address in ('93.184.216.1', '2001:4860:4860::1', '::ffff:93.184.216.1'):
            with self.subTest(address=address), self.assertRaises(policy.ScopeRefused):
                self.policy().check_address(address)

    def test_the_task_blocked_list_and_the_operators_both_apply(self):
        p = self.policy(blocked=['198.18.0.0/15'])
        self.assertTrue(p.address_refusal('93.184.216.1'))
        self.assertTrue(p.address_refusal('198.19.0.1'))
        self.assertEqual(p.address_refusal('8.8.8.8'), '')


class NetworkTests(DenyTestCase):
    def test_a_sweep_overlapping_a_denied_range_is_refused_whole(self):
        for net in ('93.184.216.0/24', '93.184.216.128/25', '93.184.0.0/16', '2001:4860::/32', '203.0.114.0/24'):
            with self.subTest(net=net), self.assertRaises(scope.Denied):
                scope.check_network(ipaddress.ip_network(net))

    def test_a_neighbour_is_not_an_overlap(self):
        for net in ('93.184.215.0/24', '93.184.217.0/24', '203.0.114.8/29', '2001:4861::/32'):
            with self.subTest(net=net):
                self.assertEqual(scope.check_network(ipaddress.ip_network(net)), ipaddress.ip_network(net))


class BrokenListTests(DenyTestCase):
    denied = '93.184.216.0/24,oops'

    def test_a_list_with_a_bad_entry_refuses_everything_and_says_so(self):
        for address in ('8.8.8.8', '93.184.216.9'):
            with self.subTest(address=address), self.assertRaises(scope.Denied) as raised:
                scope.check_ip(address, internal=True)
            self.assertIn('oops', str(raised.exception))
            self.assertIn(scope.DENY_ENV, str(raised.exception))


class NothingRegisteredTests(unittest.TestCase):
    def test_without_a_setting_nothing_extra_is_denied(self):
        scope.use_denied_ranges(None)
        self.assertEqual(scope.denied_ranges(), ())
        self.assertEqual(scope.check_ip('93.184.216.9', internal=True), '93.184.216.9')


if __name__ == '__main__':
    unittest.main()
