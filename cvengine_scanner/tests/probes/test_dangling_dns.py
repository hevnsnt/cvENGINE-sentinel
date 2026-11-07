"""The dangling_dns_check kind (``probes.dangling_dns``), ported from cvENGINE's web/tests/test_dangling_dns.py (its rating tests that need no database):
the library copy rates a finding as the server does. Every fixture is synthetic (example.com/.net/.org, documentation addresses) and no test sends a
DNS or HTTP request: the network is a fake that answers like authoritative servers do."""
import json
import unittest
from unittest import mock

from cvengine_scanner import contract
from cvengine_scanner.probes import dangling_dns as dd
from cvengine_scanner.probes.policy import ScopePolicy

SimpleTestCase = unittest.TestCase
GCLOUD = [f'ns-cloud-c{i}.googledomains.com' for i in range(1, 5)]
# the lists cvENGINE sends (cveFeed/data/takeover_providers.json), reduced to the entries these tests read
PROVIDERS = dd.Providers({
    'cname': [{'service': 'Microsoft Azure', 'suffixes': ['cloudapp.net', 'azurewebsites.net']}, {'service': 'GitHub Pages', 'suffixes': ['github.io']}],
    'nameservers': [{'service': 'Google Cloud DNS', 'patterns': ['^ns-cloud-[a-z][0-9]+\\.googledomains\\.com$']},
                    {'service': 'AWS Route 53', 'patterns': ['^ns-[0-9]+\\.awsdns-[0-9]+\\.(com|net|org|co\\.uk)$']}]})


class FakeDns:
    """Authoritative DNS in memory. ``zones``: zone -> {'ns': [hosts], 'children': {name: [hosts]}, 'cnames': {name: target}}. A server answers
    for the deepest zone it serves (a referral for a delegated child, a CNAME, the SOA, NS, or no data) and REFUSED for a zone it does not
    serve, like a self-service provider whose account holds no such zone. ``silent`` hosts never answer; ``servfail`` hosts answer SERVFAIL."""

    def __init__(self, zones, addresses, silent=(), servfail=(), registered=None, http=None):
        self.zones, self.ips, self.silent, self.servfail = zones, addresses, set(silent), set(servfail)
        self.host_of = {ip: host for host, ips in addresses.items() for ip in ips}
        self.registered_map, self.http = registered or {}, http
        self.asked, self.http_calls = [], []

    def ns(self, name):
        return list(self.zones.get(name, {}).get('ns', []))

    def addresses(self, host):
        return list(self.ips.get(host, []))

    def ask(self, server, qname, rdtype):
        self.asked.append((server, qname, rdtype))
        host = self.host_of.get(server)
        if host in self.silent:
            return None
        if host in self.servfail:
            return dd.Reply('SERVFAIL')
        served = [z for z, data in self.zones.items() if host in data.get('ns', []) and (qname == z or qname.endswith('.' + z))]
        if not served:
            return dd.Reply('REFUSED')
        zone = max(served, key=len)
        data = self.zones[zone]
        for child, hosts in data.get('children', {}).items():
            if qname == child or qname.endswith('.' + child):
                return dd.Reply('NOERROR', authority=[(child, 'NS', h) for h in hosts])
        if qname in data.get('cnames', {}):
            return dd.Reply('NOERROR', aa=True, answer=[(qname, 'CNAME', data['cnames'][qname])])
        if qname == zone and rdtype == 'SOA':
            return dd.Reply('NOERROR', aa=True, answer=[(zone, 'SOA', f'ns.{zone} hostmaster.{zone} 1 2 3 4 5')])
        if qname == zone and rdtype == 'NS':
            return dd.Reply('NOERROR', aa=True, answer=[(zone, 'NS', h) for h in data['ns']])
        return dd.Reply('NOERROR', aa=True, authority=[(zone, 'SOA', f'ns.{zone} hostmaster.{zone} 1 2 3 4 5')])

    def registered(self, domain):
        return self.registered_map.get(domain)

    def http_control(self, host):
        self.http_calls.append(host)
        return self.http


def registry_and_client(children=None, client_children=None, cnames=None, apex='example.com'):
    """The .com registry delegating ``apex`` to its own healthy servers, which delegate ``client_children``."""
    tld = apex.rsplit('.', 1)[1]
    zones = {tld: {'ns': ['a.registry.example.net'], 'children': {apex: ['ns1.example.net', 'ns2.example.net'], **(children or {})}},
             apex: {'ns': ['ns1.example.net', 'ns2.example.net'], 'children': client_children or {}, 'cnames': cnames or {}}}
    addresses = {'a.registry.example.net': ['192.0.2.1'], 'ns1.example.net': ['192.0.2.2'], 'ns2.example.net': ['192.0.2.3'],
                 **{h: [f'198.51.100.{i}'] for i, h in enumerate(GCLOUD, start=1)},
                 'ns1.dns-host.example.org': ['198.51.100.20'], 'ns2.dns-host.example.org': ['198.51.100.21']}
    return zones, addresses



def check(host, kind, triggers=(), ident='0'):
    return dd.Check(ident, host, kind, [t.lower() for t in triggers])


def assess(host, kind, triggers, net):
    return dd.assess(check(host, kind, triggers), net, PROVIDERS)


class ProviderTests(SimpleTestCase):
    def test_provider_list_is_conservative_data(self):
        self.assertEqual(PROVIDERS.claimable_provider('app-1.azurewebsites.net'), 'Microsoft Azure')
        self.assertEqual(PROVIDERS.claimable_provider('ACME.GitHub.io.'), 'GitHub Pages')
        for target in ('internal-lb-0123456789.us-east-1.elb.amazonaws.com', 'x.secureserver.net', 'mailgun.org', 'notgithub.io'):
            self.assertIsNone(PROVIDERS.claimable_provider(target), target)
        self.assertEqual(PROVIDERS.self_service_provider(GCLOUD), 'Google Cloud DNS')
        self.assertEqual(PROVIDERS.self_service_provider(['ns-1.awsdns-01.org', 'ns-2.awsdns-02.co.uk']), 'AWS Route 53')
        self.assertIsNone(PROVIDERS.self_service_provider(['ns-cloud-c1.googledomains.com', 'ns1.example.net']))  # every server must be at one

    def test_the_server_sends_the_lists_in_this_shape_and_a_bad_one_is_refused(self):
        sent = contract.load()['$defs']['targets']['dangling_dns_check']['properties']['providers']
        self.assertEqual(sorted(sent['required']), ['cname', 'nameservers'])
        for bad in (None, {}, {'cname': [], 'nameservers': [{'service': 'x', 'patterns': ['(']}]}, {'cname': [{'service': 'x'}], 'nameservers': []},
                    {'cname': [{'service': 'x', 'suffixes': []}] * 201, 'nameservers': []}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                dd.Providers(bad)


class ReplyTests(SimpleTestCase):
    def test_a_referral_and_a_refusal_read_from_dns_messages(self):
        import dns.message
        referral = dns.message.from_text(
            'id 1\nopcode QUERY\nrcode NOERROR\nflags QR\n;QUESTION\nd.example.com. IN NS\n;ANSWER\n;AUTHORITY\n'
            'd.example.com. 300 IN NS ns-cloud-c1.googledomains.com.\nd.example.com. 300 IN NS ns-cloud-c2.googledomains.com.\n;ADDITIONAL\n')
        reply = dd.reply_from(referral)
        self.assertEqual((reply.rcode, reply.aa), ('NOERROR', False))
        self.assertEqual(reply.values('d.example.com.', 'NS'), GCLOUD[:2])
        refused = dd.reply_from(dns.message.from_text('id 2\nopcode QUERY\nrcode REFUSED\nflags QR\n;QUESTION\nd.example.com. IN SOA\n'))
        self.assertEqual(refused.rcode, 'REFUSED')


class NameServerRatingTests(SimpleTestCase):
    def assess(self, host, net, trigger=GCLOUD):
        return assess(host, dd.KIND_NS, trigger, net)

    def test_a_sub_zone_delegated_to_google_cloud_dns_that_every_server_refuses_is_fire(self):
        zones, addresses = registry_and_client(client_children={'d.fs.app.example.com': GCLOUD})
        net = FakeDns(zones, addresses)
        rating = self.assess('dev.d.fs.app.example.com', net)
        self.assertEqual((rating.severity, rating.drop, rating.zone), (dd.FIRE_SEVERITY, False, 'd.fs.app.example.com'))
        self.assertIn('Google Cloud DNS', rating.note)
        soa = [a for a in net.asked if a[2] == 'SOA']
        self.assertEqual(sorted(s for s, _q, _t in soa), [f'198.51.100.{i}' for i in range(1, 5)])  # every delegated server was asked
        self.assertEqual({q for _s, q, _t in soa}, {'d.fs.app.example.com'})  # for the zone at the cut, not the matched name

    def test_an_apex_the_registry_delegates_to_google_cloud_dns_that_refuses_it_is_fire(self):
        zones = {'org': {'ns': ['a.registry.example.net'], 'children': {'example.org': GCLOUD}}}
        addresses = {'a.registry.example.net': ['192.0.2.1'], **{h: [f'198.51.100.{i}'] for i, h in enumerate(GCLOUD, start=1)}}
        rating = self.assess('www.example.org', FakeDns(zones, addresses))
        self.assertEqual((rating.severity, rating.zone), (dd.FIRE_SEVERITY, 'example.org'))

    def test_servfail_counts_like_refused(self):
        zones, addresses = registry_and_client(client_children={'d.example.com': GCLOUD})
        self.assertEqual(self.assess('d.example.com', FakeDns(zones, addresses, servfail=GCLOUD[:2])).severity, dd.FIRE_SEVERITY)

    def test_a_name_that_is_a_cname_into_a_provider_zone_is_not_the_clients_delegation(self):
        zones, addresses = registry_and_client(cnames={'vision.example.com': 'abc123.up.railway.app'})
        rating = self.assess('vision.example.com', FakeDns(zones, addresses), trigger=['ns1.railway.app'])
        self.assertTrue(rating.drop)
        self.assertIn('CNAME to abc123.up.railway.app', rating.note)

    def test_a_lame_delegation_at_a_provider_that_is_not_self_service_stays_smoke(self):
        zones, addresses = registry_and_client(client_children={'old.example.com': ['ns1.dns-host.example.org', 'ns2.dns-host.example.org']})
        self.assertEqual(self.assess('old.example.com', FakeDns(zones, addresses), trigger=['ns1.dns-host.example.org']).severity, dd.SMOKE_SEVERITY)

    def test_a_delegation_that_is_served_is_ice(self):
        zones, addresses = registry_and_client(client_children={'d.example.com': GCLOUD})
        zones['d.example.com'] = {'ns': GCLOUD}
        self.assertEqual(self.assess('d.example.com', FakeDns(zones, addresses)).severity, dd.ICE_SEVERITY)

    def test_a_name_inside_a_healthy_zone_with_no_cut_of_its_own_is_ice(self):
        zones, addresses = registry_and_client()
        self.assertEqual(self.assess('app.example.com', FakeDns(zones, addresses)).severity, dd.ICE_SEVERITY)

    def test_a_server_that_does_not_answer_leaves_baddns_rating(self):
        zones, addresses = registry_and_client(client_children={'d.example.com': GCLOUD})
        self.assertIsNone(self.assess('d.example.com', FakeDns(zones, addresses, silent=GCLOUD[3:])))
        self.assertIsNone(self.assess('d.example.com', FakeDns(zones, addresses, silent=['a.registry.example.net'])))


class CnameRatingTests(SimpleTestCase):
    def nx(self, target, **net):
        return assess('pda.example.com', dd.KIND_NXDOMAIN, [target], FakeDns({}, {}, **net))

    def test_targets_no_outsider_can_create_are_ice(self):
        for target, domain in (('internal-lb-0123456789.us-east-1.elb.amazonaws.com', 'amazonaws.com'), ('pda.example.net', 'example.net'),
                               ('x.secureserver.net', 'secureserver.net'), ('gone.example.com', 'example.com')):
            rating = self.nx(target, registered={domain: True})
            self.assertEqual((rating.severity, rating.drop), (dd.ICE_SEVERITY, False), target)
            self.assertIn(f'{domain} is registered', rating.note)

    def test_a_target_at_a_claimable_provider_keeps_its_rating(self):
        rating = self.nx('old-app.azurewebsites.net')
        self.assertIsNone(rating.severity)
        self.assertIn('Microsoft Azure', rating.note)

    def test_a_target_whose_domain_is_unregistered_keeps_its_rating(self):
        rating = self.nx('www.lapsed-example.net', registered={'lapsed-example.net': False})
        self.assertIsNone(rating.severity)
        self.assertIn('not registered', rating.note)

    def test_unknown_registration_changes_nothing(self):
        self.assertIsNone(self.nx('www.example.net'))

    def http(self, chain, answer):
        net = FakeDns({}, {}, http=answer)
        return assess('email.mail.example.com', dd.KIND_HTTP, chain, net), net

    def test_a_mailgun_404_that_a_random_host_name_also_gets_is_dropped(self):
        body = b'404 page not found\n'
        rating, net = self.http(['mailgun.org'], ((404, body), (404, body), 'cvengine-control-ab12.email.mail.example.com'))
        self.assertTrue(rating.drop)
        self.assertEqual(net.http_calls, ['email.mail.example.com'])
        self.assertIn('random host name', rating.note)

    def test_the_host_name_echoed_in_a_page_does_not_make_it_different(self):
        control = 'cvengine-control-ab12.email.mail.example.com'
        rating, _net = self.http(['mailgun.org'], ((404, b'<p>No site at email.mail.example.com</p>'), (404, f'<p>No site at {control}</p>'.encode()), control))
        self.assertTrue(rating.drop)

    def test_a_host_specific_answer_keeps_the_finding(self):
        rating, _net = self.http(['mailgun.org'], ((404, b'Domain not configured: claim it'), (404, b'404 page not found'), 'cvengine-control-1.x'))
        self.assertIsNone(rating)
        self.assertIsNone(self.http(['mailgun.org'], None)[0])  # no answer: unchanged

    def test_a_claimable_provider_is_not_controlled(self):
        rating, net = self.http(['acme.github.io'], ((404, b'same'), (404, b'same'), 'c'))
        self.assertIsNone(rating)
        self.assertEqual(net.http_calls, [])


SCOPE = {'hosts': ['dev.d.example.com', 'pda.example.com'], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False, 'addresses': [], 'blocked': []}
PROVIDER_DOC = {'cname': [{'service': 'GitHub Pages', 'suffixes': ['github.io']}],
                'nameservers': [{'service': 'Google Cloud DNS', 'patterns': ['^ns-cloud-[a-z][0-9]+\\.googledomains\\.com$']}]}


class RunBatchTests(SimpleTestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def task(self, checks, **over):
        return {'checks': checks, 'providers': PROVIDER_DOC, 'scope': SCOPE, **over}

    def test_a_rated_check_and_an_unanswered_one_are_told_apart(self):
        zones, addresses = registry_and_client(client_children={'d.example.com': GCLOUD})
        net = FakeDns(zones, addresses)
        got = dd.run_batch(self.task([{'id': 'a', 'host': 'dev.d.example.com', 'kind': 'ns', 'triggers': GCLOUD},
                                      {'id': 'b', 'host': 'pda.example.com', 'kind': 'cname_nxdomain', 'triggers': ['www.example.net']}]), net=net)
        by_id = {r['id']: r for r in got['ratings']}
        self.assertEqual((by_id['a']['state'], by_id['a']['severity'], by_id['a']['drop'], by_id['a']['zone']), ('rated', dd.FIRE_SEVERITY, False, 'd.example.com'))
        self.assertEqual(by_id['b'], {'id': 'b', 'state': 'unknown'})  # registration could not be told

    def test_a_host_the_policy_does_not_list_is_never_asked_and_is_unknown(self):
        net = FakeDns({}, {})
        got = dd.run_batch(self.task([{'id': 'a', 'host': 'elsewhere.example.org', 'kind': 'ns', 'triggers': []}]), net=net)
        self.assertEqual(got['ratings'], [{'id': 'a', 'state': 'unknown'}])
        self.assertEqual((net.asked, got['refused']), ([], ['elsewhere.example.org']))

    def test_the_fixture_validates_and_runs(self):
        from cvengine_scanner.tests.test_contract import fixture, validator
        target = fixture('targets', 'dangling_dns_check')
        self.assertEqual(list(validator(contract.target_schema('dangling_dns_check')).iter_errors(target)), [])
        got = dd.run_batch(target, net=FakeDns({}, {}, registered={'example.net': True}))
        self.assertEqual(list(validator(contract.result_schema('dangling_dns_check')).iter_errors({'outcome': 'done', **got})), [])

    def test_a_malformed_task_is_refused(self):
        for bad in (self.task([{'id': 'a', 'host': 'x.example.com', 'kind': 'mx'}]), self.task([{'host': 'x.example.com', 'kind': 'ns'}]),
                    self.task([{'id': 'a', 'host': 'x.example.com', 'kind': 'ns'}] * 51), self.task([{'id': 'a', 'host': 'x.example.com', 'kind': 'ns'}], providers=None)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                dd.run_batch(bad, net=FakeDns({}, {}))


class NetTests(SimpleTestCase):
    """The real ``Net`` under a policy: it asks only addresses the policy and the floor allow."""

    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_server_at_a_private_or_loopback_address_is_never_asked(self):
        net = dd.Net(ScopePolicy(SCOPE))
        with mock.patch('dns.query.udp', side_effect=AssertionError('sent')):
            for address in ('10.0.0.1', '127.0.0.1', '169.254.169.254'):
                self.assertIsNone(net.ask(address, 'example.com', 'NS'))
        self.assertEqual(net.policy.refused, ['10.0.0.1', '127.0.0.1', '169.254.169.254'])

    def test_a_public_server_is_asked_without_recursion_and_recorded(self):
        import dns.flags
        import dns.message
        net = dd.Net(ScopePolicy(SCOPE))
        sent = []

        def udp(query, server, timeout):
            sent.append((query, server))
            return dns.message.from_text('id 1\nopcode QUERY\nrcode REFUSED\nflags QR\n;QUESTION\nexample.com. IN SOA\n')
        with mock.patch('dns.query.udp', udp):
            reply = net.ask('93.184.215.14', 'example.com', 'SOA')
        self.assertEqual(reply.rcode, 'REFUSED')
        self.assertFalse(sent[0][0].flags & dns.flags.RD)
        self.assertEqual(net.policy.touched, ['93.184.215.14'])

    def test_the_http_control_asks_only_a_host_the_policy_lists(self):
        net = dd.Net(ScopePolicy(SCOPE))
        with mock.patch('socket.getaddrinfo', side_effect=AssertionError('resolved')):
            self.assertIsNone(net.http_control('elsewhere.example.org'))
        self.assertEqual(net.policy.refused, ['elsewhere.example.org'])


if __name__ == '__main__':
    unittest.main()
