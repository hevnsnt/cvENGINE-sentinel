"""Ported from cvENGINE's web/tests/test_suppliers.py (its check tests, which need no database), run against the library copy, plus the tests of what is
new on a Sentinel: the policy at every address, the pace and budget, the batch and its result shape."""
import ipaddress
import json
import socket
from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest import mock

from jsonschema import Draft202012Validator

from cvengine_scanner import contract, versions
from cvengine_scanner.probes import http as web
from cvengine_scanner.probes import mail_checks, suppliers as ss, supplier_checks as sc, tls
from cvengine_scanner.probes.policy import ScopePolicy
from cvengine_scanner.probes.version_probes import challenge_of

PUBLIC = '203.0.113.10'
D = 'portal.vendor.test'
GOOD_HEADERS = {'strict-transport-security': 'max-age=31536000', 'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
                'x-content-type-options': 'nosniff'}
HTML = '<html><head><title>Vendor portal</title></head><body>Welcome</body></html>'
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


DOCUMENTATION = tuple(ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'))


class DocPolicy(ScopePolicy):
    """The real policy, except that documentation space (where the test data lives, and which the Sentinel's floor refuses like any reserved range)
    is treated as public. Everything else, private and loopback space included, is judged as it is."""

    def address_refusal(self, value, literal=False):
        ip = ipaddress.ip_address(str(value).strip('[]'))
        return '' if any(ip.version == net.version and ip in net for net in DOCUMENTATION) else super().address_refusal(value, literal)


def policy(*names, private=False):
    hosts = [h for n in names for h in (n, f'mta-sts.{n}')]
    return DocPolicy({'hosts': hosts, 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': private, 'addresses': [], 'blocked': []}, internal=False)


def page(status=200, body=HTML, server='nginx', powered_by='', headers=None, ctype='text/html', location='', **extra):
    """A response in the shape ``http.probe_url`` returns (and ``Network.fetch`` completes with the challenge)."""
    raw = {'content-type': ctype, **({'server': server} if server else {}), **({'x-powered-by': powered_by} if powered_by else {}), **(headers or {})}
    return {'status': status, 'location': location, 'www_authenticate': extra.get('www_authenticate', ''), 'cookies': extra.get('cookies', []),
            'content_type': ctype, 'body': body, 'title': web.page_title(body), 'bytes': len(body), 'server': server, 'powered_by': powered_by,
            'headers': versions.keep_headers(raw), 'raw_headers': raw}


def cert(name, days=200, **kw):
    return {'host': name, 'port': 443, 'subject': name, 'issuer': 'Example CA', 'sans': [name], 'not_before': NOW - timedelta(days=100),
            'not_after': NOW + timedelta(days=days), 'signature_algorithm': 'sha256 (sha256WithRSAEncryption)', 'key_description': 'RSA 2048',
            'protocol': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384', 'chain_error': '', 'legacy_tls': False, **kw}


class FakeNet:
    """The whole network of a supplier check: names, pages, certificates and DNS records, and a log of every call. Nothing leaves the process."""

    def __init__(self):
        self.ips, self.pages, self.certs, self.records_txt, self.mx, self.sts_policy, self.known = {}, {}, {}, {}, set(), {}, set()
        self.calls = []

    def site(self, name, ip=PUBLIC, https=None, http=None, tls='good', paths=None, mail=False, server='nginx', powered_by='', headers=None):
        self.ips[name] = [ip] if isinstance(ip, str) else ip
        self.known.add(name)
        self.pages[f'https://{name}/'] = https if https is not None else page(headers={**GOOD_HEADERS, **(headers or {})}, server=server, powered_by=powered_by)
        self.pages[f'http://{name}/'] = http if http is not None else page(301, '', location=f'https://{name}/')
        self.certs[name] = cert(name) if tls == 'good' else tls
        for path, response in (paths or {}).items():
            self.pages[f'https://{name}{path}'] = response
        if mail:
            self.good_mail(name)
        return self

    def good_mail(self, name):
        self.known.add(name)
        self.mx.add(name)
        self.records_txt[name] = ['v=spf1 include:_spf.mail.example.test -all']
        self.records_txt[f'_dmarc.{name}'] = ['v=DMARC1; p=reject; rua=mailto:dmarc@' + name]

    def resolve(self, name):
        self.calls.append(('resolve', name))
        if name in self.ips:
            return list(self.ips[name])
        raise socket.gaierror(socket.EAI_NONAME, 'not found')

    def fetch(self, url, ip):
        self.calls.append(('fetch', url, ip))
        got = self.pages.get(url, page(404, '<html><title>Not found</title></html>'))
        if isinstance(got, Exception):
            raise got
        return {**got, 'url': url, 'challenge': challenge_of(got)}

    def tls(self, name, addresses):
        self.calls.append(('tls', name, tuple(addresses)))
        got = self.certs.get(name)
        if isinstance(got, Exception):
            raise got
        return got

    def dns_state(self, name):
        return 'ok' if name in self.known else 'nxdomain'

    def txt(self, name):
        return list(self.records_txt.get(name, []))

    def records(self, name, rtype):
        return []

    def has_record(self, name, rtype):
        return rtype == 'MX' and name in self.mx

    def mta_sts_policy(self, domain, addresses):
        self.calls.append(('mta-sts', domain))
        return self.sts_policy.get(domain)

    @property
    def fetched(self):
        return [c[1] for c in self.calls if c[0] == 'fetch']


class Pace0:
    """No waiting, and a log."""

    def __init__(self):
        self.hosts = []

    def wait(self, host):
        self.hosts.append(host)


class CheckTests(TestCase):
    def setUp(self):
        self.net = FakeNet()
        self.policy = policy(D)

    def run_domain(self, domain=D, budget=1000, **kw):
        res = ss.check_domain(domain, self.net, Pace0(), ss.Budget(budget), self.policy, now=NOW, **kw)
        return res, {p.check: p for p in res.postures}

    def test_a_healthy_supplier_has_no_findings_and_a_full_card(self):
        self.net.site(D, server='nginx/1.25.3')
        res, found = self.run_domain()
        self.assertEqual(found, {})
        self.assertEqual((res.card['state'], res.card['addresses'], res.card['tls']['issuer'], res.card['http']['https_status']), ('ok', [PUBLIC], 'Example CA', 200))
        self.assertTrue(res.answered)
        self.assertEqual(res.summary, {'address': 'ok'})

    def test_an_expired_certificate_is_critical_and_one_that_expires_soon_is_not(self):
        self.net.site(D, tls=cert(D, days=-3))
        _, found = self.run_domain()
        self.assertEqual((found['tls_expired'].severity, found['tls_expired'].category), (sc.CRITICAL, 'tls'))
        self.assertIn('renew', found['tls_expired'].ask)
        self.net.site(D, tls=cert(D, days=20))
        _, found = self.run_domain()
        self.assertEqual(found['tls_expiring'].severity, sc.MEDIUM)

    def test_a_certificate_for_another_name_a_weak_key_and_old_protocols_are_findings(self):
        self.net.site(D, tls=cert(D, sans=['other.test'], subject='other.test', key_description='RSA 1024', legacy_tls=True,
                                  signature_algorithm='sha1 (sha1WithRSAEncryption)', chain_error='self-signed certificate'))
        _, found = self.run_domain()
        self.assertEqual({'tls_hostname_mismatch', 'tls_weak_key', 'tls_weak_signature', 'tls_legacy_protocol', 'tls_self_signed'}, set(found))

    def test_the_tls_read_goes_only_to_the_vetted_address_on_port_443(self):
        self.net.site(D)
        self.run_domain()
        self.assertEqual([c for c in self.net.calls if c[0] == 'tls'], [('tls', D, (PUBLIC,))])
        self.assertEqual(ss.numeric_addresses([PUBLIC, '2001:db8::1']), ((socket.AF_INET, (PUBLIC, 443)), (socket.AF_INET6, ('2001:db8::1', 443, 0, 0))))

    def test_a_certificate_that_could_not_be_read_decides_nothing(self):
        self.net.site(D, tls=None)
        res, _ = self.run_domain()
        self.assertNotIn('tls', res.resolvable)
        self.assertNotIn('tls', res.card)
        self.net.site(D, tls=ValueError('unparseable'))
        res, _ = self.run_domain()
        self.assertNotIn('tls', res.resolvable)

    def test_a_mail_domain_without_spf_dmarc_or_mta_sts_is_reported(self):
        self.net.site(D)
        self.net.mx.add(D)
        res, found = self.run_domain()
        self.assertEqual((found['spf_missing'].severity, found['dmarc_missing'].severity, found['mta_sts_missing'].severity), (sc.MEDIUM, sc.HIGH, sc.LOW))
        self.assertEqual(res.resolvable['email'], {''})
        self.assertEqual(res.card['mail'], {'handles_mail': True, 'mx': True})

    def test_weak_spf_dmarc_dkim_and_a_testing_mta_sts_policy(self):
        self.net.site(D)
        self.net.mx.add(D)
        self.net.records_txt[D] = ['v=spf1 +all']
        self.net.records_txt[f'_dmarc.{D}'] = ['v=DMARC1; p=none']
        self.net.records_txt[f'_mta-sts.{D}'] = ['v=STSv1; id=1']
        self.net.ips[f'mta-sts.{D}'] = [PUBLIC]
        self.net.sts_policy[D] = 'version: STSv1\nmode: testing\nmx: mail.vendor.test\nmax_age: 86400'
        _, found = self.run_domain()
        self.assertEqual((found['spf_allow_all'].severity, found['dmarc_none'].severity, found['mta_sts_not_enforced'].severity), (sc.CRITICAL, sc.MEDIUM, sc.MEDIUM))
        self.assertNotIn('mta_sts_missing', found)
        self.assertIn(('mta-sts', D), self.net.calls)

    def test_a_clean_mail_domain_has_no_email_findings(self):
        self.net.site(D, mail=True)
        self.net.records_txt[f'_mta-sts.{D}'] = ['v=STSv1; id=1']
        self.net.ips[f'mta-sts.{D}'] = [PUBLIC]
        self.net.sts_policy[D] = 'version: STSv1\nmode: enforce\nmx: mail.vendor.test\nmax_age: 604800'
        _, found = self.run_domain()
        self.assertEqual([k for k, p in found.items() if p.category == 'email' and k.split('_')[0] in ('spf', 'dmarc', 'mta')], [])

    def test_the_mta_sts_policy_host_is_vetted_like_every_other_connection(self):
        self.net.site(D)
        self.net.mx.add(D)
        self.net.records_txt[f'_mta-sts.{D}'] = ['v=STSv1; id=1']
        self.net.ips[f'mta-sts.{D}'] = ['10.1.2.3']
        _, found = self.run_domain()
        self.assertNotIn(('mta-sts', D), self.net.calls)
        self.assertIn('mta_sts_policy_unreachable', found)

    def test_dns_that_fails_on_the_way_makes_the_email_review_inconclusive(self):
        self.net.site(D)
        self.net.mx.add(D)
        states = iter(['ok', 'unknown'])
        self.net.dns_state = lambda name: next(states, 'unknown')
        res, found = self.run_domain()
        self.assertNotIn('email', res.resolvable)
        self.assertEqual([k for k in found if k.startswith(('spf', 'dmarc', 'mta'))], [])
        self.assertEqual(res.card['evidence']['dns'], 'unknown')

    def test_a_name_that_handles_no_mail_gets_no_email_findings(self):
        self.net.site(D)
        res, found = self.run_domain()
        self.assertEqual([k for k in found if k.startswith(('spf', 'dmarc', 'mta'))], [])
        self.assertEqual(res.card['mail'], {'handles_mail': False, 'mx': False})

    def test_a_mail_only_name_with_no_address_is_still_reviewed_and_never_contacted(self):
        self.net.known.add(D)
        self.net.mx.add(D)
        res, found = self.run_domain()
        self.assertIn('spf_missing', found)
        self.assertEqual(res.card['state'], 'no_address')
        self.assertEqual(res.summary['address'], 'none')
        self.assertEqual([c for c in self.net.calls if c[0] in ('fetch', 'tls', 'mta-sts')], [])

    def test_missing_security_headers_and_plain_http_are_findings(self):
        self.net.site(D, https=page(headers={}), http=page(200))
        _, found = self.run_domain()
        self.assertEqual(found['hsts_missing'].severity, sc.MEDIUM)
        self.assertEqual(found['security_headers_missing'].evidence['missing'], ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options'])
        self.assertEqual(found['http_no_redirect'].severity, sc.MEDIUM)
        self.net.site(D, https=page(headers={**GOOD_HEADERS, 'strict-transport-security': 'max-age=300'}))
        _, found = self.run_domain()
        self.assertEqual(found['hsts_weak'].severity, sc.LOW)
        self.assertNotIn('hsts_missing', found)

    def test_a_site_that_answers_only_over_plain_http_is_high(self):
        self.net.site(D, https=OSError('refused'), http=page(200), tls=None)
        _, found = self.run_domain()
        self.assertEqual(found['no_https'].severity, sc.HIGH)

    def test_a_listed_admin_page_is_reported_once_with_one_plain_get_per_path(self):
        phpmyadmin = page(200, '<html><title>phpMyAdmin</title><body>phpMyAdmin login</body></html>')
        self.net.site(D, paths={'/phpmyadmin/': phpmyadmin, '/manager/html': page(401, '', www_authenticate='Basic realm="Tomcat Manager Application"'),
                                '/login': page(200, '<title>Sign in [Jenkins]</title>')})
        _, found = self.run_domain()
        self.assertEqual((found['exposed_phpmyadmin'].severity, found['exposed_tomcat_manager'].severity, found['exposed_login_jenkins'].severity),
                         (sc.MEDIUM, sc.MEDIUM, sc.MEDIUM))
        paths = [u for u in self.net.fetched if u.startswith(f'https://{D}/') and u != f'https://{D}/']
        self.assertEqual(sorted(paths), sorted(f'https://{D}{p}' for p in sc.PATHS))  # each path asked exactly once, from the fixed list
        self.assertEqual(len(sc.PATHS), len(set(sc.PATHS)))
        self.assertLessEqual(len(sc.PATHS), 12)

    def test_a_catch_all_that_answers_200_to_everything_is_not_a_finding(self):
        catch_all = page(200, HTML + '<input type="password">')
        self.net.site(D, https=page(200, HTML + '<input type="password">', headers=GOOD_HEADERS))
        for path in sc.PATHS:
            self.net.pages[f'https://{D}{path}'] = catch_all
        _, found = self.run_domain()
        self.assertEqual([k for k in found if k.startswith('exposed_')], [])
        self.net.pages[f'https://{D}/admin/'] = page(200, '<html><title>Admin sign in</title><form><input type="password"></form></html>')
        _, found = self.run_domain()
        self.assertEqual(found['exposed_admin'].severity, sc.LOW)

    def test_a_path_that_does_not_answer_decides_nothing_and_a_404_resolves(self):
        self.net.site(D, paths={'/phpmyadmin/': OSError('timed out')})
        res, _ = self.run_domain()
        self.assertNotIn('exposed_phpmyadmin', res.resolvable['exposed'])
        self.assertIn('exposed_solr', res.resolvable['exposed'])

    def test_an_edge_that_challenges_the_request_is_recorded_and_nothing_more_is_asked(self):
        challenge = page(403, '<html><title>Just a moment...</title>cloudflare</html>', server='cloudflare', headers={'cf-mitigated': 'challenge'})
        self.net.site(D, https=challenge)
        res, found = self.run_domain()
        self.assertEqual((res.card['state'], res.card['evidence']['challenged']), ('challenged', 'Cloudflare'))
        self.assertEqual([k for k in found if k.startswith(('exposed_', 'cve_', 'security_headers'))], [])
        self.assertEqual([u for u in self.net.fetched if u.count('/') > 3], [])  # no path was asked
        self.assertEqual(res.fingerprints, [])

    def test_the_front_page_fingerprints_the_edge_and_the_distribution_are_reported_for_the_servers_catalog_match(self):
        self.net.site(D, https=page(headers=GOOD_HEADERS, server='nginx/1.18.0 (Ubuntu)', powered_by='PHP/7.4.3',
                                    body='<html><head><title>Vendor portal</title><meta name="generator" content="WordPress 6.2.1"></head><body></body></html>'))
        res, found = self.run_domain()
        names = {f['name']: f['source'] for f in res.fingerprints}
        self.assertEqual((names['nginx:1.18.0'], names['PHP:7.4.3'], names['WordPress:6.2.1']), ('header:server', 'header:x-powered-by', 'meta:generator'))
        self.assertEqual((res.edges, res.distro, res.resolvable['cve']), ([], 'ubuntu', {'cve_'}))
        self.assertEqual([k for k in found if k.startswith('cve_')], [])  # the catalog is the server's: the Sentinel decides no CVE finding
        self.assertEqual(res.card['http']['headers']['x-powered-by'], 'PHP/7.4.3')
        self.assertEqual(res.card['http']['cookies'], [])

    def test_an_edge_in_front_is_named_and_the_cve_category_is_not_decidable(self):
        self.net.site(D, https=page(headers={**GOOD_HEADERS, 'cf-ray': 'abc-AMS', 'server': 'cloudflare'}, server='cloudflare'))
        res, _ = self.run_domain()
        self.assertTrue(res.edges)
        self.assertNotIn('cve', res.resolvable)

    # --- the address gate and the budget
    def test_a_name_that_resolves_to_a_private_or_loopback_address_is_not_contacted_whatever_the_server_allows(self):
        for ip in ('10.1.2.3', '127.0.0.1', '169.254.169.254', '192.168.1.1', '100.64.0.1', '::1', 'fd00::1'):
            net = self.net = FakeNet()
            net.site(D, ip=ip)
            res, found = self.run_domain()
            self.assertEqual((res.summary['address'], res.card['state']), ('blocked', 'blocked'), ip)
            self.assertEqual([c for c in net.calls if c[0] in ('fetch', 'tls', 'mta-sts')], [], ip)
            self.assertFalse(res.answered)
        net = self.net = FakeNet()
        net.site(D, ip=[PUBLIC, '10.0.0.5'])  # one private address refuses the whole name
        res, _ = self.run_domain()
        self.assertEqual(res.summary['address'], 'blocked')
        self.policy = policy(D, private=True)  # the server's lab setting: a supplier's policy never carries it, but a Sentinel judges only what it is told
        self.assertEqual(ss.public_addresses(D, self.net, policy(D))[1], 'blocked')

    def test_the_lookup_outcomes(self):
        net = FakeNet()
        self.assertEqual(ss.public_addresses('nope.vendor.test', net, self.policy), ([], 'none'))
        net.resolve = mock.Mock(side_effect=socket.gaierror(socket.EAI_AGAIN, 'try again'))
        self.assertEqual(ss.public_addresses(D, net, self.policy), ([], 'unknown'))
        net.resolve = mock.Mock(side_effect=OSError('x'))
        self.assertEqual(ss.public_addresses(D, net, self.policy), ([], 'unknown'))
        net.resolve = mock.Mock(return_value=['2001:db8::1', PUBLIC, PUBLIC])
        self.assertEqual(ss.public_addresses(D, net, DocPolicy({'hosts': [D]}, internal=False)), ([PUBLIC, '2001:db8::1'], 'ok'))
        self.assertEqual(ss.public_addresses(D, net, ScopePolicy({'hosts': [D]}, internal=False)), ([], 'blocked'))  # the real floor refuses documentation space

    def test_a_name_that_does_not_fit_the_budget_is_partial_and_asks_nothing_it_cannot_finish(self):
        self.net.site(D)
        res, _ = self.run_domain(budget=ss.TLS_COST + 2)
        self.assertTrue(res.partial)
        self.assertFalse(res.stopped)
        self.assertLessEqual(res.requests, ss.TLS_COST + 2)
        self.assertEqual(len(self.net.fetched), 2)

    def test_a_stopped_task_asks_nothing_more_and_is_reported_stopped(self):
        self.net.site(D)
        calls = iter([False, False, True])
        res, _ = self.run_domain(stop=lambda: next(calls, True))
        self.assertTrue(res.stopped)
        self.assertEqual(self.net.fetched, [])

    def test_a_busy_answer_stops_the_name_for_this_task(self):
        self.net.site(D, https=page(503, '<html>try later</html>', headers={}))
        res, _ = self.run_domain()
        self.assertTrue(res.partial)
        self.assertFalse(res.stopped)

    def test_every_request_is_a_get_of_the_front_page_or_a_listed_path_at_the_vetted_address(self):
        self.net.site(D)
        self.run_domain()
        for call in self.net.calls:
            if call[0] == 'fetch':
                self.assertEqual(call[2], PUBLIC)
                self.assertTrue(call[1].startswith((f'https://{D}', f'http://{D}')))
                self.assertIn(call[1].split(D, 1)[1], ('/', *sc.PATHS))

    def test_the_pace_is_asked_before_every_request(self):
        self.net.site(D)
        pace = Pace0()
        ss.check_domain(D, self.net, pace, ss.Budget(1000), self.policy, now=NOW)
        self.assertEqual(len(pace.hosts), 1 + 2 + len(sc.PATHS))  # the certificate, the front page twice, each path once
        self.assertEqual(set(pace.hosts), {D})


class PaceTests(TestCase):
    def test_the_gap_to_one_host_and_the_gap_to_any_host(self):
        now, slept = [100.0], []
        pace = ss.Pace(gap=1.0, host_gap=2.0, sleep=lambda s: (slept.append(round(s, 3)), now.__setitem__(0, now[0] + s)), clock=lambda: now[0])
        pace.wait('a.vendor.test')
        pace.wait('a.vendor.test')
        pace.wait('b.vendor.test')
        self.assertEqual(slept, [2.0, 1.0])
        now[0] += 5
        pace.wait('a.vendor.test')
        self.assertEqual(slept, [2.0, 1.0])
        self.assertEqual(pace.requests, 4)


# ----------------------------------------------------------------------------- the pure evaluators

class PureTests(TestCase):
    def test_the_posture_text_is_the_servers_to_write_so_the_result_never_carries_it(self):
        p = sc.Posture('hsts_missing', 2, 't', 'd', 'web', D, ask='ask', evidence={'a': 1})
        doc = ss.posture_doc(p)
        self.assertEqual(set(doc), {'check', 'severity', 'title', 'detail', 'category', 'evidence'})
        self.assertNotIn('ask', doc)

    def test_the_hsts_age_and_levels(self):
        self.assertEqual(sc.hsts_max_age('max-age=31536000; includeSubDomains'), 31536000)
        self.assertIsNone(sc.hsts_max_age('includeSubDomains'))
        self.assertEqual(sc.level(9), 'critical')

    def test_a_certificate_is_judged_the_way_owned_hosts_are(self):
        found = {f.check for f in tls.evaluate_cert({**cert(D, days=3), 'sans': ['x.test'], 'subject': 'x.test'}, now=NOW)}
        self.assertEqual(found, {'tls_expiring', 'tls_hostname_mismatch'})
        clipped = tls.clip_certificate({**cert(D), 'subject': 's' * 900, 'sans': ['n' * 900] * 500})
        self.assertEqual((len(clipped['subject']), len(clipped['sans']), len(clipped['sans'][0])), (500, 200, 255))

    def test_email_findings_over_injected_dns(self):
        txt = {'example.com': ['v=spf1 +all'], '_dmarc.example.com': ['v=DMARC1; p=none']}
        found, has_mx = mail_checks.email_findings('example.com', fetch=lambda n: txt.get(n, []), mx=lambda n, t: t == 'MX', records=lambda n, t: [])
        self.assertTrue(has_mx)
        self.assertTrue({'spf_allow_all', 'dmarc_none'} <= {f.check for f in found})

    def test_a_subdomain_inherits_the_organizational_dmarc_policy(self):
        txt = {'_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:r@example.com']}
        found, _ = mail_checks.email_findings('mail.example.com', fetch=lambda n: txt.get(n, []), mx=lambda n, t: t == 'MX', records=lambda n, t: [])
        checks = {f.check: f for f in found}
        self.assertNotIn('dmarc_missing', checks)
        self.assertEqual(checks['spf_missing'].severity, 0)  # DMARC p=reject already applies to this name

    def test_the_catch_all_comparison(self):
        a = sc.fingerprint_of(page(200, HTML))
        self.assertTrue(sc.similar(a, sc.fingerprint_of(page(200, HTML + ' '))))
        self.assertFalse(sc.similar(a, sc.fingerprint_of(page(200, '<title>Other</title>'))))
        r1, r2 = sc.fingerprint_of(page(301, '', location='https://x.test/a')), sc.fingerprint_of(page(302, '', location='https://y.test/a'))
        self.assertTrue(sc.similar(r1, r2))


# ----------------------------------------------------------------------------- the real network, with the transport replaced

class NetworkTests(TestCase):
    def test_a_fetch_goes_through_the_policy_to_the_vetted_address_and_says_which_edge_challenged_it(self):
        pol = policy(D)
        answer = page(403, '<html><title>Just a moment...</title>cloudflare</html>', headers={'cf-mitigated': 'challenge'})
        with mock.patch.object(web, 'probe_url', return_value=answer) as probe:
            got = ss.Network(pol).fetch(f'https://{D}/', PUBLIC)
        probe.assert_called_once_with(f'https://{D}/', pol, max_bytes=64 * 1024, connect_ip=PUBLIC)
        self.assertEqual(got['challenge'], 'Cloudflare')

    def test_a_name_outside_the_policy_is_never_resolved(self):
        with mock.patch('socket.getaddrinfo') as lookup:
            with self.assertRaises(ValueError):
                ss.Network(policy(D)).resolve('other.vendor.test')
        lookup.assert_not_called()

    def test_the_tls_read_asks_the_pinned_transport_for_the_vetted_numeric_addresses(self):
        pol = policy(D)
        with mock.patch.object(tls, 'probe_tls', return_value=None) as probe:
            ss.Network(pol).tls(D, [PUBLIC])
        probe.assert_called_once_with(D, 443, pol, ((socket.AF_INET, (PUBLIC, 443)),))


# ----------------------------------------------------------------------------- the supplier_check kind

def target(domains=(D,), **kw):
    return {'domains': list(domains), 'pace': {'gap': 1.0, 'host_gap': 2.0}, 'max_requests': 600,
            'scope': {'hosts': [h for n in domains for h in (n, f'mta-sts.{n}')], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False,
                      'addresses': [], 'blocked': []}, **kw}


def validator(half, kind):
    schema = contract.result_schema(kind) if half == 'results' else contract.target_schema(kind)
    return Draft202012Validator(schema)


class RunBatchTests(TestCase):
    def setUp(self):
        self.net = FakeNet()
        patch = mock.patch.object(ss, 'ScopePolicy', DocPolicy)  # the test data is in documentation space (see DocPolicy)
        patch.start()
        self.addCleanup(patch.stop)

    def run_batch(self, tgt=None, **kw):
        return ss.run_batch(tgt or target(), net=self.net, pace=Pace0(), now=NOW, **kw)

    def test_one_row_per_name_and_the_result_is_in_contract(self):
        self.net.site(D, server='nginx/1.18.0 (Ubuntu)', https=page(headers={}, server='nginx/1.18.0 (Ubuntu)'), tls=cert(D, days=12))
        out = self.run_batch()
        self.assertEqual(list(validator('results', 'supplier_check').iter_errors({'outcome': 'done', **out})), [])
        self.assertEqual(list(validator('targets', 'supplier_check').iter_errors(target())), [])
        (row,) = out['domains']
        self.assertEqual(row['domain'], D)
        self.assertEqual({p['check'] for p in row['postures']}, {'hsts_missing', 'security_headers_missing', 'tls_expiring'})
        self.assertEqual(row['card']['tls']['days_left'], 12)
        self.assertEqual(row['fingerprints'][0], {'name': 'nginx:1.18.0', 'source': 'header:server'})
        self.assertEqual((row['edges'], row['distro'], row['answered'], row['stopped'], row['partial']), ([], 'ubuntu', True, False, False))
        self.assertEqual(row['resolvable']['tls'], ['tls_'])
        self.assertGreater(row['requests'], 10)
        json.dumps(out)  # nothing but plain data

    def test_a_name_without_an_address_is_reported_as_it_is(self):
        out = self.run_batch(target(domains=[D, 'gone.vendor.test']))
        self.assertEqual([r['domain'] for r in out['domains']], [D, 'gone.vendor.test'])
        self.assertEqual({r['summary']['address'] for r in out['domains']}, {'none'})
        self.assertEqual(list(validator('results', 'supplier_check').iter_errors({'outcome': 'done', **out})), [])

    def test_a_name_the_policy_does_not_list_is_not_asked_and_has_no_row(self):
        self.net.site(D)
        self.net.site('other.vendor.test')
        tgt = target(domains=[D, 'other.vendor.test'])
        tgt['scope'] = {**tgt['scope'], 'hosts': [D, f'mta-sts.{D}']}
        out = self.run_batch(tgt)
        self.assertEqual([r['domain'] for r in out['domains']], [D])
        self.assertEqual(out['refused'], ['other.vendor.test'])
        self.assertNotIn('other.vendor.test', [c[1] for c in self.net.calls if c[0] == 'resolve'])

    def test_an_excluded_name_is_not_asked(self):
        self.net.site(D)
        tgt = target()
        tgt['scope'] = {**tgt['scope'], 'excluded': [D]}
        out = self.run_batch(tgt)
        self.assertEqual((out['domains'], out['refused']), ([], [D]))
        self.assertEqual(self.net.calls, [])

    def test_a_missing_or_malformed_policy_allows_nothing(self):
        self.net.site(D)
        out = self.run_batch({**target(), 'scope': None})
        self.assertEqual((out['domains'], self.net.calls), ([], []))

    def test_the_budget_ends_the_batch_after_the_name_that_ran_out(self):
        names = [D, 'two.vendor.test', 'three.vendor.test']
        for name in names:
            self.net.site(name)
        out = self.run_batch(target(domains=names, max_requests=ss.TLS_COST + 4))
        self.assertEqual([r['domain'] for r in out['domains']], [D])  # the rest are asked for again by the server
        self.assertTrue(out['domains'][0]['partial'])
        self.assertLessEqual(out['domains'][0]['requests'], ss.TLS_COST + 4)

    def test_the_clock_ends_the_batch(self):
        self.net.site(D)
        self.net.site('two.vendor.test')
        ticks = iter([0.0] + [ss.MAX_SECONDS + 1.0] * 50)
        out = ss.run_batch(target(domains=[D, 'two.vendor.test']), net=self.net, pace=Pace0(), now=NOW, clock=lambda: next(ticks))
        self.assertEqual(out['domains'], [])  # out of time before the first name: nothing asked, nothing claimed

    def test_what_is_not_a_plain_name_is_refused_before_anything_is_asked(self):
        for bad in ('203.0.113.10', '*.vendor.test', 'https://portal.vendor.test/', 'portal.vendor.test:443', 'user@vendor.test', 'a.localhost', 'x.internal',
                    'vendor', '', 5, None, 'two words.test', 'a/b.test'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ss.run_batch(target(domains=[bad]), net=self.net, pace=Pace0())
        with self.assertRaises(ValueError):
            ss.run_batch(target(domains=[f'n{i}.vendor.test' for i in range(26)]), net=self.net, pace=Pace0())
        with self.assertRaises(ValueError):
            ss.run_batch({'domains': [], 'scope': target()['scope']}, net=self.net, pace=Pace0())
        self.assertEqual(self.net.calls, [])

    def test_a_name_is_lowercased_and_asked_once(self):
        self.net.site(D)
        out = self.run_batch(target(domains=['PORTAL.Vendor.test.', D]))
        self.assertEqual([r['domain'] for r in out['domains']], [D])

    def test_the_pace_a_task_asks_for_is_never_below_a_polite_one(self):
        self.net.site(D)
        seen = {}
        real = ss.Pace

        class Spy(real):
            def __init__(self, gap, host_gap, **kw):
                seen.update(gap=gap, host_gap=host_gap)
                super().__init__(gap, host_gap, sleep=lambda s: None)

        with mock.patch.object(ss, 'Pace', Spy):
            ss.run_batch({**target(), 'pace': {'gap': 0, 'host_gap': 0}, 'max_requests': 10 ** 9}, net=self.net, now=NOW)
        self.assertEqual(seen, {'gap': ss.MIN_GAP, 'host_gap': ss.MIN_HOST_GAP})
        with mock.patch.object(ss, 'Pace', Spy):
            ss.run_batch({**target(), 'pace': 'fast'}, net=self.net, now=NOW)
        self.assertEqual(seen, {'gap': ss.DEFAULT_GAP, 'host_gap': ss.DEFAULT_HOST_GAP})

    def test_the_shipped_fixture_target_runs(self):
        fixture = json.loads((contract.FIXTURES / 'targets' / 'supplier_check.json').read_text(encoding='utf-8'))
        out = ss.run_batch(fixture, net=self.net, pace=Pace0(), now=NOW)
        self.assertEqual([r['domain'] for r in out['domains']], fixture['domains'])
