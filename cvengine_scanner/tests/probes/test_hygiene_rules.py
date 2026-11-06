"""The email authentication rules of the hygiene_check kind, ported from cvENGINE's web/tests/test_hygiene.py (SPF, DMARC, DKIM, CAA and the review's
orchestration) and web/tests/test_hygiene_mail.py (the MailFail rules): the library copy keeps the server's behaviour. No DNS or HTTP leaves a test."""
import base64
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cvengine_scanner.probes import hygiene as hy
from cvengine_scanner.probes import mailfail as mf
from cvengine_scanner.probes import rdap

SimpleTestCase = TestCase = unittest.TestCase


def checks(findings):
    return {f.check for f in findings}


def modulus(bits):
    return (1 << (bits - 1)) | 1  # any odd number of that size: only the size is read


def dkim_key(bits):
    key = rsa.RSAPublicNumbers(65537, modulus(bits)).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return 'v=DKIM1; k=rsa; p=' + base64.b64encode(der).decode()


def dnskey(algorithm, bits=2048, protocol=3):
    raw = bytes([3]) + (65537).to_bytes(3, 'big') + modulus(bits).to_bytes(bits // 8, 'big')
    return f'257 {protocol} {algorithm} {base64.b64encode(raw).decode()}'


class SpfTests(TestCase):
    def test_missing_depends_on_mail(self):
        self.assertEqual(hy.evaluate_spf('a.com', [], True)[0].severity, hy.MEDIUM)
        self.assertEqual(hy.evaluate_spf('a.com', [], False)[0].severity, hy.LOW)

    def test_policy_strength(self):
        self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 include:_spf.google.com -all'], True)), set())
        self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 mx +all'], True)), {'spf_allow_all'})
        self.assertEqual(hy.evaluate_spf('a.com', ['v=spf1 mx +all'], True)[0].severity, hy.CRITICAL)
        self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 mx ?all'], True)), {'spf_neutral'})
        self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 mx ~all'], True)), {'spf_softfail'})
        self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 mx'], True)), {'spf_no_all'})
        self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 redirect=_spf.example.com'], True)), set())  # redirect closes it
        self.assertIn('spf_ptr', checks(hy.evaluate_spf('a.com', ['v=spf1 ptr -all'], True)))

    def test_multiple_records_and_lookup_limit(self):
        self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 -all', 'v=spf1 mx -all'], True)), {'spf_multiple'})
        self.assertIn('spf_too_many_lookups', checks(hy.evaluate_spf('a.com', ['v=spf1 -all'], True, lookup_count=11)))
        self.assertNotIn('spf_too_many_lookups', checks(hy.evaluate_spf('a.com', ['v=spf1 -all'], True, lookup_count=10)))

    def test_lookup_counting_follows_includes_without_looping(self):
        zone = {'a.com': ['v=spf1 include:b.com mx a -all'], 'b.com': ['v=spf1 include:a.com ip4:1.2.3.4 exists:x.b.com -all']}
        # include:b (1), b's include:a (1, then its terms are not walked again), exists (1), mx (1), a (1)
        self.assertEqual(hy.count_spf_lookups('a.com', lambda d: zone.get(d, [])), 5)


class DmarcTests(TestCase):
    def test_missing_none_and_reject(self):
        self.assertEqual(hy.evaluate_dmarc('a.com', [], True)[0].severity, hy.HIGH)
        self.assertEqual(hy.evaluate_dmarc('a.com', [], False)[0].severity, hy.LOW)
        self.assertEqual(checks(hy.evaluate_dmarc('a.com', ['v=DMARC1; p=none; rua=mailto:d@a.com'], True)), {'dmarc_none'})
        self.assertEqual(checks(hy.evaluate_dmarc('a.com', ['v=DMARC1; p=reject; rua=mailto:d@a.com'], True)), set())

    def test_details(self):
        r = hy.evaluate_dmarc('a.com', ['v=DMARC1; p=quarantine; pct=50; sp=none'], True)
        self.assertTrue({'dmarc_quarantine', 'dmarc_partial', 'dmarc_no_reports', 'dmarc_subdomain_weak'} <= checks(r))
        self.assertEqual(checks(hy.evaluate_dmarc('a.com', ['v=DMARC1; rua=mailto:x@a.com'], True)), {'dmarc_invalid'})
        self.assertEqual(checks(hy.evaluate_dmarc('a.com', ['v=DMARC1; p=none', 'v=DMARC1; p=reject'], True)), {'dmarc_multiple'})


class DkimCaaTests(TestCase):
    @staticmethod
    def rsa_record(bits):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        pub = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
        der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return f'v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}'

    def test_key_strength_and_revocation(self):
        self.assertEqual(hy.dkim_key_bits(self.rsa_record(2048)), 2048)
        self.assertEqual(checks(hy.evaluate_dkim('a.com', {'google': self.rsa_record(2048)}, True)), set())
        self.assertEqual(checks(hy.evaluate_dkim('a.com', {'s1': self.rsa_record(1024)}, True)), {'dkim_short_key'})
        self.assertEqual(checks(hy.evaluate_dkim('a.com', {'old': 'v=DKIM1; p='}, True)), {'dkim_not_found'})  # revoked = not present
        self.assertEqual(hy.evaluate_dkim('a.com', {'old': 'v=DKIM1; p='}, False), [])
        self.assertEqual(hy.dkim_key_bits('v=DKIM1; p=notbase64!!'), 0)

    def test_not_found_only_matters_for_mail_domains_and_is_informational(self):
        self.assertEqual(hy.evaluate_dkim('a.com', {}, False), [])
        f = hy.evaluate_dkim('a.com', {}, True)
        self.assertEqual((f[0].check, f[0].severity), ('dkim_not_found', hy.INFO))

    def test_caa(self):
        self.assertEqual(checks(hy.evaluate_caa('a.com', [])), {'caa_missing'})
        self.assertEqual(hy.evaluate_caa('a.com', ['0 issue "letsencrypt.org"']), [])

    def test_email_findings_orchestration_with_fake_dns(self):
        zone = {'a.com': ['v=spf1 mx ~all'], '_dmarc.a.com': ['v=DMARC1; p=none']}
        findings, has_mx = hy.email_findings('a.com', fetch=lambda n: zone.get(n, []), mx=lambda n, t: t == 'MX')
        self.assertTrue(has_mx)
        self.assertTrue({'spf_softfail', 'dmarc_none', 'dkim_not_found', 'caa_missing'} <= checks(findings))

    def test_a_subdomain_inherits_the_organizational_domains_dmarc_policy(self):
        """S08-7: RFC 7489 6.6.3, a name with no record of its own is held to the apex's (its sp for subdomains): no false HIGH."""
        zone = {'_dmarc.a.com': ['v=DMARC1; p=reject; rua=mailto:d@a.com']}
        fetch = lambda n: zone.get(n, [])
        findings, _ = hy.email_findings('mail.a.com', fetch=fetch, mx=lambda n, t: t == 'MX')
        self.assertNotIn('dmarc_missing', checks(findings))
        zone['_dmarc.a.com'] = ['v=DMARC1; p=reject; sp=none; rua=mailto:d@a.com']
        findings, _ = hy.email_findings('mail.a.com', fetch=fetch, mx=lambda n, t: t == 'MX')
        inherited = [f for f in findings if f.check == 'dmarc_subdomain_weak']
        # sp=none is the policy it has, and the cause is the apex's record: the apex's finding, naming the name it covers (1.3.5 item 20)
        self.assertEqual([(f.severity, f.host, f.evidence['inherited_from'], f.evidence['covers']) for f in inherited],
                         [(hy.MEDIUM, 'a.com', 'a.com', ['mail.a.com'])])
        self.assertTrue({'dmarc_none', 'dmarc_no_reports'}.isdisjoint(checks(findings)))  # the record's other details are the apex's own findings
        zone.clear()
        findings, _ = hy.email_findings('mail.a.com', fetch=fetch, mx=lambda n, t: t == 'MX')
        self.assertIn('dmarc_missing', checks(findings))  # neither the name nor its apex publishes one
        zone['_dmarc.mail.a.com'] = ['v=DMARC1; p=none']
        zone['_dmarc.a.com'] = ['v=DMARC1; p=reject']
        findings, _ = hy.email_findings('mail.a.com', fetch=fetch, mx=lambda n, t: t == 'MX')
        self.assertIn('dmarc_none', checks(findings))  # its own record wins over the apex's




class RecordRuleTests(SimpleTestCase):
    def test_every_finding_credits_mailfail(self):
        finding = mf.evaluate_mx('acme.example', ['acme-example.mail.protection.outlook.com.'])[0]
        self.assertIn('Black Hills Information Security', finding.evidence['credit'])
        self.assertIn('github.com/ACK-J/MailFail', finding.evidence['credit'])

    def test_spf(self):
        self.assertEqual(checks(mf.evaluate_spf('acme.example', ['include:_spf.example.com v=spf1 -all'])), {'spf_invalid_prefix'})
        self.assertEqual(checks(mf.evaluate_spf('acme.example', ['v=spf1 include:relay.mailchannels.net -all'])), {'spf_mailchannels'})
        self.assertEqual(mf.evaluate_spf('acme.example', ['v=spf1 -all']), [])
        self.assertEqual(mf.spf_referenced_domains(['v=spf1 include:_spf.example.com ~include:mail.acme-example.ai '
                                                    'include:%{d}.macro.example redirect=spf.example.org']),
                         ['_spf.example.com', 'mail.acme-example.ai', 'spf.example.org'])

    def test_dmarc(self):
        self.assertEqual(checks(mf.evaluate_dmarc('acme.example', ['p=reject; v=DMARC1'])), {'dmarc_invalid_prefix'})
        self.assertEqual(checks(mf.evaluate_dmarc('acme.example', ['v=DMARC1; p=reject; rua=reports@example.com; ruf=mailto:f@example.com'])),
                         {'dmarc_rua_malformed'})
        self.assertEqual(checks(mf.evaluate_dmarc('acme.example', ['v=DMARC1; p=reject; rua=mailto:r@acme.example; fo=1'])),
                         {'dmarc_fo_without_ruf'})
        self.assertEqual(mf.evaluate_dmarc('acme.example', ['v=DMARC1; p=reject; rua=mailto:r@acme.example']), [])
        self.assertEqual(mf.dmarc_report_domains(['v=DMARC1; p=reject; rua=mailto:a@Reports.Example.com!10m,mailto:b@acme.example; '
                                                  'ruf=mailto:c@reports.example.com']), ['reports.example.com', 'acme.example'])

    def test_report_authorization(self):
        self.assertEqual(checks(mf.evaluate_report_authorization('acme.example', 'example.com', [])), {'dmarc_report_unauthorized'})
        self.assertEqual(mf.evaluate_report_authorization('acme.example', 'example.com', ['v=DMARC1']), [])

    def test_dkim(self):
        key = dkim_key(2048)
        self.assertEqual(checks(mf.evaluate_dkim('acme.example', {'s1': key + '; t=y'})), {'dkim_testing_mode'})
        self.assertEqual(checks(mf.evaluate_dkim('acme.example', {'s1': key + '; h=sha1'})), {'dkim_sha1'})
        self.assertEqual(mf.evaluate_dkim('acme.example', {'s1': key + '; h=sha1:sha256'}), [])
        self.assertEqual(checks(mf.evaluate_dkim('acme.example', {'s1': 'v=DKIM1; k=rsa; p=bm90IGEga2V5'})), {'dkim_invalid_key'})
        self.assertEqual(mf.evaluate_dkim('acme.example', {'s1': 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='}), [])
        self.assertEqual(mf.evaluate_dkim('acme.example', {'s1': 'v=DKIM1; p='}), [])  # revoked

    def test_arc(self):
        self.assertEqual(checks(mf.evaluate_arc('acme.example', {'arc': dkim_key(512)})), {'arc_weak_key'})
        self.assertEqual(checks(mf.evaluate_arc('acme.example', {'arc': dkim_key(1024)})), {'arc_short_key'})
        self.assertEqual(mf.evaluate_arc('acme.example', {'arc': dkim_key(2048)}), [])

    def test_adsp_bimi_mailchannels(self):
        self.assertEqual(checks(mf.evaluate_adsp('acme.example', ['dkim=all'])), {'adsp_present'})
        self.assertEqual(mf.evaluate_adsp('acme.example', []), [])
        self.assertEqual(checks(mf.evaluate_bimi('acme.example', ['l=https://acme.example/logo.svg; v=BIMI1'])), {'bimi_invalid'})
        self.assertEqual(checks(mf.evaluate_bimi('acme.example', ['v=BIMI1; l=https://acme.example/logo.png; a=http://acme.example/vmc.pem'])),
                         {'bimi_logo_invalid', 'bimi_vmc_invalid'})
        self.assertEqual(mf.evaluate_bimi('acme.example', ['v=BIMI1; l=https://acme.example/logo.svg; a=https://acme.example/vmc.pem']), [])
        self.assertEqual(checks(mf.evaluate_mailchannels('acme.example', ['v=mc1 cfid=acme.example.workers.dev'])),
                         {'mailchannels_shared_relay'})
        self.assertEqual(mf.evaluate_mailchannels('acme.example', ['v=mc1 auth=myaccountid']), [])

    def test_microsoft_direct_send_is_read_from_mx_only(self):
        finding = mf.evaluate_mx('acme.example', ['acme-example.mail.protection.outlook.com.'])[0]
        self.assertEqual((finding.check, finding.severity), ('mx_direct_send', hy.MEDIUM))
        self.assertIn('RejectDirectSend', finding.detail)
        self.assertEqual(finding.evidence['reference'], mf.DIRECT_SEND_REFERENCE)
        self.assertEqual(mf.evaluate_mx('acme.example', ['mx1.example.com.']), [])

    def test_mta_sts(self):
        self.assertEqual(checks(mf.evaluate_mta_sts('acme.example', [], None, has_mx=True)), {'mta_sts_missing'})
        self.assertEqual(mf.evaluate_mta_sts('acme.example', [], None, has_mx=False), [])
        self.assertEqual(checks(mf.evaluate_mta_sts('acme.example', ['id=1; v=STSv1'], None, True)), {'mta_sts_invalid'})
        self.assertEqual(checks(mf.evaluate_mta_sts('acme.example', ['v=STSv1; id=1'], None, True)), {'mta_sts_policy_unreachable'})
        self.assertEqual(mf.evaluate_mta_sts('acme.example', ['v=STSv1; id=1'], None, True, policy_checked=False), [])
        policy = 'version: STSv1\nmode: testing\nmx: mx.acme.example\nmax_age: 86400\n'
        self.assertEqual(checks(mf.evaluate_mta_sts('acme.example', ['v=STSv1; id=1'], policy, True)), {'mta_sts_not_enforced'})
        self.assertEqual(mf.evaluate_mta_sts('acme.example', ['v=STSv1; id=1'], policy.replace('testing', 'enforce'), True), [])

    def test_tls_reporting(self):
        self.assertEqual(checks(mf.evaluate_tls_reporting('acme.example', [], True)), {'smtp_tlsrpt_missing'})
        self.assertEqual(checks(mf.evaluate_tls_reporting('acme.example', ['v=TLSRPTv1; rua=http://acme.example/r'], True)),
                         {'smtp_tlsrpt_invalid'})
        self.assertEqual(checks(mf.evaluate_tls_reporting('acme.example', ['rua=mailto:r@acme.example; v=TLSRPTv1'], True)),
                         {'smtp_tlsrpt_invalid'})
        self.assertEqual(mf.evaluate_tls_reporting('acme.example', ['v=TLSRPTv1; rua=mailto:r@acme.example,https://r.acme.example/'], True), [])

    def test_dane(self):
        bad = mf.evaluate_dane('acme.example', {'mx.acme.example': ['1 1 1 ab12', '3 0 1 cd34', '3 1 2 ef56']})
        self.assertEqual(checks(bad), {'dane_misconfigured'})
        self.assertIn('usage 1', bad[0].detail)
        self.assertIn('selector 0', bad[0].detail)
        self.assertEqual(mf.evaluate_dane('acme.example', {'mx.acme.example': ['3 1 1 ab12', '2 0 1 cd34']}), [])

    def test_dnssec(self):
        self.assertEqual(mf.rsa_key_bits(dnskey(8, 2048).split()[3]), 2048)
        self.assertEqual(checks(mf.evaluate_dnssec('acme.example', [dnskey(5)])), {'dnssec_weak_algorithm'})
        self.assertEqual(checks(mf.evaluate_dnssec('acme.example', [dnskey(8, bits=512)])), {'dnssec_weak_key'})
        self.assertEqual(checks(mf.evaluate_dnssec('acme.example', [dnskey(8, protocol=2)])), {'dnssec_invalid_protocol'})
        self.assertEqual(mf.evaluate_dnssec('acme.example', [dnskey(8), '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==']), [])



class TakeoverTests(SimpleTestCase):
    def test_only_unregistered_third_party_domains_count(self):
        asked = []

        def registered(name):
            asked.append(name)
            return {'gone-example.com': False, 'unknown-example.com': None}.get(name, True)
        names = ['_spf.gone-example.com', 'mail.acme.example', 'x.unknown-example.com', 'spf.live-example.com', 'ns-example.com']
        out = mf.unregistered_domains(names, 'acme.example', has_ns=lambda name: name == 'ns-example.com', registered=registered)
        self.assertEqual(out, ['gone-example.com'])
        self.assertNotIn('acme.example', asked)  # the target's own domain is never asked about
        self.assertNotIn('ns-example.com', asked)  # name servers mean registered
        self.assertEqual(checks(mf.evaluate_takeover('acme.example', out, ['gone-example.com'])),
                         {'spf_include_registerable', 'dmarc_report_domain_registerable'})


class EmailReviewTests(SimpleTestCase):
    def test_injected_dns_runs_the_mailfail_checks_without_any_outbound_request(self):
        zone = {'acme.example': ['v=spf1 include:_spf.example.com -all'], '_dmarc.acme.example': ['v=DMARC1; p=reject; rua=mailto:r@reports.example.com'],
                'default._bimi.acme.example': ['v=BIMI1; l=http://acme.example/logo.png'], '_mta-sts.acme.example': ['v=STSv1; id=1'],
                'selector1._domainkey.acme.example': [dkim_key(2048) + '; t=y']}
        with mock.patch('cvengine_scanner.probes.transport.resolve', side_effect=AssertionError('no HTTP')), \
                mock.patch('cvengine_scanner.probes.rdap.get_https', side_effect=AssertionError('no RDAP')):
            findings, has_mx = hy.email_findings('acme.example', fetch=lambda n: zone.get(n, []), mx=lambda n, t: t == 'MX')
        found = checks(findings)
        self.assertTrue(has_mx)
        self.assertTrue({'dkim_testing_mode', 'bimi_logo_invalid', 'dmarc_report_unauthorized', 'smtp_tlsrpt_missing'} <= found)
        self.assertTrue({'spf_softfail', 'dmarc_quarantine'}.isdisjoint(found))  # the established checks still run unchanged
        self.assertNotIn('mta_sts_policy_unreachable', found)  # the policy file is not fetched with injected DNS

    def test_mx_dane_and_dnssec_use_the_records_reader(self):
        def records(name, rtype):
            return {('acme.example', 'MX'): ['10 acme-example.mail.protection.outlook.com.'],
                    ('_25._tcp.acme-example.mail.protection.outlook.com', 'TLSA'): ['1 1 1 ab12'],
                    ('acme.example', 'DNSKEY'): [dnskey(5)]}.get((name, rtype), [])
        findings, _ = hy.email_findings('acme.example', fetch=lambda n: [], mx=lambda n, t: t == 'MX', records=records)
        self.assertTrue({'mx_direct_send', 'dane_misconfigured', 'dnssec_weak_algorithm'} <= checks(findings))

    def test_a_failing_mailfail_check_never_breaks_the_review(self):
        with mock.patch('cvengine_scanner.probes.mailfail.evaluate_bimi', side_effect=RuntimeError('boom')):
            findings, _ = hy.email_findings('acme.example', fetch=lambda n: [], mx=lambda n, t: t == 'MX')
        self.assertIn('spf_missing', checks(findings))

    def test_a_missing_record_is_confirmed_by_the_resolvers_the_task_carries(self):
        import dns.resolver

        class Nothing:
            """A resolver for which no name exists; remembers the servers it was pointed at."""
            pointed = []

            def __init__(self, configure=True):
                self.nameservers = []

            def __setattr__(self, key, value):
                if key == 'nameservers':
                    Nothing.pointed.append(value)
                super().__setattr__(key, value)

            def resolve(self, name, rtype):
                raise dns.resolver.NXDOMAIN()
        with mock.patch('dns.resolver.Resolver', Nothing):
            findings, _ = hy.email_findings('acme.example', confirm=['192.0.2.53'], rdap=False)
        self.assertIn(['192.0.2.53'], Nothing.pointed)
        missing = [f for f in findings if f.check == 'spf_missing'][0]
        self.assertIs(missing.evidence['dns_confirmed'], True)  # two resolvers agreed
        self.assertEqual([o['resolver'] for o in missing.evidence['dns']], ['system', '192.0.2.53'])

    def test_the_rdap_switch_and_a_scope_that_refuses_the_policy_host_are_honoured(self):
        zone = {'acme.example': ['v=spf1 include:_spf.gone-example.com -all']}
        policy = mock.Mock()
        policy.host_refusal.return_value = 'outside the scope policy'
        records = lambda name, rtype: [] if rtype != 'MX' else ['10 mx.acme.example.']  # noqa: E731
        with mock.patch.object(mf.rdap, 'registered', side_effect=AssertionError('no RDAP when it is off')), \
                mock.patch.object(mf, 'fetch_mta_sts_policy', side_effect=AssertionError('the policy host is refused')):
            zone['_mta-sts.acme.example'] = ['v=STSv1; id=1']
            out = mf.review('acme.example', True, zone['acme.example'], [], {}, lambda n: zone.get(n, []), records, http=True, scope=policy, rdap_on=False)
        self.assertNotIn('mta_sts_policy_unreachable', checks(out))  # not asked is not "unreachable"
