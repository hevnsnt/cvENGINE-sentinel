"""The Direct Send test (``probes.direct_send``): it asks the tenant over SMTP, stops before DATA, and only a clear answer counts. No network
leaves a test except the local fake SMTP server one test starts on 127.0.0.1."""
import socket
import threading
import unittest

from cvengine_scanner.probes import direct_send as ds
from cvengine_scanner.probes import mailfail as mf
from cvengine_scanner.probes.policy import ScopePolicy

MX = 'acme-example.mail.protection.outlook.com'


class FakeSMTP:
    """An smtplib-like object scripted per command; it records every call."""

    def __init__(self, mail=(250, b'2.1.0 Sender OK'), rcpt=None, greeting=(220, b'ready'), starttls=False, fail_on=None):
        self.calls, self.mail_reply, self.greeting, self.tls, self.fail_on = [], mail, greeting, starttls, fail_on
        self.rcpt_replies = list(rcpt or [(250, b'2.1.5 Recipient OK')])

    def _call(self, name, *args):
        self.calls.append((name,) + args)
        if self.fail_on == name:
            raise OSError('connection reset')

    def connect(self, host, port):
        self._call('connect', host, port)
        return self.greeting

    def ehlo(self, name=''):
        self._call('ehlo', name)
        return 250, b'ok'

    def has_extn(self, name):
        return self.tls and name == 'starttls'

    def starttls(self, context=None):
        self._call('starttls')
        return 220, b'go ahead'

    def mail(self, sender):
        self._call('mail', sender)
        return self.mail_reply

    def rcpt(self, recipient):
        self._call('rcpt', recipient)
        return self.rcpt_replies.pop(0) if self.rcpt_replies else (550, b'5.4.1 Recipient address rejected: Access denied')

    def data(self, *a):
        self._call('data')
        raise AssertionError('DATA must never be sent')

    def rset(self):
        self._call('rset')

    def quit(self):
        self._call('quit')

    def close(self):
        self._call('close')


class SessionTests(unittest.TestCase):
    def run_session(self, smtp):
        return ds.session('acme.example', MX, smtp)

    def test_open_tenant_is_accepted_and_no_message_is_sent(self):
        smtp = FakeSMTP()
        out = self.run_session(smtp)
        self.assertEqual(out['outcome'], 'accepted')
        self.assertEqual(out['rcpt'], 'postmaster@acme.example')
        self.assertEqual(out['mail_from'], 'cvengine-direct-send-test@acme.example')
        names = [c[0] for c in smtp.calls]
        self.assertNotIn('data', names)
        self.assertEqual(names[-3:], ['rset', 'quit', 'close'])

    def test_reject_direct_send_reply_is_rejected_at_rcpt_or_mail(self):
        msg = b'5.7.68 TenantInboundAttribution; Direct Send not allowed for this organization from unauthorized sources'
        self.assertEqual(self.run_session(FakeSMTP(rcpt=[(550, msg)]))['outcome'], 'rejected')
        self.assertEqual(self.run_session(FakeSMTP(mail=(550, msg)))['outcome'], 'rejected')

    def test_unknown_recipients_try_the_next_role_address_then_stay_inconclusive(self):
        smtp = FakeSMTP(rcpt=[(550, b'5.4.1 Recipient address rejected: Access denied'), (250, b'2.1.5 Recipient OK')])
        out = self.run_session(smtp)
        self.assertEqual((out['outcome'], out['rcpt']), ('accepted', 'abuse@acme.example'))
        smtp = FakeSMTP(rcpt=[(550, b'5.4.1 Recipient address rejected')] * 10)
        out = self.run_session(smtp)
        self.assertEqual(out['outcome'], 'inconclusive')
        self.assertEqual(len([c for c in smtp.calls if c[0] == 'rcpt']), len(ds.RECIPIENTS))

    def test_anything_unclear_is_inconclusive(self):
        self.assertEqual(self.run_session(FakeSMTP(greeting=(554, b'no service')))['outcome'], 'inconclusive')
        self.assertEqual(self.run_session(FakeSMTP(mail=(451, b'try later')))['outcome'], 'inconclusive')
        self.assertEqual(self.run_session(FakeSMTP(fail_on='mail'))['outcome'], 'inconclusive')
        self.assertEqual(self.run_session(FakeSMTP(rcpt=[(452, b'4.5.3 too many')] * 10))['outcome'], 'inconclusive')

    def test_starttls_is_used_when_offered(self):
        smtp = FakeSMTP(starttls=True)
        self.run_session(smtp)
        self.assertIn(('starttls',), smtp.calls)


class PolicyTests(unittest.TestCase):
    def test_the_mx_host_is_reached_under_a_policy_for_that_host_only(self):
        seen = {}

        def connect(host, derived):
            seen['host'], seen['policy'] = host, derived
            return FakeSMTP()
        task = ScopePolicy({'domains': ['acme.example'], 'excluded': ['skip.acme.example']}, internal=False)
        out = ds.test('acme.example', MX, task, connect=connect)
        self.assertEqual(out['outcome'], 'accepted')
        self.assertEqual(seen['policy'].host_refusal(MX), '')
        self.assertEqual(seen['policy'].host_refusal('other.example'), 'outside the scope policy')
        self.assertEqual(seen['policy'].host_refusal('skip.acme.example'), 'excluded')

    def test_an_excluded_mx_host_is_never_contacted(self):
        task = ScopePolicy({'domains': ['acme.example'], 'excluded_trees': ['outlook.com']}, internal=False)
        out = ds.test('acme.example', MX, task)
        self.assertEqual(out['outcome'], 'inconclusive')
        self.assertEqual(task.touched, [])

    def test_m365_hosts(self):
        self.assertEqual(ds.m365_hosts(['10 x', MX + '.', 'mx.other.example.']), [MX])


class ReviewWiringTests(unittest.TestCase):
    def records(self, name, rtype):
        return {('acme.example', 'MX'): ['0 ' + MX + '.']}.get((name, rtype), [])

    def test_review_reports_only_a_tested_acceptance(self):
        calls = []

        def direct(domain, mx, scope):
            calls.append((domain, mx))
            return {'outcome': 'accepted', 'mx': mx, 'mail_from': 'x@acme.example', 'rcpt': 'postmaster@acme.example', 'reply': '250 ok',
                    'transcript': []}
        scope = ScopePolicy({'domains': ['acme.example']}, internal=False)
        found = mf.review('acme.example', True, [], [], {}, lambda n: [], self.records, http=True, scope=scope, rdap_on=False,
                          direct_test=direct)
        self.assertEqual(calls, [('acme.example', MX)])
        self.assertIn('mx_direct_send', {f.check for f in found})
        rejected = lambda d, m, s: {'outcome': 'rejected'}  # noqa: E731
        found = mf.review('acme.example', True, [], [], {}, lambda n: [], self.records, http=True, scope=scope, rdap_on=False,
                          direct_test=rejected)
        self.assertNotIn('mx_direct_send', {f.check for f in found})

    def test_no_test_without_real_dns_or_a_scope(self):
        boom = lambda d, m, s: self.fail('must not run')  # noqa: E731
        mf.review('acme.example', True, [], [], {}, lambda n: [], self.records, http=False, scope=None, direct_test=boom)
        mf.review('acme.example', True, [], [], {}, lambda n: [], self.records, http=True, scope=None, rdap_on=False, direct_test=boom)


class WireTests(unittest.TestCase):
    """A real SMTP dialog with a local server that rejects like Microsoft: the bytes on the wire stop at RCPT."""

    def test_wire_dialog_never_reaches_data(self):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        port, lines = server.getsockname()[1], []

        def serve():
            conn, _ = server.accept()
            f = conn.makefile('rb')
            conn.sendall(b'220 fake ESMTP\r\n')
            while True:
                line = f.readline()
                if not line:
                    break
                lines.append(line.strip().decode())
                cmd = line[:4].upper()
                if cmd == b'EHLO':
                    conn.sendall(b'250-fake\r\n250 SIZE 1000\r\n')
                elif cmd == b'RCPT':
                    conn.sendall(b'550 5.7.68 TenantInboundAttribution; Direct Send not allowed\r\n')
                elif cmd == b'QUIT':
                    conn.sendall(b'221 bye\r\n')
                    break
                else:
                    conn.sendall(b'250 ok\r\n')
            conn.close()
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        out = ds.session('acme.example', MX, ds._PinnedSMTP(sock, MX))
        t.join(5)
        server.close()
        self.assertEqual(out['outcome'], 'rejected')
        self.assertFalse(any(x.upper().startswith('DATA') for x in lines), lines)
        self.assertEqual([x.split(':')[0].split()[0].upper() for x in lines], ['EHLO', 'MAIL', 'RCPT', 'RSET', 'QUIT'])


if __name__ == '__main__':
    unittest.main()
