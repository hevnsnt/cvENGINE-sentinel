"""The SSH, SMTP, SMB and RDP service feature readings (``probes.service_probes``): the parsers fed captured or fixture bytes, the exchanges against
local servers, and the follow-up of a fingerprint pass (which endpoints are asked, the time budget, the cap)."""
import socket
import threading
import time
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from cvengine_scanner import contract, features
from cvengine_scanner.probes import service_probes as sp
from cvengine_scanner.probes import ssh_probe
from cvengine_scanner.probes.policy import ScopePolicy

FIXTURES = Path(__file__).resolve().parent.parent / 'fixtures'
NSE_XML = (FIXTURES / 'nmap_service_features.xml').read_text(encoding='utf-8')
SSHAMBLE = (FIXTURES / 'ssh_probe_openssh.jsonl').read_text(encoding='utf-8')

# Captured from impacket 0.12.0's SMB server (SimpleSMBServer, SMB2 support on and off) answering this module's own requests.
SMB2_202_REPLY = bytes.fromhex(
    '0000009efe534d4240000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041'
    '000100020200004141414141414141414141414141414100000000000001000000010000000100002882313b78dd01002882313b78dd0180001e0000000000601c06062b06'
    '01050502a0123010a00e300c060a2b06010401823702020a')
SMB1_ACCEPTED_REPLY = bytes.fromhex(
    '00000073ff534d4272000000008000c80000000000000000000000000000fffe00000000110000030100010000fa000000000100000000007400008000000000000000000000'
    '002e0041414141414141414141414141414141601c06062b0601050502a0123010a00e300c060a2b06010401823702020a')
SMB2_NOT_SUPPORTED_REPLY = bytes.fromhex(
    '00000049fe534d4240000000bb0000c0000001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000900'
    '000000000000ff')


def smb311_reply(compression=(1, 2, 3), signing_required=True):
    """An SMB 3.1.1 NEGOTIATE response laid out as MS-SMB2 2.2.4 says (a Windows 10 1909 answer has this shape): the preauth integrity context
    and, when ``compression`` is not None, a compression context naming those algorithm ids."""
    header = b'\xfeSMB' + (64).to_bytes(2, 'little') + b'\0' * 6 + (0).to_bytes(2, 'little') + (1).to_bytes(2, 'little') + b'\x01\0\0\0' + b'\0' * 44
    contexts = [(1, (1).to_bytes(2, 'little') + (32).to_bytes(2, 'little') + (1).to_bytes(2, 'little') + b'\x33' * 32)]
    if compression is not None:
        contexts.append((3, len(compression).to_bytes(2, 'little') + b'\0\0' + b'\0' * 4 + b''.join(a.to_bytes(2, 'little') for a in compression)))
    security = b'\x60\x28' + b'\0' * 40
    offset = 64 + 64 + len(security)
    offset += -offset % 8
    body = ((65).to_bytes(2, 'little') + (0x03 if signing_required else 0x01).to_bytes(2, 'little') + (0x0311).to_bytes(2, 'little')
            + len(contexts).to_bytes(2, 'little') + b'\x44' * 16 + (0x2f).to_bytes(4, 'little') + (8388608).to_bytes(4, 'little') * 3
            + b'\0' * 16 + (128).to_bytes(2, 'little') + len(security).to_bytes(2, 'little') + offset.to_bytes(4, 'little'))
    message = header + body + security
    message += b'\0' * (-len(message) % 8)
    for index, (kind, data) in enumerate(contexts):
        part = kind.to_bytes(2, 'little') + len(data).to_bytes(2, 'little') + b'\0' * 4 + data
        message += part if index == len(contexts) - 1 else part + b'\0' * (-len(part) % 8)
    return len(message).to_bytes(4, 'big') + message


SMB1_REFUSED_REPLY = (b'\0\0\0\x25' + b'\xffSMB\x72' + b'\0' * 4 + b'\x98' + (0xC801).to_bytes(2, 'little') + b'\0' * 12 + b'\0\0\xff\xfe\0\0\0\0'
                      + b'\x01\xff\xff' + b'\0\0')

POSTFIX_GREETING = b'220 mail.example.com ESMTP Postfix (Ubuntu)\r\n'
POSTFIX_EHLO = (b'250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-STARTTLS\r\n'
                b'250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250-SMTPUTF8\r\n250 CHUNKING\r\n')
EXIM_EHLO = (b'250-mx.example.org Hello cvengine-sentinel.invalid [198.51.100.7]\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING\r\n'
             b'250-AUTH PLAIN LOGIN NTLM\r\n250-CHUNKING\r\n250 HELP\r\n')
EXCHANGE_EHLO = (b'250-EX01.corp.example Hello [198.51.100.7]\r\n250-SIZE 37748736\r\n250-PIPELINING\r\n250-DSN\r\n250-ENHANCEDSTATUSCODES\r\n'
                 b'250-STARTTLS\r\n250-X-ANONYMOUSTLS\r\n250-AUTH NTLM\r\n250-X-EXPS GSSAPI NTLM\r\n250-8BITMIME\r\n250-BINARYMIME\r\n'
                 b'250-CHUNKING\r\n250 XRDST\r\n')
BARE_EHLO = b'250-relay.example.net\r\n250-SIZE 10485760\r\n250 HELP\r\n'


def by_feature(items):
    return {(i['host'], i['port'], i['feature']): i['value'] for i in items}


class SshTests(unittest.TestCase):
    def test_nmap_ssh2_enum_algos_tables_give_the_terrapin_reading(self):
        got = by_feature(sp.nse_readings(NSE_XML))
        self.assertEqual(got[('192.0.2.20', 22, 'ssh_terrapin')], 'exposed')  # chacha20 offered, no strict kex (OpenSSH 8.9)
        self.assertEqual(got[('192.0.2.20', 22, 'ssh_cbc')], 'no')
        self.assertEqual(got[('192.0.2.20', 22, 'ssh_aes_gcm')], 'yes')
        # CBC in one direction only (the tables are split) with an EtM MAC, but strict kex offered
        self.assertEqual(got[('192.0.2.21', 2222, 'ssh_terrapin')], 'strict_kex')
        self.assertEqual(got[('192.0.2.21', 2222, 'ssh_cbc')], 'yes')

    def test_the_sshamble_record_gives_the_same_readings_and_the_auth_methods(self):
        found = []
        entry = ssh_probe.parse_host('192.0.2.10', 22, SSHAMBLE, True, features=found)
        self.assertTrue(entry['reached'])
        got = by_feature(found)
        self.assertEqual(got[('192.0.2.10', 22, 'ssh_terrapin')], 'strict_kex')  # OpenSSH 10.3: chacha20 and EtM, strict kex
        self.assertEqual(got[('192.0.2.10', 22, 'ssh_auth_methods')], 'publickey,password,keyboard-interactive')
        self.assertEqual(features.clean_features(found), found)

    def test_neither_mode_is_no_affected_mode(self):
        got = by_feature(sp.ssh_readings('h', 22, kex=['curve25519-sha256'], ciphers=['aes128-ctr', 'aes128-cbc'], macs=['hmac-sha2-256']))
        self.assertEqual(got[('h', 22, 'ssh_terrapin')], 'no_affected_mode')  # CBC without an EtM MAC is not the affected mode

    def test_an_unread_list_is_no_reading(self):
        self.assertEqual(sp.ssh_readings('h', 22, kex=['curve25519-sha256'], ciphers=None, macs=None), [])
        got = by_feature(sp.ssh_readings('h', 22, kex=None, ciphers=['chacha20-poly1305@openssh.com'], macs=[]))
        self.assertNotIn(('h', 22, 'ssh_terrapin'), got)  # an affected mode, but whether strict kex is offered was not read
        got = by_feature(sp.ssh_readings('h', 22, kex=['curve25519-sha256'], ciphers=['aes256-cbc'], macs=None))
        self.assertNotIn(('h', 22, 'ssh_terrapin'), got)  # CBC, and the MACs were not read


class RdpTests(unittest.TestCase):
    def test_nla_required_and_not_from_rdp_enum_encryption(self):
        got = by_feature(sp.nse_readings(NSE_XML))
        self.assertEqual(got[('192.0.2.20', 3389, 'rdp_nla')], 'required')
        self.assertEqual(got[('192.0.2.21', 3389, 'rdp_nla')], 'not_required')

    def test_tls_alone_is_enough_for_not_required_and_unknown_answers_are_no_reading(self):
        self.assertEqual(sp.rdp_reading('h', 3389, '\n  Security layer\n    SSL: SUCCESS\n')['value'], 'not_required')
        self.assertIsNone(sp.rdp_reading('h', 3389, '\n  Security layer\n    CredSSP (NLA): SUCCESS\n    Native RDP: Unknown\n'))
        self.assertIsNone(sp.rdp_reading('h', 3389, 'ERROR: Script execution failed (use -d to debug)'))
        self.assertEqual(sp.rdp_reading('h', 3389, '  Security layer\n    CredSSP (NLA): SUCCESS\n    Native RDP: FAILED (HYBRID_REQUIRED_BY_SERVER)\n'
                                                  '    SSL: FAILED (HYBRID_REQUIRED_BY_SERVER)\n')['value'], 'required')

    def test_unreadable_reports_give_nothing(self):
        self.assertEqual(sp.nse_readings(''), [])
        self.assertEqual(sp.nse_readings('<nmaprun'), [])
        self.assertEqual(sp.nse_readings('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>'), [])


class SmtpTests(unittest.TestCase):
    def test_postfix_lists_starttls_chunking_and_no_auth_before_tls(self):
        code, lines = sp.parse_reply(POSTFIX_EHLO)
        self.assertEqual(code, 250)
        got = by_feature(sp.ehlo_readings('mx', 25, lines))
        self.assertEqual({k[2]: v for k, v in got.items()}, {'smtp_chunking': 'yes', 'smtp_starttls': 'yes', 'smtp_smtputf8': 'yes',
                                                            'smtp_8bitmime': 'yes', 'smtp_pipelining': 'yes'})
        self.assertNotIn(('mx', 25, 'smtp_auth'), got)  # AUTH may be offered after STARTTLS, which is never sent: unknown

    def test_exim_lists_auth_ntlm_in_cleartext(self):
        got = by_feature(sp.ehlo_readings('mx', 587, sp.parse_reply(EXIM_EHLO)[1]))
        self.assertEqual(got[('mx', 587, 'smtp_auth')], 'ntlm,plain,login')
        self.assertEqual(got[('mx', 587, 'smtp_starttls')], 'no')
        self.assertEqual(got[('mx', 587, 'smtp_chunking')], 'yes')

    def test_exchange_and_a_bare_relay(self):
        got = by_feature(sp.ehlo_readings('ex', 25, sp.parse_reply(EXCHANGE_EHLO)[1]))
        self.assertEqual(got[('ex', 25, 'smtp_auth')], 'ntlm')
        self.assertEqual(got[('ex', 25, 'smtp_smtputf8')], 'no')
        got = by_feature(sp.ehlo_readings('relay', 25, sp.parse_reply(BARE_EHLO)[1]))
        self.assertEqual(got[('relay', 25, 'smtp_auth')], 'none')  # no AUTH and no STARTTLS: none at all
        self.assertEqual(got[('relay', 25, 'smtp_chunking')], 'no')

    def test_unknown_mechanisms_are_other_and_a_long_list_keeps_the_rule_bearing_ones(self):
        lines = ['x', 'AUTH PLAIN LOGIN CRAM-MD5 DIGEST-MD5 SCRAM-SHA-1 SCRAM-SHA-256 XOAUTH2 OAUTHBEARER GSSAPI NTLM EXTERNAL FOO BAR']
        value = by_feature(sp.ehlo_readings('m', 25, lines))[('m', 25, 'smtp_auth')]
        self.assertTrue(value.startswith('external,ntlm,gssapi'))
        self.assertLessEqual(len(value), features.MAX_VALUE)
        self.assertIsNotNone(features.clean_value('smtp_auth', value))

    def test_incomplete_or_mixed_replies_are_not_replies(self):
        self.assertIsNone(sp.parse_reply(b'250-a\r\n250-b\r\n'))
        self.assertIsNone(sp.parse_reply(b'250-a\r\n354 b\r\n'))
        self.assertIsNone(sp.parse_reply(b'HTTP/1.1 400 Bad Request\r\n'))


class SmbTests(unittest.TestCase):
    def test_the_negotiate_request_offers_every_dialect_and_the_three_contexts(self):
        req = sp.smb2_negotiate_request(b'\x11' * 16, b'\x22' * 32)
        msg = req[4:]
        self.assertEqual(int.from_bytes(req[:4], 'big'), len(msg))
        self.assertEqual(msg[:4], b'\xfeSMB')
        self.assertEqual(int.from_bytes(msg[12:14], 'little'), 0)  # NEGOTIATE, and nothing else
        body = msg[64:]
        self.assertEqual([int.from_bytes(body[36 + 2 * i:38 + 2 * i], 'little') for i in range(5)], [0x202, 0x210, 0x300, 0x302, 0x311])
        offset, count = int.from_bytes(body[28:32], 'little'), int.from_bytes(body[32:34], 'little')
        self.assertEqual((offset % 8, count), (0, 3))
        kinds = []
        for _ in range(count):
            kind, size = int.from_bytes(msg[offset:offset + 2], 'little'), int.from_bytes(msg[offset + 2:offset + 4], 'little')
            kinds.append(kind)
            offset += 8 + size
            offset += -offset % 8
        self.assertEqual(kinds, [1, 2, 3])

    def test_the_smb1_request_names_only_nt_lm_012(self):
        req = sp.smb1_negotiate_request()
        self.assertEqual(req[4:9], b'\xffSMB\x72')
        self.assertTrue(req.endswith(b'\x02NT LM 0.12\x00'))
        self.assertNotIn(b'SMB 2', req)

    def test_captured_impacket_answers(self):
        self.assertEqual(sp.parse_smb2_negotiate(SMB2_202_REPLY), {'dialect': '2.0.2', 'signing_required': False, 'compression': None})
        self.assertIsNone(sp.parse_smb2_negotiate(SMB2_NOT_SUPPORTED_REPLY))  # STATUS_NOT_SUPPORTED: an SMB1-only server
        self.assertIs(sp.parse_smb1_negotiate(SMB1_ACCEPTED_REPLY), True)
        got = by_feature(sp.smb_readings('h', 445, sp.parse_smb2_negotiate(SMB2_202_REPLY), True))
        self.assertEqual(got, {('h', 445, 'smb_dialect'): '2.0.2', ('h', 445, 'smb_signing'): 'not_required',
                               ('h', 445, 'smb_compression'): 'no', ('h', 445, 'smbv1'): 'yes'})

    def test_smb_311_with_and_without_compression(self):
        parsed = sp.parse_smb2_negotiate(smb311_reply())
        self.assertEqual(parsed, {'dialect': '3.1.1', 'signing_required': True, 'compression': ['LZNT1', 'LZ77', 'LZ77+Huffman']})
        got = by_feature(sp.smb_readings('h', 445, parsed, False))
        self.assertEqual(got[('h', 445, 'smb_compression')], 'yes')
        self.assertEqual(got[('h', 445, 'smbv1')], 'no')
        self.assertEqual(got[('h', 445, 'smb_signing')], 'required')
        for compression in (None, (0,)):  # no context (compression disabled), or only NONE
            got = by_feature(sp.smb_readings('h', 445, sp.parse_smb2_negotiate(smb311_reply(compression)), None))
            self.assertEqual(got[('h', 445, 'smb_compression')], 'no')
            self.assertNotIn(('h', 445, 'smbv1'), got)

    def test_smb1_refused_and_garbage(self):
        self.assertIs(sp.parse_smb1_negotiate(SMB1_REFUSED_REPLY), False)
        self.assertIs(sp.parse_smb1_negotiate(SMB2_202_REPLY), False)
        self.assertIsNone(sp.parse_smb1_negotiate(b'\0\0\0\x05hello'))
        self.assertIsNone(sp.parse_smb2_negotiate(b'\x85\0\0\0'))
        self.assertIsNone(sp.parse_smb2_negotiate(SMB2_202_REPLY[:60]))


class LocalServer:
    """A TCP server on 127.0.0.1 that answers each connection with ``handler(conn)``."""

    def __init__(self, handler):
        self.handler = handler
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.received = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    self.handler(self, conn)
                except OSError:
                    pass

    def close(self):
        self.sock.close()

    def wait_for(self, count, seconds=2.0):
        """Wait until the server thread has recorded ``count`` messages (it may still be reading when the client returns)."""
        stop = time.monotonic() + seconds
        while len(self.received) < count and time.monotonic() < stop:
            time.sleep(0.01)
        return self.received


def local_connect(address, port, policy, timeout=2):
    return socket.create_connection(('127.0.0.1', port), timeout)


def smtp_handler(server, conn):
    conn.sendall(POSTFIX_GREETING)
    data = b''
    while not data.endswith(b'\r\n'):
        data += conn.recv(100)
    server.received.append(data)
    conn.sendall(POSTFIX_EHLO)
    server.received.append(conn.recv(100))


class NetworkTests(unittest.TestCase):
    def test_one_ehlo_then_quit(self):
        server = LocalServer(smtp_handler)
        self.addCleanup(server.close)
        got = by_feature(sp.probe_smtp('192.0.2.30', server.port, ScopePolicy(), connect=local_connect))
        self.assertEqual(got[('192.0.2.30', server.port, 'smtp_chunking')], 'yes')
        self.assertEqual(server.wait_for(2), [b'EHLO cvengine-sentinel.invalid\r\n', b'QUIT\r\n'])

    def test_a_server_that_does_not_greet_with_220_is_not_asked(self):
        def busy(server, conn):
            conn.sendall(b'554 5.7.1 no service\r\n')
            server.received.append(conn.recv(100))
        server = LocalServer(busy)
        self.addCleanup(server.close)
        self.assertEqual(sp.probe_smtp('192.0.2.30', server.port, ScopePolicy(), connect=local_connect), [])
        self.assertEqual(server.wait_for(1), [b''])  # nothing was sent: the connection was closed

    def test_smb_two_negotiates_and_a_closed_smb1_connection_is_no(self):
        def smb(server, conn):
            request = conn.recv(4096)
            server.received.append(request[4:9])
            if request[4:8] == b'\xfeSMB':
                conn.sendall(smb311_reply())
            # an SMB1 NEGOTIATE is answered by closing the connection (Windows with SMBv1 removed)
        server = LocalServer(smb)
        self.addCleanup(server.close)
        got = by_feature(sp.probe_smb('192.0.2.31', server.port, ScopePolicy(), connect=local_connect))
        self.assertEqual(server.wait_for(2), [b'\xfeSMB@', b'\xffSMBr'])
        self.assertEqual(got[('192.0.2.31', server.port, 'smb_compression')], 'yes')
        self.assertEqual(got[('192.0.2.31', server.port, 'smbv1')], 'no')

    def test_silence_is_no_reading(self):
        def silent(server, conn):
            conn.recv(4096)
            time.sleep(0.6)
        server = LocalServer(silent)
        self.addCleanup(server.close)
        old = sp.READ_SECONDS
        sp.READ_SECONDS = 0.3
        self.addCleanup(setattr, sp, 'READ_SECONDS', old)
        self.assertEqual(sp.probe_smb('192.0.2.31', server.port, ScopePolicy(), connect=local_connect), [])

    def test_the_policy_floor_refuses_loopback_before_anything_is_sent(self):
        server = LocalServer(smtp_handler)
        self.addCleanup(server.close)
        policy = ScopePolicy({'hosts': ['127.0.0.1'], 'addresses': ['127.0.0.1']})
        self.assertEqual(sp.probe_smtp('127.0.0.1', server.port, policy), [])  # the real connect: transport.open_socket with the policy
        self.assertEqual(server.received, [])


class FollowUpTests(unittest.TestCase):
    HOSTS = [{'ip': '8.8.4.4', 'ports': [{'number': 25, 'protocol': 'tcp', 'service_name': 'smtp'},
                                              {'number': 465, 'protocol': 'tcp', 'service_name': 'smtp', 'tunnel': 'ssl'},
                                              {'number': 445, 'protocol': 'tcp', 'service_name': 'microsoft-ds'},
                                              {'number': 139, 'protocol': 'tcp', 'service_name': 'netbios-ssn'},
                                              {'number': 22, 'protocol': 'tcp', 'service_name': 'ssh'}]},
             {'ip': '8.8.8.8', 'ports': [{'number': 25, 'protocol': 'tcp', 'service_name': 'smtp'}]}]

    def test_only_cleartext_smtp_and_port_445_of_the_task_addresses(self):
        self.assertEqual(sp.endpoints(self.HOSTS, {'8.8.4.4'}), [('smtp', '8.8.4.4', 25), ('smb', '8.8.4.4', 445)])

    def test_the_probes_run_under_a_policy_of_the_task_addresses(self):
        seen = []

        def connect(address, port, policy, timeout=2):
            seen.append((address, port, policy.address_refusal(address, literal=True)))
            raise OSError('refused')
        items, skipped = sp.follow_up(self.HOSTS, {'8.8.4.4'}, connect=connect)
        self.assertEqual((items, skipped), ([], 0))
        self.assertEqual(sorted(seen), [('8.8.4.4', 25, ''), ('8.8.4.4', 445, ''), ('8.8.4.4', 445, '')])

    def test_no_budget_asks_nothing_and_counts_the_skipped(self):
        def connect(*a, **k):
            raise AssertionError('nothing may be asked')
        self.assertEqual(sp.follow_up(self.HOSTS, {'8.8.4.4'}, budget=0, connect=connect), ([], 2))

    def test_the_cap_and_the_order_of_a_full_list(self):
        hosts = [{'ip': f'192.0.2.{i}', 'ports': [{'number': 25, 'protocol': 'tcp', 'service_name': 'smtp'}]} for i in range(1, 80)]
        calls = []
        _items, skipped = sp.follow_up(hosts, {h['ip'] for h in hosts}, connect=lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(OSError()))
        self.assertEqual((len(calls), skipped), (sp.MAX_ENDPOINTS, 79 - sp.MAX_ENDPOINTS))
        many = [sp._item(f'192.0.2.{i}', 25, 'smtp_pipelining', 'yes') for i in range(1, 120)] + \
               [sp._item(f'192.0.2.{i}', 3389, 'rdp_nla', 'required') for i in range(1, 30)]
        kept, dropped = sp.bounded(many)
        self.assertEqual((len(kept), dropped), (features.MAX_ITEMS, len(many) - features.MAX_ITEMS))
        self.assertEqual(sum(1 for i in kept if i['feature'] == 'rdp_nla'), 29)  # the rule-bearing readings are kept first


class ContractTests(unittest.TestCase):
    def test_nmap_and_ssh_probe_results_with_readings_validate(self):
        items = sp.nse_readings(NSE_XML)
        doc = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.20', 'os_guess': '', 'ports': []}], 'service_features': items}
        self.assertEqual(list(Draft202012Validator(contract.result_schema('nmap')).iter_errors(doc)), [])
        found = []
        entry = ssh_probe.parse_host('192.0.2.10', 22, SSHAMBLE, True, features=found)
        doc = {'outcome': 'done', 'hosts': [entry], 'touched': [], 'refused': [], 'service_features': found}
        self.assertEqual(list(Draft202012Validator(contract.result_schema('ssh_probe')).iter_errors(doc)), [])

    def test_every_new_feature_is_in_the_vocabulary(self):
        for key in sp.PRIORITY:
            self.assertIn(key, features.FEATURES)


if __name__ == '__main__':
    unittest.main()
