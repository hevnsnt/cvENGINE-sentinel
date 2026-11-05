"""Ported from cvENGINE's web/tests/test_egress_proxy.py (its tests that need no database), run against the library copy."""
import os
import socket
from unittest import mock
from unittest import TestCase as SimpleTestCase
from cvengine_scanner.probes import egress_proxy
HTTP_PROXY = 'http://203.0.113.50:3128'
SOCKS_PROXY = 'socks5://203.0.113.51:1080'
LOGIN_PROXY = 'http://bob:hunter2@203.0.113.52:3128'
def spec(line):
    parsed = egress_proxy.parse(line)
    assert parsed is not None, line
    return parsed
def answer(ip, port, family=socket.AF_INET):
    address = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', address
def fake_dns(table):
    """A ``getaddrinfo`` that answers names from ``table`` and leaves every other lookup (the loopback proxy fixture) to the real one."""
    real = socket.getaddrinfo

    def lookup(host, port, *args, **kwargs):
        if host in table:
            return [answer(table[host], int(port))]
        return real(host, port, *args, **kwargs)
    return lookup
def clean_environment(case):
    """No bypass list from the machine running the tests (a CI or sandbox NO_PROXY would hide what the cases check)."""
    patcher = mock.patch.dict(os.environ)
    patcher.start()
    case.addCleanup(patcher.stop)
    for name in ('CVENGINE_PROXY_BYPASS', 'NO_PROXY', 'no_proxy', 'CELERY_BROKER', 'CELERY_BACKEND', 'POSTGRES_HOST'):
        os.environ.pop(name, None)
class ParseTests(SimpleTestCase):
    def test_the_four_schemes_parse_with_default_ports_and_a_login(self):
        self.assertEqual((spec('http://203.0.113.1:8080').scheme, spec('http://203.0.113.1:8080').port), ('http', 8080))
        self.assertEqual(spec('https://p.example.com').port, 443)
        self.assertEqual(spec('socks5://p.example.com').port, 1080)
        self.assertEqual(spec('SOCKS5H://P.example.com:9050').scheme, 'socks5h')
        login = spec('http://bob:p%40ss@203.0.113.1:8080/')
        self.assertEqual((login.username, login.password, login.url), ('bob', 'p@ss', 'http://bob:p%40ss@203.0.113.1:8080'))

    def test_anything_else_is_skipped(self):
        for bad in ('', ' ', 'socks4://203.0.113.1:1080', 'ftp://203.0.113.1', 'file:///etc/passwd', 'not a proxy', 'http://', 'http://:8080',
                    'http://203.0.113.1:99999', 'http://203.0.113.1:0', 'http://203.0.113.1:8080/path', 'http://203.0.113.1:8080?x=1',
                    'http://203.0.113.1:8080 extra', 'http://u:p\r\nX: y@203.0.113.1:8080', 'http://' + 'a' * 500 + ':80'):
            self.assertIsNone(egress_proxy.parse(bad), bad)

    def test_a_spec_never_shows_its_password(self):
        s = spec(LOGIN_PROXY)
        for text in (repr(s), str(s), egress_proxy.describe(s), f'{s}', '%s' % (s,)):
            self.assertNotIn('hunter2', text)
        self.assertEqual(egress_proxy.describe(s), 'http://203.0.113.52:3128 (with login)')
class BypassTests(SimpleTestCase):
    def setUp(self):
        clean_environment(self)

    def test_loopback_localhost_and_the_stack_never_go_through_a_proxy(self):
        for host in ('127.0.0.1', '127.8.8.8', '::1', '[::1]', 'localhost', 'app.localhost', 'LOCALHOST.', 'redis', 'db', 'web', 'celery', 'celery-beat',
                     '0.0.0.0', ''):
            self.assertTrue(egress_proxy.bypass(host), host)
        for host in ('203.0.113.5', 'www.example.com', '2001:db8::1', 'redis.example.com'):
            self.assertFalse(egress_proxy.bypass(host), host)

    def test_private_link_local_and_tailnet_addresses_skip_the_proxy_unless_asked(self):
        private = ('10.0.0.5', '172.16.4.4', '192.168.1.9', '169.254.1.1', '100.100.1.1', 'fd00::5', 'fe80::1')
        for host in private:
            self.assertTrue(egress_proxy.bypass(host), host)
        with mock.patch.dict(os.environ, {'CVENGINE_PROXY_PRIVATE': '1'}):
            for host in private:
                self.assertFalse(egress_proxy.bypass(host), host)
            self.assertTrue(egress_proxy.bypass('127.0.0.1'))

    def test_the_stack_hosts_of_the_environment_are_included(self):
        with mock.patch.dict(os.environ, {'CELERY_BROKER': 'redis://:pw@cache.internal:6379/0', 'POSTGRES_HOST': 'pg.internal'}):
            self.assertTrue(egress_proxy.bypass('cache.internal'))
            self.assertTrue(egress_proxy.bypass('pg.internal'))
        with mock.patch.dict(os.environ, {'POSTGRES_HOST': '/var/run/postgresql'}):
            self.assertFalse(egress_proxy.bypass('/var/run/postgresql'.strip('/')))

    def test_the_operators_list_takes_names_suffixes_ips_and_ranges(self):
        with mock.patch.dict(os.environ, {'CVENGINE_PROXY_BYPASS': 'lab.example.com, .corp.example.com ,10.0.0.0/8,192.0.2.7', 'NO_PROXY': '*.intranet.example'}):
            for host in ('lab.example.com', 'x.lab.example.com', 'a.corp.example.com', '10.9.8.7', '192.0.2.7', 'h.intranet.example'):
                self.assertTrue(egress_proxy.bypass(host), host)
            for host in ('example.com', 'notlab.example.com', '11.0.0.1', '192.0.2.8'):
                self.assertFalse(egress_proxy.bypass(host), host)
ORIGIN_BODY = b'<html><head><title>origin behind the proxy</title></head><body>hello</body></html>'
def origin_response():
    return b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: origin-fixture\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(ORIGIN_BODY) + ORIGIN_BODY
def read_head(stream):
    head = b''
    while not head.endswith(b'\r\n\r\n'):
        byte = stream.recv(1)
        if not byte:
            break
        head += byte
    return head.decode('latin-1')
def self_signed(directory):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'app.example.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2)).sign(key, hashes.SHA256()))
    cert_path, key_path = os.path.join(directory, 'cert.pem'), os.path.join(directory, 'key.pem')
    with open(cert_path, 'wb') as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, 'wb') as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path
