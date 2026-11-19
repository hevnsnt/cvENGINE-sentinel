"""The ALPN reading of the hygiene TLS probe (``probes.hygiene._fetch_cert``): whether a TLS service offers HTTP/2, read from the same handshake that
reads the certificate, against a real local TLS server; and that offering ALPN changes none of the certificate and posture readings."""
import datetime
import os
import socket
import ssl
import tempfile
import threading
import unittest
from unittest import mock

from cvengine_scanner.probes import hygiene as hy
from cvengine_scanner.probes.policy import ScopePolicy

ADDRS = ((socket.AF_INET, ('127.0.0.1', 443)),)


def _self_signed(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'asset.example.com')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('asset.example.com')]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = os.path.join(directory, 'cert.pem'), os.path.join(directory, 'key.pem')
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


class LocalTlsServer:
    """A TLS server on 127.0.0.1 that completes every handshake it is offered, with ``alpn`` as its ALPN protocols (None: no ALPN at all)."""

    def __init__(self, cert_path, key_path, alpn=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        if alpn is not None:
            self.ctx.set_alpn_protocols(alpn)
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass

    def connect(self, addresses, timeout, policy, host=None):
        return socket.create_connection(('127.0.0.1', self.port), timeout=timeout)

    def close(self):
        self.sock.close()


class AlpnReadingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.cert, cls.key = _self_signed(cls.dir.name)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def read(self, alpn):
        server = LocalTlsServer(self.cert, self.key, alpn)
        self.addCleanup(server.close)
        policy = ScopePolicy({'hosts': ['asset.example.com']})
        with mock.patch.object(hy.transport, 'open_socket', server.connect):
            return hy._fetch_cert('asset.example.com', 443, policy, addresses=ADDRS)

    def test_a_server_that_offers_http2_reads_h2(self):
        self.assertEqual(self.read(['h2', 'http/1.1'])['alpn'], 'h2')

    def test_a_server_that_offers_only_http1_reads_http1(self):
        self.assertEqual(self.read(['http/1.1'])['alpn'], 'http/1.1')

    def test_a_server_without_alpn_reads_none(self):
        self.assertEqual(self.read(None)['alpn'], 'none')

    def test_the_offer_changes_no_certificate_or_posture_reading(self):
        offered = self.read(['h2', 'http/1.1'])
        server = LocalTlsServer(self.cert, self.key, ['h2', 'http/1.1'])
        self.addCleanup(server.close)
        plain_handshake = hy._modern_handshake
        with mock.patch.object(hy.transport, 'open_socket', server.connect), \
                mock.patch.object(hy, '_modern_handshake', lambda *a, **k: plain_handshake(*a, **{**k, 'offer_alpn': False})):
            plain = hy._fetch_cert('asset.example.com', 443, ScopePolicy({'hosts': ['asset.example.com']}), addresses=ADDRS)
        self.assertEqual(plain['alpn'], 'unknown')  # no offer made: not read
        self.assertEqual({k: v for k, v in offered.items() if k != 'alpn'}, {k: v for k, v in plain.items() if k != 'alpn'})
        self.assertEqual((offered['subject'], offered['key_description']), ('asset.example.com', 'EC secp256r1'))

    def test_a_server_that_refuses_the_offer_is_read_again_without_it(self):
        calls = []
        info = ('der', 'TLSv1.3', 'TLS_AES_128_GCM_SHA256', 'unknown')

        def handshake(host, port, policy, addresses, timeout, offer_alpn=True):
            calls.append(offer_alpn)
            if offer_alpn:
                raise ssl.SSLError(1, '[SSL: TLSV1_ALERT_NO_APPLICATION_PROTOCOL] tlsv1 alert no application protocol')
            return info
        with mock.patch.object(hy, '_modern_handshake', handshake), mock.patch('cryptography.x509.load_der_x509_certificate',
                                                                                side_effect=RuntimeError('stop here')):
            with self.assertRaises(RuntimeError):  # the certificate is read from the second handshake
                hy._fetch_cert('asset.example.com', 443, ScopePolicy({'hosts': ['asset.example.com']}), addresses=ADDRS)
        self.assertEqual(calls, [True, False])

    def test_any_other_handshake_failure_is_not_retried(self):
        calls = []

        def handshake(host, port, policy, addresses, timeout, offer_alpn=True):
            calls.append(offer_alpn)
            raise ssl.SSLError(1, '[SSL: WRONG_VERSION_NUMBER] wrong version number')
        with mock.patch.object(hy, '_modern_handshake', handshake):
            self.assertIsNone(hy._fetch_cert('asset.example.com', 443, ScopePolicy({'hosts': ['asset.example.com']}), addresses=ADDRS))
        self.assertEqual(calls, [True])

    def test_the_legacy_client_leaves_alpn_unknown(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        with open(self.cert, 'rb') as f:
            der = x509.load_pem_x509_certificate(f.read()).public_bytes(serialization.Encoding.DER)
        with mock.patch.object(hy.legacy_tls, 'handshake', return_value=(der, 'TLSv1', 'AES128-SHA')):
            info = hy._fetch_cert('asset.example.com', 443, ScopePolicy({'hosts': ['asset.example.com']}), legacy=True, addresses=ADDRS)
        self.assertEqual(info['alpn'], 'unknown')

    def test_only_our_own_protocols_are_reported(self):
        self.assertEqual(hy._alpn_reading('spdy/3', True), 'unknown')
        self.assertEqual(hy._alpn_reading(None, True), 'none')
        self.assertEqual(hy._alpn_reading('h2', False), 'unknown')
        self.assertTrue(set(hy.ALPN_VALUES) >= {hy._alpn_reading(v, True) for v in ('h2', 'http/1.1', None, 'x')})


if __name__ == '__main__':
    unittest.main()
