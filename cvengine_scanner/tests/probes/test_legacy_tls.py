"""Ported from cvENGINE's web/tests/test_legacy_tls.py (its tests that need no database), run against the library copy."""
import ssl
from unittest import mock
from unittest import TestCase as SimpleTestCase
from cvengine_scanner.probes import legacy_tls
from cvengine_scanner.probes.policy import ScopePolicy
POLICY = ScopePolicy({'domains': ['example.test']}, internal=False)
class LegacyTlsTests(SimpleTestCase):
	"""The one module that speaks TLS 1.0 / 1.1 on purpose (the hygiene check for servers that still accept them)."""

	def test_the_client_is_limited_to_the_two_old_versions(self):
		ctx = legacy_tls._context()
		self.assertEqual((ctx.minimum_version, ctx.maximum_version), (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1))
		self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)  # it reads a certificate, it validates nothing

	def test_a_refusing_server_or_a_build_without_the_old_protocols_is_simply_no(self):
		with mock.patch.object(legacy_tls.pinned_transport, 'resolve', return_value=((2, ('93.184.215.14', 443)),)), \
				mock.patch.object(legacy_tls.pinned_transport, 'open_socket', side_effect=OSError('refused')):
			self.assertIsNone(legacy_tls.handshake('asset.example.test', 443, 5, POLICY))
			self.assertFalse(legacy_tls.accepts('asset.example.test', 443, 5, POLICY))
		with mock.patch.object(legacy_tls, '_context', side_effect=ssl.SSLError('no TLS 1.0 here')):
			self.assertIsNone(legacy_tls.handshake('asset.example.test', 443, 5, POLICY))

	def test_only_a_negotiated_old_version_counts_and_the_policy_reaches_the_transport(self):
		addresses = ((2, ('93.184.215.14', 443)),)
		tls = mock.MagicMock()
		tls.__enter__.return_value = tls
		tls.getpeercert.return_value, tls.cipher.return_value = b'der', ('AES128-SHA', 'TLSv1', 128)
		ctx, raw = mock.MagicMock(), mock.MagicMock()
		raw.__enter__.return_value = raw
		ctx.wrap_socket.return_value = tls
		with mock.patch.object(legacy_tls, '_context', return_value=ctx), \
				mock.patch.object(legacy_tls.pinned_transport, 'open_socket', return_value=raw) as connect:
			tls.version.return_value = 'TLSv1'
			self.assertEqual(legacy_tls.handshake('asset.example.test', 443, 5, POLICY, addresses=addresses), (b'der', 'TLSv1', 'AES128-SHA'))
			self.assertTrue(legacy_tls.accepts('asset.example.test', 443, 5, POLICY, addresses=addresses))
			tls.version.return_value = 'TLSv1.2'
			self.assertFalse(legacy_tls.accepts('asset.example.test', 443, 5, POLICY, addresses=addresses))
		connect.assert_any_call(addresses, 5, POLICY, host='asset.example.test')
