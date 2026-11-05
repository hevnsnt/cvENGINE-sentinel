"""Ported from cvENGINE's web/tests/test_sensitive.py (its tests that need no database), run against the library copy."""
import json
from unittest import TestCase as SimpleTestCase
from cvengine_scanner.probes import sensitive as sv
AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'
GITHUB = 'ghp' + '_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'
SLACK = 'xoxb' + '-' + '123456789012-abcdefghij'
STRIPE = 'sk' + '_live_' + 'a1B2c3D4e5F6g7H8i9J0k1L2'
GOOGLE = 'AIza' + 'SyA1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q'
JWT = 'eyJhbGciOiJIUzI1NiJ9' + '.' + 'eyJzdWIiOiIxMjM0NTY3ODkwIn0' + '.' + 'dBjftJeZ4CVPmB92K27uhbUJU1p1r'
PEM = '-----BEGIN RSA ' + 'PRIVATE KEY-----'
EMAIL = 'johndoe@acme-corp.io'
PHONE = '+44 20 7946 0958'
CARD = '4111 1111 1111 1111'
class PatternTests(SimpleTestCase):
	def types(self, text):
		return set(sv.scan_text(text))

	def test_scanning_a_hostile_64kb_body_takes_linear_time(self):
		# Before the repeats were bounded these cost 1 to 35 seconds each on one worker thread.
		import time
		bodies = ('a' * 65536, 'a-' * 32768, 'a.' * 32768, 'a@' * 32768, 'eyJ' + 'a' * 65000, ('eyJ' + 'a' * 12 + '.') * 4000)
		started = time.monotonic()
		for body in bodies:
			sv.scan_text(body)
		self.assertLess(time.monotonic() - started, 2.0)

	def test_bounded_patterns_still_find_ordinary_values(self):
		found = sv.scan_text('write alice.smith@mail.acme-corp.io, host db1.prod.corp.local, ip 10.1.2.3')
		self.assertEqual({'email', 'internal_host', 'internal_ip'}, set(found))

	def test_each_credential_pattern_matches_and_near_misses_do_not(self):
		for name, value in (('aws_key', AWS_KEY), ('github_token', GITHUB), ('slack_token', SLACK), ('stripe_key', STRIPE),
				('google_key', GOOGLE), ('jwt', JWT), ('private_key', PEM)):
			self.assertEqual(self.types(f'x {value} y'), {name}, name)
		self.assertEqual(self.types('AKIA' + 'SHORT'), set())
		self.assertEqual(self.types('ghp' + '_tooshort'), set())
		self.assertEqual(self.types('-----BEGIN ' + 'CERTIFICATE-----'), set())

	def test_email_phone_and_internal_identifiers(self):
		self.assertEqual(self.types(f'contact {EMAIL}'), {'email'})
		self.assertEqual(self.types(f'call {PHONE}'), {'phone'})
		self.assertEqual(self.types('db at 10.20.30.40 and 192.168.1.5'), {'internal_ip'})
		self.assertEqual(self.types('host build01.corp and db.internal'), {'internal_host'})
		self.assertEqual(self.types('public 8.8.8.8 and 10.999.1.1'), set())

	def test_noise_is_dropped(self):
		self.assertEqual(self.types('noreply@example.com support@sentry.io logo@2x.png'), set())

	def test_a_card_needs_luhn_and_a_card_iin_and_a_timestamp_is_not_one(self):
		self.assertEqual(self.types(f'pay {CARD}'), {'card'})
		self.assertNotIn('card', self.types('pay 4111 1111 1111 1112'))  # Luhn fails
		self.assertEqual(self.types('ts 1700000000000'), set())  # 13 digits, wrong IIN
		self.assertEqual(self.types('5555555555554444'), {'card'})
		self.assertTrue(sv.luhn_ok('4111111111111111') and not sv.luhn_ok('4111111111111112'))

	def test_a_phone_is_not_a_card_and_all_one_digit_numbers_are_ignored(self):
		self.assertNotIn('phone', self.types(f'pay {CARD}'))
		self.assertEqual(self.types('call 000-000-0000'), set())

	def test_a_jwt_is_not_counted_as_an_email_and_a_credential_is_not_counted_twice(self):
		found = sv.scan_text(f'token {JWT} and {AWS_KEY}')
		self.assertEqual(set(found), {'jwt', 'aws_key'})
		found = sv.scan_text(f'key=ab{AWS_KEY}@cd.io')
		self.assertNotIn('aws_key', found.get('email', {}))

	def test_values_are_deduplicated_and_capped(self):
		found = sv.scan_text(' '.join([EMAIL] * 5))
		self.assertEqual(found['email']['count'], 1)
		many = ' '.join(f'user{i}@acme-corp.io' for i in range(80))
		self.assertEqual(sv.scan_text(many)['email']['count'], sv.MAX_PER_TYPE)

	def test_mask_never_exposes_more_than_four_characters_and_handles_short_values(self):
		self.assertEqual(sv.mask(AWS_KEY), 'AK********LE')
		self.assertEqual(sv.mask('abcdefghij'), 'ab******ij')
		for value in ('', 'a', 'abc', 'abcd', 'abcde', 'x' * 100, GITHUB, JWT, PEM):
			out = sv.mask(value)
			shown = sum(1 for a, b in zip(out, value) if a == b != '*')
			self.assertLessEqual(len([c for c in out if c != '*']), 4, value)
			self.assertLessEqual(len(out), 12, value)
		self.assertEqual(sv.mask('abc'), '***')
		self.assertEqual(sv.mask(EMAIL), 'jo**@****.io')
		self.assertNotIn('johndoe', sv.mask(EMAIL))

	def test_scan_text_returns_only_counts_and_masked_samples(self):
		found = sv.scan_text(f'{EMAIL} {AWS_KEY}')
		self.assertEqual(found['aws_key'], {'count': 1, 'sample': 'AWS access key, 20 chars (AKIA...)'})
		self.assertNotIn(AWS_KEY, json.dumps(found))
		self.assertNotIn('johndoe', json.dumps(found))

	def test_score_tiers(self):
		self.assertEqual(sv.sensitive_score({}), 0)
		self.assertEqual(sv.sensitive_score({'aws_key': {'count': 1}}), 25)
		self.assertEqual(sv.sensitive_score({'email': {'count': 5}}), 15)
		self.assertEqual(sv.sensitive_score({'phone': {'count': 3}}), 15)
		self.assertEqual(sv.sensitive_score({'card': {'count': 1}}), 15)
		self.assertEqual(sv.sensitive_score({'email': {'count': 2}}), 5)
		self.assertEqual(sv.sensitive_score({'internal_ip': {'count': 1}}), 5)
		self.assertEqual(sv.sensitive_score({'email': {'count': 9}, 'jwt': {'count': 1}}), 25)

	def test_only_text_like_content_is_scanned(self):
		for ok in ('text/html', 'text/plain; charset=utf-8', 'application/json', 'application/javascript', 'application/vnd.api+json',
				'application/atom+xml', 'APPLICATION/JSON'):
			self.assertTrue(sv.is_text(ok), ok)
		for bad in ('image/png', 'font/woff2', 'application/pdf', 'application/octet-stream', '', None):
			self.assertFalse(sv.is_text(bad), bad)
