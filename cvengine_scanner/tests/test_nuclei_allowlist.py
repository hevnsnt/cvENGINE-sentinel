"""The service-port allowlist (``cvengine_scanner.nuclei_allowlist``): the files it ships, how a template is checked against it, and the decode that reads a
template's strings in plain text, hex and base64 for what authenticates. The templates the third review named are real files (``fixtures/nuclei_service_refused``,
MIT, from nuclei-templates v10.5.1)."""
import json
import re
import tempfile
import unittest
from pathlib import Path

from cvengine_scanner import nuclei_allowlist as al

FIXTURES = Path(__file__).resolve().parent.parent / 'fixtures'
REFUSED = FIXTURES / 'nuclei_service_refused'
# the seven the third review named (N7), then the others the decode and the review keep out
NAMED = ('backdoored-zte', 'tidb-unauth', 'clickhouse-unauth', 'CVE-2022-24706', 'CVE-2026-83548', 'CVE-2026-55040', 'CVE-2024-54772')


def _templates():
    return al.load_allowlist()['templates']


class ShippedListTests(unittest.TestCase):
    def test_the_list_records_the_release_and_a_sha256_for_every_template(self):
        data = al.load_allowlist()
        self.assertEqual(data['nuclei_templates'], 'v10.5.1')
        self.assertGreater(len(data['templates']), 250)
        for tid, entry in data['templates'].items():
            with self.subTest(template=tid):
                self.assertRegex(entry['sha256'], r'^[0-9a-f]{64}$')
                self.assertTrue(entry['classes'])
                self.assertEqual(entry['severity'], entry['severity'].lower())

    def test_the_release_of_the_list_is_the_release_the_dockerfile_pins(self):
        dockerfile = (Path(__file__).resolve().parent.parent.parent / 'Dockerfile').read_text(encoding='utf-8')
        pinned = re.search(r'(?m)^ARG NUCLEI_TEMPLATES_VERSION=(\S+)$', dockerfile).group(1)
        self.assertEqual(al.load_allowlist()['nuclei_templates'], pinned)

    def test_every_template_left_out_has_a_reason_and_none_is_on_the_list(self):
        left = json.loads(al.LEFT_OUT_FILE.read_text(encoding='utf-8'))
        self.assertEqual(left['nuclei_templates'], al.load_allowlist()['nuclei_templates'])
        self.assertGreater(len(left['templates']), 100)
        self.assertFalse(set(left['templates']) & set(_templates()))
        for tid, entry in left['templates'].items():
            with self.subTest(template=tid):
                self.assertTrue(entry['reasons'])
                self.assertTrue(all(isinstance(r, str) and r for r in entry['reasons']))

    def test_the_seven_templates_the_review_named_are_not_on_the_list_and_say_why(self):
        left = json.loads(al.LEFT_OUT_FILE.read_text(encoding='utf-8'))['templates']
        for tid in NAMED:
            with self.subTest(template=tid):
                self.assertNotIn(tid, _templates())
                self.assertIn(tid, left)

    def test_the_restored_templates_were_read_and_are_recorded(self):
        data = al.load_allowlist()
        self.assertEqual(sorted(data['reviewed_exceptions']), ['mongodb-unauth', 'perforce-detection', 'smb-signing'])
        review = json.loads(al.REVIEW_FILE.read_text(encoding='utf-8'))
        for tid in data['reviewed_exceptions']:
            self.assertEqual(review['restored'][tid]['sha256'], data['templates'][tid]['sha256'])
            self.assertTrue(review['restored'][tid]['reason'])
        for tid in ('perforce-detection', 'smb-signing'):
            self.assertRegex(review['restored'][tid]['reason'], 'captur')
        self.assertNotIn('pgsql-detect', data['templates'])  # it sends a user name and starts a SCRAM login: it stays out
        self.assertEqual(data['templates']['perforce-detection']['fixed_ports'], [1666])  # it also connects to 1666: it runs only on that port

    def test_a_missing_or_broken_list_allows_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            for text in (None, '{', '[]', '{"templates": []}'):
                path = Path(tmp) / 'list.json'
                if text is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(text, encoding='utf-8')
                al.forget()
                self.addCleanup(al.forget)
                self.assertEqual(al.load_allowlist(path)['templates'], {}, text)

    def test_rtl_tcp_server_detect_is_absent_it_sends_set_frequency_and_set_sample_rate(self):
        """Its two hex inputs are rtl_tcp commands 0x01 and 0x02: a setting changed on the target's tuner, which the read-only rule excludes."""
        self.assertNotIn('rtl-tcp-server-detect', _templates())
        left = json.loads(al.LEFT_OUT_FILE.read_text(encoding='utf-8'))['templates']
        self.assertIn('rtl-tcp-server-detect', left)
        self.assertTrue(any('frequency' in r for r in left['rtl-tcp-server-detect']['reasons']))
        review = json.loads(al.REVIEW_FILE.read_text(encoding='utf-8'))
        self.assertIn('frequency', review['refused']['rtl-tcp-server-detect'])

    def test_mongodb_unauth_is_listed_after_a_full_reading_and_the_reading_is_recorded(self):
        entry = _templates()['mongodb-unauth']
        review = json.loads(al.REVIEW_FILE.read_text(encoding='utf-8'))
        self.assertEqual(review['read_only']['mongodb-unauth'], entry['sha256'])
        self.assertEqual(review['restored']['mongodb-unauth']['sha256'], entry['sha256'])  # the decode flags the database name 'admin'
        self.assertIn('startupWarnings', review['restored']['mongodb-unauth']['reason'])
        self.assertIn('mongodb', entry['classes'])


class CheckFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 't.yaml'
        self.text = 'id: probe-detect\ninfo:\n  name: x\ntcp:\n  - host:\n      - "{{Hostname}}"\n'
        self.path.write_text(self.text, encoding='utf-8')
        self.list = {'templates': {'probe-detect': {'sha256': al.sha256_of(self.text.encode())}}, 'reviewed_exceptions': set()}

    def test_a_template_on_the_list_with_its_recorded_content_is_allowed(self):
        self.assertEqual(al.check_file(self.path, self.list), (True, None, 'probe-detect'))

    def test_a_template_the_list_does_not_know_is_refused(self):
        self.path.write_text(self.text.replace('probe-detect', 'brand-new-detect'), encoding='utf-8')
        allowed, why, tid = al.check_file(self.path, self.list)
        self.assertFalse(allowed)
        self.assertIn('not on the service-port allowlist', why)
        self.assertEqual(tid, 'brand-new-detect')

    def test_a_template_whose_content_changed_is_refused_by_one_byte(self):
        self.path.write_text(self.text + '#', encoding='utf-8')
        allowed, why, _tid = al.check_file(self.path, self.list)
        self.assertFalse(allowed)
        self.assertIn('sha256 changed', why)

    def test_a_file_that_cannot_be_read_or_has_no_id_or_is_huge_is_refused(self):
        self.assertFalse(al.check_file(Path(self.tmp.name) / 'missing.yaml', self.list)[0])
        self.path.write_text('info:\n  name: no id\n', encoding='utf-8')
        self.assertFalse(al.check_file(self.path, self.list)[0])
        self.path.write_text('id: probe-detect\n' + 'x' * (al.MAX_TEMPLATE_BYTES + 1), encoding='utf-8')
        self.assertFalse(al.check_file(self.path, self.list)[0])

    def test_the_id_is_read_from_the_top_level_key_only(self):
        self.path.write_text('info:\n  description: |\n    id: probe-detect\n', encoding='utf-8')
        self.assertFalse(al.check_file(self.path, self.list)[0])


def findings(text):
    return al.credential_findings(text)


class DecodeTests(unittest.TestCase):
    """What authenticates is found in plain text, hex and base64, whatever the verb: the way the third review found what the rule missed."""

    def test_the_seven_templates_the_review_named_are_each_flagged_from_their_real_files(self):
        for tid in NAMED:
            with self.subTest(template=tid):
                self.assertTrue(findings((REFUSED / f'{tid}.yaml').read_text(encoding='utf-8')), tid)

    def test_what_the_other_refused_templates_send_is_flagged_too(self):
        for tid in ('pgsql-detect', 'dionaea-ftp-honeypot-detect', 'CVE-2021-44521'):
            with self.subTest(template=tid):
                self.assertTrue(findings((REFUSED / f'{tid}.yaml').read_text(encoding='utf-8')), tid)

    def test_a_login_in_hex_with_no_verb_is_found(self):
        text = 'id: a\ntcp:\n  - inputs:\n      - data: "{data}"\n        type: hex\n'
        for data in ('00000003' + b'\x00root\x00mysql_native_password\x00'.hex(),  # a MySQL handshake response
                     b'\x07default\x00\x00'.hex() + '00',  # a ClickHouse hello naming the user
                     b'\x06admin'.hex(),  # a MikroTik user name
                     b'user\x00postgres\x00'.hex()):
            self.assertTrue(findings(text.format(data=data)), data)

    def test_a_login_in_base64_is_found(self):
        import base64
        for raw in (b'Authorization: Basic YWRtaW46YWRtaW4=', b'root:toor', b'USER admin'):
            text = f'id: a\njavascript:\n  - code: |\n      send("{base64.b64encode(raw).decode()}")\n'
            self.assertTrue(findings(text), raw)

    def test_a_plain_account_name_or_a_cookie_or_a_header_is_found(self):
        for body in ('tcp:\n  - inputs:\n      - data: "root\\r\\n"\n', 'tcp:\n  - inputs:\n      - data: "Zte521\\r\\nAUTH x\\r\\n"\n', 'variables:\n  cookie: monster\ntcp:\n  - inputs:\n      - data: "x"\n',
                     'javascript:\n  - code: |\n      req.Header.Set("Authorization: Bearer " + t)\n', 'javascript:\n  - args:\n      Host: "{{Host}}"\n      User: "test"\n    code: |\n      x'):
            self.assertTrue(findings('id: a\n' + body), body)

    def test_a_template_that_only_reads_a_banner_has_no_finding(self):
        for body in ('tcp:\n  - inputs:\n      - data: "\\n"\n    matchers:\n      - type: word\n        words:\n          - "220"\n',
                     'tcp:\n  - inputs:\n      - data: 00000000\n        type: hex\n    matchers:\n      - type: dsl\n        dsl:\n          - "contains(raw, \'FileZilla\')"\n',
                     'javascript:\n  - args:\n      Host: "{{Host}}"\n      Port: "22"\n    code: |\n      // the server may want a password; this reads the banner only\n      let c = require("nuclei/ssh").SSHClient();\n      Export(c.ConnectSSHInfoMode(Host, Port));\n'):
            self.assertEqual(findings('id: a\n' + body), [], body)

    def test_the_strings_a_reply_must_hold_are_not_read_as_what_is_sent(self):
        """A matcher says what the server answers (``password:`` after a telnet banner): it is never a credential of ours."""
        body = 'tcp:\n  - inputs:\n      - data: "\\n"\n    matchers:\n      - type: word\n        words:\n          - "login:"\n          - "Password"\n    extractors:\n      - type: regex\n        regex:\n          - "user ([a-z]+)"\n'
        self.assertEqual(findings('id: a\n' + body), [])

    def test_a_number_written_as_hex_keeps_its_zeros(self):
        """YAML reads ``data: 00000000`` as the number 0: the loader leaves it as the text it was, so its bytes are not changed."""
        text = 'id: a\ntcp:\n  - inputs:\n      - data: 00726f6f74\n        type: hex\n'
        self.assertTrue(findings(text))  # b'\x00root'

    def test_a_template_that_cannot_be_read_is_a_finding(self):
        self.assertTrue(findings('id: a\n  : [broken'))
        self.assertTrue(findings('- just\n- a list\n'))


if __name__ == '__main__':
    unittest.main()
