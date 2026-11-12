"""The nuclei service-port allowlist, as shipped: every template on it was checked (content rule, decode, a person's reading of the exploit class), the vendored
copies of those templates are the files the list's hashes name, and ``scripts/generate_service_allowlist.py`` makes the same list from them.

Where the pinned library is practical to read: the allowlisted templates are vendored, byte for byte (``cvengine_scanner/fixtures/nuclei_templates``, about 400 KB, MIT,
from nuclei-templates v10.5.1; ``.gitattributes`` keeps their bytes), so CI checks the real files without the 14,000-file library. The templates that were left out are
not vendored (except the ten the reviews named, ``fixtures/nuclei_service_refused``); a test that regenerates the whole list from the full library runs when the library is
present (``NUCLEI_TEMPLATES_DIR``, else ``~/nuclei-templates``: the Sentinel image has it there) and is skipped otherwise."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

from client import tools
from cvengine_scanner import nuclei_allowlist as al

ROOT = Path(__file__).resolve().parent.parent.parent
VENDORED = ROOT / 'cvengine_scanner' / 'fixtures' / 'nuclei_templates'
REFUSED = ROOT / 'cvengine_scanner' / 'fixtures' / 'nuclei_service_refused'


def _generator():
    spec = importlib.util.spec_from_file_location('generate_service_allowlist', ROOT / 'scripts' / 'generate_service_allowlist.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _generator()


def _library():
    for candidate in (os.environ.get('NUCLEI_TEMPLATES_DIR'), os.path.join(os.path.expanduser('~'), 'nuclei-templates')):
        if candidate and os.path.isdir(os.path.join(candidate, 'network')) and os.path.isdir(os.path.join(candidate, 'javascript')):
            return candidate
    return None


class VendoredTemplatesTests(unittest.TestCase):
    def setUp(self):
        self.data = al.load_allowlist()

    def test_the_vendored_files_are_exactly_the_allowlisted_templates_with_the_recorded_hashes(self):
        vendored = {p.relative_to(VENDORED).as_posix() for p in VENDORED.rglob('*.yaml')}
        self.assertEqual(vendored, {e['path'] for e in self.data['templates'].values()})
        for tid, entry in self.data['templates'].items():
            with self.subTest(template=tid):
                allowed, why, found = al.check_file(VENDORED / entry['path'], self.data)
                self.assertTrue(allowed, why)
                self.assertEqual(found, tid)

    def test_every_allowlisted_template_passes_the_content_rule_and_the_decode(self):
        """At the pinned release. A template a person read and restored (``reviewed_exceptions``) is the one allowed to fail them, and only those two."""
        failed = []
        for tid, entry in self.data['templates'].items():
            path = VENDORED / entry['path']
            rule = tools._paced_template(str(path))
            decode = al.credential_findings(path.read_text(encoding='utf-8'))
            if (rule or decode) and tid not in self.data['reviewed_exceptions']:
                failed.append((tid, rule, decode[:2]))
        self.assertEqual(failed, [])
        self.assertEqual(sorted(self.data['reviewed_exceptions']), ['perforce-detection', 'smb-signing'])

    def test_what_the_two_checks_flag_in_the_refused_templates_they_agree_on(self):
        """Where the content rule flags a template, the decode flags it too; the decode also flags what the rule cannot see (the seven the third review named)."""
        for path in sorted(REFUSED.glob('*.yaml')):
            with self.subTest(template=path.stem):
                decode = al.credential_findings(path.read_text(encoding='utf-8'))
                self.assertTrue(decode)
                if tools._paced_template(str(path)):
                    self.assertTrue(decode)
        missed_by_the_rule = [p.stem for p in REFUSED.glob('*.yaml') if tools._paced_template(str(p)) is None]
        self.assertTrue({'backdoored-zte', 'tidb-unauth', 'clickhouse-unauth', 'CVE-2022-24706', 'CVE-2024-54772'} <= set(missed_by_the_rule))

    def test_no_allowlisted_template_names_a_port_the_target_does_not(self):
        """A literal port in a host or address is recorded as ``fixed_ports`` (a run sends the template only to a target on it); anything else follows the target."""
        for tid, entry in self.data['templates'].items():
            doc = GEN.yaml.safe_load((VENDORED / entry['path']).read_text(encoding='utf-8'))
            self.assertEqual(entry.get('fixed_ports', []), GEN.fixed_ports(doc), tid)

    def test_no_allowlisted_template_is_udp_self_contained_credentialed_or_of_another_protocol(self):
        for tid, entry in self.data['templates'].items():
            text = (VENDORED / entry['path']).read_text(encoding='utf-8')
            doc = GEN.yaml.safe_load(text)
            with self.subTest(template=tid):
                self.assertFalse(GEN._UDP.search(text))
                self.assertFalse(doc.get('self-contained'))
                self.assertFalse([k for k in GEN.OTHER_KEYS if doc.get(k)])
                self.assertFalse(GEN.javascript_reasons(doc))
                self.assertFalse(set(doc['info'].get('tags', '').split(',') if isinstance(doc['info'].get('tags'), str) else doc['info'].get('tags', [])) & set(tools.flags.NUCLEI_SERVICE_EXCLUDED_TAGS))

    def test_every_exploit_class_template_on_the_list_was_read_with_this_content(self):
        review = json.loads(al.REVIEW_FILE.read_text(encoding='utf-8'))
        exploit = []
        for tid, entry in self.data['templates'].items():
            doc = GEN.yaml.safe_load((VENDORED / entry['path']).read_text(encoding='utf-8'))
            tags = doc['info'].get('tags', [])
            tags = [t.strip() for t in tags.split(',')] if isinstance(tags, str) else tags
            if GEN.exploit_class(tags, entry['severity']):
                exploit.append(tid)
                self.assertEqual(review['read_only'].get(tid), entry['sha256'], tid)
                self.assertNotIn(tid, review['refused'])
        self.assertGreater(len(exploit), 30)  # the critical, high and medium ones that remain
        self.assertFalse(set(review['refused']) & set(self.data['templates']))


class GeneratorTests(unittest.TestCase):
    """The generator and the shipped list agree."""

    def test_regenerating_from_the_vendored_files_gives_the_shipped_list(self):
        allowlist, left, _facts = GEN.analyse(VENDORED, GEN.load_review(), self.data_release())
        self.assertEqual(left['templates'], {})  # every vendored file is kept: they are the list
        self.assertEqual(allowlist['templates'], al.load_allowlist()['templates'])
        self.assertEqual(allowlist['reviewed_exceptions'], sorted(al.load_allowlist()['reviewed_exceptions']))

    @staticmethod
    def data_release():
        return al.load_allowlist()['nuclei_templates']

    @unittest.skipUnless(_library(), 'the pinned nuclei-templates library is not here (NUCLEI_TEMPLATES_DIR, or ~/nuclei-templates in the image)')
    def test_regenerating_from_the_whole_pinned_library_gives_the_shipped_files(self):
        allowlist, left, _facts = GEN.analyse(_library(), GEN.load_review(), self.data_release())
        self.assertEqual(GEN.dump(allowlist), al.ALLOWLIST_FILE.read_text(encoding='utf-8'))
        self.assertEqual(GEN.dump(left), al.LEFT_OUT_FILE.read_text(encoding='utf-8'))

    def library(self, files, review=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for rel, text in files.items():
            path = Path(tmp.name, rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        allowlist, left, _facts = GEN.analyse(tmp.name, {'read_only': {}, 'refused': {}, 'restored': {}, **(review or {})}, 'vTEST')
        return allowlist['templates'], left['templates']

    TCP = 'id: {id}\ninfo:\n  name: x\n  severity: {severity}\n  tags: {tags}\ntcp:\n  - host:\n      - "{host}"\n    inputs:\n      - data: "\\n"\n    port: 21\n'

    def test_a_new_template_is_left_out_until_it_was_read_when_it_is_of_the_exploit_class(self):
        files = {'network/a.yaml': self.TCP.format(id='plain-detect', severity='info', tags='ftp,detect', host='{{Hostname}}'),
                 'network/b.yaml': self.TCP.format(id='new-cve', severity='critical', tags='cve,ftp', host='{{Hostname}}')}
        kept, left = self.library(files)
        self.assertIn('plain-detect', kept)
        self.assertIn('new-cve', left)
        self.assertIn('not reviewed', left['new-cve']['reasons'][0])
        digest = left['new-cve']['sha256']
        kept, left = self.library(files, {'read_only': {'new-cve': digest}})
        self.assertIn('new-cve', kept)
        kept, left = self.library(files, {'read_only': {'new-cve': '0' * 64}})  # read with other content: read again
        self.assertIn('new-cve', left)
        kept, left = self.library(files, {'read_only': {'new-cve': digest}, 'refused': {'new-cve': 'writes a file'}})
        self.assertIn('writes a file', left['new-cve']['reasons'][-1])

    def test_a_template_with_a_credential_a_udp_probe_or_another_protocol_is_left_out_with_each_reason(self):
        files = {
            'network/cred.yaml': 'id: cred\ninfo:\n  name: x\n  severity: info\n  tags: ftp\ntcp:\n  - inputs:\n      - data: "root\\r\\n"\n',
            'javascript/udp.yaml': 'id: udp\ninfo:\n  name: x\n  severity: info\n  tags: ntp\njavascript:\n  - code: |\n      let c = require("nuclei/net").Open("udp", Host + ":" + Port);\n',
            'network/both.yaml': 'id: both\ninfo:\n  name: x\n  severity: info\n  tags: ftp\ntcp:\n  - inputs:\n      - data: "\\n"\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}"\n',
            'javascript/login.yaml': 'id: login\ninfo:\n  name: x\n  severity: info\n  tags: mysql\njavascript:\n  - code: |\n      const m = require("nuclei/mysql");\n      new m.MySQLClient().Connect(Host, Port, "a", "b");\n',
            'javascript/info.yaml': 'id: infoonly\ninfo:\n  name: x\n  severity: info\n  tags: ssh\njavascript:\n  - args:\n      Host: "{{Host}}"\n      Port: "22"\n    code: |\n      const m = require("nuclei/ssh");\n      Export(m.SSHClient().ConnectSSHInfoMode(Host, Port));\n',
        }
        kept, left = self.library(files)
        self.assertEqual(sorted(kept), ['infoonly'])
        self.assertTrue(any('sent account name' in r for r in left['cred']['reasons']))
        self.assertTrue(any('UDP' in r for r in left['udp']['reasons']))
        self.assertTrue(any('http' in r for r in left['both']['reasons']))
        self.assertTrue(any('Connect' in r and 'not on the read-only list' in r for r in left['login']['reasons']))

    def test_a_template_that_names_a_port_of_its_own_is_listed_with_it(self):
        kept, _left = self.library({'network/p.yaml': self.TCP.format(id='two-ports', severity='info', tags='detect', host='{{Hostname}}:1666'),
                                    'network/q.yaml': self.TCP.format(id='follows', severity='info', tags='detect', host='{{Hostname}}')})
        self.assertEqual(kept['two-ports']['fixed_ports'], [1666])
        self.assertNotIn('fixed_ports', kept['follows'])

    def test_a_template_a_person_restored_keeps_its_hash_and_loses_it_when_the_file_changes(self):
        text = 'id: named\ninfo:\n  name: x\n  severity: info\n  tags: smb\njavascript:\n  - args:\n      Host: "{{Host}}"\n      User: "test"\n    code: |\n      Export(require("nuclei/smb").SMBClient().ListSMBv2Metadata(Host, Port));\n'
        kept, left = self.library({'javascript/n.yaml': text})
        self.assertIn('named', left)
        digest = left['named']['sha256']
        kept, left = self.library({'javascript/n.yaml': text}, {'restored': {'named': {'sha256': digest, 'reason': 'read'}}})
        self.assertTrue(kept['named']['restored'])
        kept, left = self.library({'javascript/n.yaml': text + '# changed\n'}, {'restored': {'named': {'sha256': digest, 'reason': 'read'}}})
        self.assertIn('named', left)


if __name__ == '__main__':
    unittest.main()
