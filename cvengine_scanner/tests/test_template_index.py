"""The template index (``cvengine_scanner.template_index``): the shipped file describes the pinned release, each verdict is this library's rule, and a policy
approves exactly what the server's rule for an installed template would (``cveFeed.validation.installed_template_problem``)."""
import hashlib
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

from cvengine_scanner import checks, flags, nuclei_allowlist, template_index as ti

ROOT = Path(__file__).resolve().parent.parent.parent


def _generator():
    spec = importlib.util.spec_from_file_location('generate_template_index', ROOT / 'scripts' / 'generate_template_index.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ShippedIndexTests(unittest.TestCase):
    def setUp(self):
        ti.forget()
        self.index = ti.load()

    def test_it_describes_the_release_the_dockerfile_pins(self):
        pinned = re.search(r'(?m)^ARG NUCLEI_TEMPLATES_VERSION=(\S+)$', (ROOT / 'Dockerfile').read_text(encoding='utf-8')).group(1)
        self.assertEqual(ti.release(), pinned)
        self.assertEqual(self.index['nuclei_templates'], nuclei_allowlist.load_allowlist()['nuclei_templates'])
        self.assertGreater(len(self.index['templates']), 10_000)
        self.assertEqual(ti.digest(), hashlib.sha256(ti.INDEX_FILE.read_bytes()).hexdigest())

    def test_every_entry_is_well_formed(self):
        reasons = len(self.index['reasons'])
        for path, entry in self.index['templates'].items():
            self.assertRegex(path, r'^(?!/)[A-Za-z0-9_./+-]+\.ya?ml$')
            self.assertNotIn('..', path.split('/'))
            self.assertRegex(entry['sha256'], r'^[0-9a-f]{64}$')
            self.assertTrue(entry['id'])
            for verdict in ti.VERDICTS:
                if verdict in entry:
                    self.assertTrue(0 <= entry[verdict] < reasons, (path, verdict))

    def test_the_index_and_the_service_allowlist_agree_on_every_template_both_record(self):
        hashes = {}
        for entry in self.index['templates'].values():
            hashes.setdefault(entry['id'], set()).add(entry['sha256'])
        for tid, listed in nuclei_allowlist.load_allowlist()['templates'].items():
            with self.subTest(template=tid):
                self.assertIn(listed['sha256'], hashes.get(tid, set()))

    def test_the_policies_nest(self):
        sets = {name: set(ti.approved(read_only, credentials)) for name, read_only, credentials in
                (('readonly', True, False), ('readonly-cred', True, True), ('all', False, False), ('all-cred', False, True))}
        self.assertLess(sets['readonly'], sets['readonly-cred'])
        self.assertLess(sets['readonly'], sets['all'])
        self.assertLess(sets['all'], sets['all-cred'])
        self.assertLess(sets['readonly-cred'], sets['all-cred'])
        self.assertIn('http/technologies/tech-detect.yaml', sets['readonly'])  # the light pass's fingerprint is never policy-excluded

    def test_a_cve_is_found_by_its_file_name(self):
        found = ti.for_cve('CVE-2021-44228')
        self.assertTrue(found)
        self.assertTrue(all(Path(path).stem.upper() == 'CVE-2021-44228' for path, _e in found))
        self.assertEqual(ti.for_cve('cve-2021-44228'), found)
        self.assertEqual(ti.for_cve(''), [])
        path, entry = found[0]
        self.assertEqual(ti.by_sha256(entry['sha256'])[0][0], path)


class VerdictTests(unittest.TestCase):
    """The verdicts are this library's rules, and ``policy_problem`` composes them as the server's rule for an installed template does."""

    def entry(self, text):
        reasons = []
        return _generator().entry_for(text.encode(), reasons), {'nuclei_templates': 'v0', 'rules': 1, 'reasons': reasons, 'templates': {}, 'sha256': ''}

    READ = 'id: r\ninfo:\n  name: r\n  severity: info\n  tags: tech,panel\n  metadata:\n    vendor: Acme\n    product: Widget\n' \
           '  classification:\n    cpe: cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/"\n'
    POST = READ.replace('method: GET', 'method: POST')
    CRED = READ + '    headers:\n      Authorization: Basic YWRtaW46YWRtaW4=\n'
    TAGGED = READ.replace('tags: tech,panel', 'tags: default-login,panel')

    def test_metadata_is_read_from_info(self):
        entry, _index = self.entry(self.READ)
        self.assertEqual((entry['id'], entry['tags'], entry['vendor'], entry['product'], entry['cpe']), ('r', ['panel', 'tech'], 'acme', 'widget', 'a:acme:widget'))
        self.assertEqual(entry['sha256'], hashlib.sha256(self.READ.encode()).hexdigest())

    def test_each_policy_composes_the_verdicts_like_the_server(self):
        cases = {  # text -> (readonly, readonly-cred, all, all-cred) approved
            self.READ: (True, True, True, True), self.POST: (False, False, True, True), self.CRED: (False, True, False, True), self.TAGGED: (False, True, False, True)}
        for text, want in cases.items():
            entry, index = self.entry(text)
            got = tuple(not ti.policy_problem(entry, read_only, credentials, index) for read_only, credentials in ((True, False), (True, True), (False, False), (False, True)))
            with self.subTest(text=text[-60:]):
                self.assertEqual(got, want)
                if text is not self.TAGGED:  # a credential tag is refused whatever the text says
                    self.assertEqual(bool(ti.policy_problem(entry, True, False, index)), bool(checks.readonly_problem(text)))

    def test_a_file_that_is_too_large_or_not_utf8_never_runs_and_one_without_an_id_is_no_template(self):
        gen = _generator()
        for raw in (b'id: big\n' + b'#' * ti.MAX_TEMPLATE_BYTES, b'id: bad\n\xff\xfe'):
            reasons = []
            entry = gen.entry_for(raw, reasons)
            index = {'nuclei_templates': 'v0', 'rules': 1, 'reasons': reasons, 'templates': {}, 'sha256': ''}
            self.assertTrue(ti.policy_problem(entry, False, True, index))
        self.assertIsNone(gen.entry_for(b'info:\n  name: helper\n', []))

    def test_a_missing_or_broken_index_approves_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            for content in (None, 'not json', json.dumps({'templates': []})):
                path = Path(tmp) / 'index.json'
                if content is not None:
                    path.write_text(content, encoding='utf-8')
                ti.forget()
                index = ti.load(path)
                with self.subTest(content=content):
                    self.assertEqual(index['templates'], {})
                    self.assertEqual(ti.approved(False, True, index), {})
        ti.forget()
        self.assertTrue(ti.policy_problem(None))

    def test_the_credential_tags_are_the_flags(self):
        self.assertEqual(set(flags.NUCLEI_CREDENTIAL_TAGS), {'default-login', 'bruteforce'})
