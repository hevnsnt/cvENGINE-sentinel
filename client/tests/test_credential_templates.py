"""TL-2 item 3 on the Sentinel: a nuclei run that does not carry ``allow_credential_checks`` leaves out the installed templates that send a credential of their
own, through a list made once per templates release (``client.credential_templates``)."""
import os
import tempfile
import unittest
from unittest import mock

from client import credential_templates as ct
from client import tools

BASIC = ("id: planted-basic\ninfo: {name: x, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n    headers:\n      Authorization: \"Basic YWRtaW46YWRtaW4=\"\n"
         "    matchers:\n      - type: word\n        words: [ok]\n")
PLAIN = "id: plain\ninfo: {name: x, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n    matchers:\n      - type: word\n        words: [ok]\n"
PLACEHOLDER = BASIC.replace('planted-basic', 'placeholder').replace('Basic YWRtaW46YWRtaW4=', 'Bearer {{token}}')


class Library(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.dir = os.path.join(self.home.name, 'nuclei-templates')
        os.makedirs(os.path.join(self.dir, 'http'))
        for name, text in (('basic', BASIC), ('plain', PLAIN), ('placeholder', PLACEHOLDER)):
            with open(os.path.join(self.dir, 'http', f'{name}.yaml'), 'w') as handle:
                handle.write(text)
        patcher = mock.patch.dict(os.environ, {'HOME': self.home.name, 'CVENGINE_NUCLEI_TEMPLATES_DIR': self.dir})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.basic = os.path.join(self.dir, 'http', 'basic.yaml')

    def run_web(self, **kwargs):
        seen = {}

        def fake_run(argv, timeout, register=None, env=None):
            seen['argv'] = list(argv)
            if '-et' in argv:
                with open(argv[argv.index('-et') + 1], encoding='utf-8') as handle:
                    seen['excluded'] = handle.read().split()
            return ''
        with mock.patch('client.tools._run', side_effect=fake_run):
            result = tools.run_nuclei(['www.example.test'], **kwargs)
        return result, seen


def checks_rule_refuses_it_at_200k(path):
    from cvengine_scanner import checks
    with open(path, encoding='utf-8') as handle:
        return checks.credential_problem(handle.read()).endswith('too large')


class ListTests(Library):
    def test_the_list_holds_the_fixed_credential_and_neither_the_placeholder_nor_the_plain_template(self):
        self.assertEqual(ct.compute(self.dir), ([self.basic], []))

    def test_a_template_that_cannot_be_read_or_parsed_is_on_the_list_apart(self):
        broken = os.path.join(self.dir, 'http', 'broken.yaml')
        with open(broken, 'w') as handle:
            handle.write('id: [unclosed token\n  authorization: {\n')
        self.assertEqual(ct.compute(self.dir), ([self.basic], [broken]))
        with mock.patch.object(ct, 'MAX_INSTALLED_BYTES', 100):  # over the ceiling: cannot be judged
            credential, unreadable = ct.compute(self.dir)
        self.assertEqual(credential, [])
        self.assertIn(self.basic, unreadable)

    def test_a_large_template_is_judged_at_its_real_size(self):
        padding = '\n' + ''.join(f'# {i} filler line of a big detection feed\n' for i in range(8000))  # about 350,000 bytes, over the rule's 200,000
        clean = os.path.join(self.dir, 'http', 'big-clean.yaml')
        dirty = os.path.join(self.dir, 'http', 'big-basic.yaml')
        with open(clean, 'w') as handle:
            handle.write(PLAIN.replace('plain', 'big-clean') + padding)
        with open(dirty, 'w') as handle:
            handle.write(BASIC.replace('planted-basic', 'big-basic') + padding)
        self.assertGreater(os.path.getsize(clean), 200_000)
        credential, unreadable = ct.compute(self.dir)
        self.assertEqual(credential, sorted([self.basic, dirty]))  # the large template with a Basic header is excluded
        self.assertEqual(unreadable, [])  # the large clean one stays in
        self.assertTrue(checks_rule_refuses_it_at_200k(dirty))

    def test_the_list_is_kept_and_reused(self):
        self.assertEqual(ct.lists_for(self.dir, 'v1'), ([self.basic], []))
        with mock.patch.object(ct, 'compute', side_effect=AssertionError('made again')):
            self.assertEqual(ct.lists_for(self.dir, 'v1'), ([self.basic], []))

    def test_a_new_release_a_changed_file_set_or_a_new_library_makes_it_again(self):
        ct.lists_for(self.dir, 'v1')
        with mock.patch.object(ct, 'compute', return_value=(['/x'], [])) as made:
            self.assertEqual(ct.lists_for(self.dir, 'v2'), (['/x'], []))  # a new templates release
            self.assertEqual(made.call_count, 1)
        with open(os.path.join(self.dir, 'http', 'another.yaml'), 'w') as handle:
            handle.write(PLAIN.replace('plain', 'another'))
        with mock.patch.object(ct, 'compute', return_value=(['/y'], [])) as made:
            self.assertEqual(ct.lists_for(self.dir, 'v2'), (['/y'], []))  # a file was added
            self.assertEqual(made.call_count, 1)
        with mock.patch.object(ct, 'RULE_REV', ct.RULE_REV + 1), mock.patch.object(ct, 'compute', return_value=(['/z'], [])) as made:
            self.assertEqual(ct.lists_for(self.dir, 'v2'), (['/z'], []))  # the rule changed
            self.assertEqual(made.call_count, 1)

    def test_an_unreadable_or_damaged_cache_means_make_it_now(self):
        ct.lists_for(self.dir, 'v1')
        for path in ct._cache_paths(self.dir):
            if os.path.exists(path):
                with open(path, 'w') as handle:
                    handle.write('{"paths": 5')
        self.assertEqual(ct.lists_for(self.dir, 'v1'), ([self.basic], []))

    def test_a_directory_that_cannot_be_read_raises(self):
        with self.assertRaises(ct.CredentialListError):
            ct.lists_for(os.path.join(self.home.name, 'missing'), 'v1')


class RunTests(Library):
    def test_a_run_without_the_field_leaves_out_the_planted_template_and_says_how_many(self):
        result, seen = self.run_web()
        self.assertEqual(seen['excluded'], [self.basic])
        self.assertEqual(result['cuts'], [{'what': 'templates_with_credentials', 'kind': 'items', 'limit': 0, 'dropped': 1}])  # one count, not names

    def test_unreadable_templates_are_counted_apart(self):
        with open(os.path.join(self.dir, 'http', 'broken.yaml'), 'w') as handle:
            handle.write('id: [unclosed token\n  authorization: {\n')
        result, seen = self.run_web()
        self.assertEqual(result['cuts'], [{'what': 'templates_with_credentials', 'kind': 'items', 'limit': 0, 'dropped': 1},
                                          {'what': 'templates_unreadable', 'kind': 'items', 'limit': 0, 'dropped': 1}])
        self.assertEqual(len(seen['excluded']), 2)

    def test_a_run_with_the_field_on_does_not(self):
        result, seen = self.run_web(allow_credential_checks=True)
        self.assertNotIn('-et', seen['argv'])
        self.assertNotIn('cuts', result)

    def test_a_bundle_is_filtered_the_same_way(self):
        bundle = os.path.join(self.home.name, 'bundle-abc')
        os.makedirs(os.path.join(bundle, 'http'))
        with open(os.path.join(bundle, 'http', 'basic.yaml'), 'w') as handle:
            handle.write(BASIC)
        _result, seen = self.run_web(templates=bundle)
        self.assertEqual(seen['excluded'], [os.path.join(bundle, 'http', 'basic.yaml')])
        self.assertEqual(sorted(os.listdir(bundle)), ['http'])  # a bundle is verified by its hash: nothing is written into it

    def test_a_set_with_nothing_to_leave_out_gets_no_exclusion(self):
        os.unlink(self.basic)
        _result, seen = self.run_web()
        self.assertNotIn('-et', seen['argv'])

    def test_when_the_list_cannot_be_made_the_unfiltered_set_does_not_run(self):
        with mock.patch.object(ct, 'lists_for', side_effect=ct.CredentialListError('boom')), mock.patch('client.tools._run') as fake_run:
            result = tools.run_nuclei(['www.example.test'])
        fake_run.assert_not_called()
        self.assertEqual(result['unreachable'], ['www.example.test'])  # the server keeps it due
        self.assertIn('credential', result['not_checked'][0]['reason'])

    def test_the_exclusion_file_is_removed_after_the_run(self):
        _result, seen = self.run_web()
        self.assertFalse(os.path.exists(seen['argv'][seen['argv'].index('-et') + 1]))

    def test_every_kind_that_runs_installed_templates_goes_through_the_same_path(self):
        # nuclei_light, nuclei_targeted and nuclei_deep all run ``run_nuclei``; a signed-in run does too
        from client import tools as t
        self.assertEqual({t.RUNNERS[k] for k in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep')}, {t.run_nuclei})


class WarmTests(Library):
    def test_the_start_makes_the_list_so_the_first_task_does_not(self):
        tools.warm_credential_templates()
        with mock.patch.object(ct, 'compute', side_effect=AssertionError('made inside a task')):
            _result, seen = self.run_web()
        self.assertEqual(seen['excluded'], [self.basic])

    def test_the_start_never_raises(self):
        with mock.patch.object(ct, 'lists_for', side_effect=RuntimeError('boom')):
            tools.warm_credential_templates()
