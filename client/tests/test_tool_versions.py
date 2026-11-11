"""scripts/check_tool_versions.py: every pin in the Dockerfile, requirements.txt and docker-compose.yml is compared with its upstream's newest release.
The upstream answers here are recorded shapes (never the network); the module is loaded from the script, which is not a package."""
import importlib.util
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent
spec = importlib.util.spec_from_file_location('check_tool_versions', ROOT / 'scripts' / 'check_tool_versions.py')
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)

NEW_DIGEST = 'sha256:' + 'a' * 64
OLD_DIGEST = 'sha256:' + 'b' * 64

DOCKERFILE = '''FROM ubuntu:26.04@%s AS builder
FROM ubuntu:26.04@%s
ARG GOVERSION=1.27.3
ARG NMAPVERSION=7.993
ARG NUCLEI_VERSION=3.11.1
ARG NAABU_VERSION=2.7.0
ARG WPSCAN_VERSION=4.2.0
ARG WAFW00F_VERSION=2.4.2
ARG PYSOCKS_VERSION=1.7.1
ARG TZDATA_VERSION=2025.2
ARG TESTSSL_VERSION=3.2.5
ARG BBOT_VERSION=3.0.2
ARG KINGFISHER_VERSION=2.16.0
ARG SSHAMBLE_VERSION=0.5.1
ARG NUCLEI_TEMPLATES_VERSION=v10.5.1
ARG PLAYWRIGHT_CHROMIUM_VERSION=158.0.8127.18
ARG KINGFISHER_SHA256_AMD64=%s
RUN pip install --no-cache-dir pip==25.2 setuptools==80.9.0 wheel==0.45.1
''' % (OLD_DIGEST, OLD_DIGEST, 'c' * 64)
REQUIREMENTS = '''xmltodict==1.0.4  # a comment
Pillow==13.0.0
# playwright==0.0.1 is only a comment
playwright==1.65.0
'''
COMPOSE = '''services:
  gvmd:
    image: "registry.community.greenbone.net/community/gvmd:stable@%s"
  data:
    image: "registry.community.greenbone.net/community/vulnerability-tests:community"
''' % OLD_DIGEST

PYPI = {'PySocks': '1.7.1', 'tzdata': '2025.2', 'Pillow': '13.0.0', 'xmltodict': '1.0.4', 'playwright': '1.65.0', 'pip': '25.2', 'setuptools': '80.9.0', 'wheel': '0.45.1', 'wafw00f': '2.4.2',
        'bbot': '3.0.2'}
GO = {'nuclei/v3': 'v3.11.1', 'naabu/v2': 'v2.7.0'}


def answers(**override):
    """The recorded upstream answers, every tool current, keyed by URL; ``override`` replaces one by a substring of its URL."""
    table = {
        'https://nmap.org/dist/': '<a href="nmap-7.993.tar.bz2">nmap-7.993.tar.bz2</a> <a href="nmap-7.99.tar.bz2">x</a>',
        'https://rubygems.org/api/v1/gems/wpscan.json': {'version': '4.2.0'},
        'https://go.dev/dl/?mode=json': [{'version': 'go1.28rc1', 'stable': False}, {'version': 'go1.27.3', 'stable': True}],
        'https://api.github.com/repos/testssl/testssl.sh/tags?per_page=30': [{'name': '3.3dev'}, {'name': 'v3.2.5'}, {'name': 'v3.2.4'}],
        'https://api.github.com/repos/mongodb/kingfisher/releases/latest': {'tag_name': 'v2.16.0'},
        'https://api.github.com/repos/runZeroInc/sshamble/releases/latest': {'tag_name': 'v0.5.1'},
        'https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest': {'tag_name': 'v10.5.1'},
        'https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions': {'versions': [{'version': '158.0.8127.18'}]},
        'https://hub.docker.com/v2/repositories/library/ubuntu/tags/26.04': {'digest': OLD_DIGEST},
        'https://registry.community.greenbone.net/v2/community/gvmd/manifests/stable': {'digest': OLD_DIGEST},
    }
    for name, version in PYPI.items():
        table['https://pypi.org/pypi/%s/json' % name] = {'info': {'version': version}}
    for module, version in GO.items():
        table['https://proxy.golang.org/github.com/projectdiscovery/%s/@latest' % module] = {'Version': version}
    for part, value in override.items():
        hits = [url for url in table if part in url]
        assert len(hits) == 1, (part, hits)
        table[hits[0]] = value
    return table


def getter(table):
    def get(url, as_json=True):
        if url not in table:
            raise OSError('unexpected url ' + url)  # a pin with no recorded answer reads as unreachable
        return table[url]
    return get


class Checkout:
    """A temporary checkout holding the three files the script reads."""
    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.write('Dockerfile', DOCKERFILE)
        self.write('requirements.txt', REQUIREMENTS)
        self.write('docker-compose.yml', COMPOSE)
        return self

    def write(self, name, text):
        (self.root / name).write_text(text)

    def __exit__(self, *exc):
        self.tmp.cleanup()


def rows_of(table, checkout):
    return {r['tool']: r for r in tools.collect(getter(table), root=checkout.root)}


class ComparisonTests(unittest.TestCase):
    def test_a_newer_upstream_release_is_behind(self):
        with Checkout() as c:
            rows = rows_of(answers(**{'nmap.org': '<a href="nmap-7.995.tar.bz2">'}), c)
        self.assertTrue(rows['nmap']['behind'])
        self.assertEqual((rows['nmap']['pinned'], rows['nmap']['latest']), ('7.993', '7.995'))

    def test_everything_at_its_newest_is_current(self):
        with Checkout() as c:
            rows = rows_of(answers(), c)
        self.assertEqual([r['tool'] for r in rows.values() if r['behind']], [])
        self.assertEqual([r['tool'] for r in rows.values() if r['latest'] is None or r['pinned'] is None], [])

    def test_versions_compare_numerically_not_as_text(self):
        self.assertTrue(tools.version_key('3.10.1') > tools.version_key('3.9.9'))
        self.assertTrue(tools.version_key('7.99') < tools.version_key('7.993'))

    def test_every_kind_of_pin_is_read(self):
        with Checkout() as c:
            rows = rows_of(answers(), c)
        for tool in ('go (toolchain)', 'nmap', 'nuclei', 'naabu', 'wpscan', 'wafw00f', 'testssl.sh', 'bbot', 'kingfisher', 'sshamble',
                     'nuclei-templates', 'pip', 'setuptools', 'wheel', 'xmltodict', 'playwright'):
            self.assertIn(tool, rows)
        for tool in ('pysocks', 'tzdata', 'pillow'):
            self.assertIn(tool, rows)
        self.assertEqual(rows['kingfisher']['pinned'], '2.16.0')
        self.assertEqual(rows['nuclei-templates']['pinned'], '10.5.1')

    def test_each_upstream_is_read_in_its_own_shape(self):
        with Checkout() as c:
            rows = rows_of(answers(**{'tags?per_page': [{'name': 'v3.3dev'}, {'name': 'v3.2.9'}], 'kingfisher/releases': {'tag_name': 'v2.18.1'},
                                      'proxy.golang.org/github.com/projectdiscovery/nuclei': {'Version': 'v3.12.0'},
                                      'go.dev': [{'version': 'go1.99rc1', 'stable': False}, {'version': 'go1.27.4', 'stable': True}],
                                      'pypi.org/pypi/playwright': {'info': {'version': '1.66.0'}}}), c)
        self.assertEqual([rows[t]['latest'] for t in ('testssl.sh', 'kingfisher', 'nuclei', 'go (toolchain)', 'playwright')],
                         ['3.2.9', '2.18.1', '3.12.0', '1.27.4', '1.66.0'])
        self.assertTrue(all(rows[t]['behind'] for t in ('testssl.sh', 'kingfisher', 'nuclei', 'go (toolchain)', 'playwright')))

    def test_a_commented_out_pin_is_not_a_pin(self):
        with Checkout() as c:
            rows = rows_of(answers(), c)
        self.assertEqual(rows['playwright']['pinned'], '1.65.0')

    def test_the_base_image_digest_is_compared_with_the_registry(self):
        with Checkout() as c:
            current = rows_of(answers(), c)['ubuntu:26.04 (base image)']
            moved = rows_of(answers(**{'library/ubuntu': {'digest': NEW_DIGEST}}), c)['ubuntu:26.04 (base image)']
        self.assertFalse(current['behind'])
        self.assertTrue(moved['behind'])
        self.assertEqual(moved['latest'], NEW_DIGEST[:19])

    def test_a_greenbone_image_pinned_by_digest_is_compared_and_a_moving_tag_is_not(self):
        with Checkout() as c:
            rows = rows_of(answers(**{'gvmd/manifests': {'digest': NEW_DIGEST}}), c)
        self.assertTrue(rows['greenbone gvmd']['behind'])
        self.assertNotIn('greenbone vulnerability-tests', rows)

    def test_the_chromium_build_is_advisory_and_never_behind(self):
        with Checkout() as c:
            rows = rows_of(answers(**{'versionhistory': {'versions': [{'version': '159.0.1.2'}, {'version': '158.0.8127.18'}]}}), c)
        row = rows['chromium (Playwright build)']
        self.assertEqual((row['behind'], row['behind_advisory'], row['advisory']), (False, True, True))

    def test_pysocks_and_tzdata_are_required_pins(self):
        """Delete or rename either ARG and the row must not just vanish: the gate fails (S2)."""
        for arg in ('PYSOCKS_VERSION', 'TZDATA_VERSION'):
            self.assertTrue(tools.DOCKERFILE_ARGS[arg][3], arg)
            with Checkout() as c:
                c.write('Dockerfile', re.sub(rf'(?m)^ARG {arg}=\S+\n', '', DOCKERFILE))
                rows = tools.collect(getter(answers()), root=c.root)
            missing = [r['tool'] for r in tools.failing(rows) if r['pinned'] is None]
            self.assertEqual(missing, [{'PYSOCKS_VERSION': 'pysocks', 'TZDATA_VERSION': 'tzdata'}[arg]])

    def test_an_advisory_row_that_is_older_than_the_newest_says_behind_not_newer(self):
        row = tools.row('chromium', '156.0.8078.4', '157.0.8103.50', True)
        self.assertTrue(row['behind_advisory'])
        self.assertFalse(row['behind'])
        self.assertIn('behind (advisory)', tools.report([row]))
        self.assertNotIn('newer', tools.report([row]))
        self.assertIn('::warning::chromium: 156.0.8078.4 is pinned, 157.0.8103.50 is the newest release.', tools.warnings([row]))
        self.assertEqual(tools.failing([row]), [])

    def test_a_crash_exits_2_so_a_release_override_cannot_cover_it(self):
        """Python exits 1 on an uncaught error, the same as 'behind': the script turns a crash into 2 (S1)."""
        with mock.patch.object(tools, 'collect', side_effect=RuntimeError('boom')), redirect_stdout(io.StringIO()):
            with mock.patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit) as caught:
                tools.run(['--fail-if-behind'])
        self.assertEqual(caught.exception.code, 2)


class FailClosedTests(unittest.TestCase):
    def exit_code(self, rows, *flags):
        with mock.patch.object(tools, 'collect', return_value=rows), redirect_stdout(io.StringIO()):
            try:
                tools.main(list(flags))
            except SystemExit as leave:
                return leave.code
        return 0

    def test_an_unreachable_site_is_unknown_in_the_report_and_fails_the_gate(self):
        def offline(url, as_json=True):
            raise OSError('offline')
        with Checkout() as c:
            rows = tools.collect(offline, root=c.root)
        self.assertTrue(rows and all(r['latest'] is None and not r['behind'] for r in rows))
        self.assertTrue(all(r['pinned'] for r in rows))
        self.assertEqual(self.exit_code(rows), 0)
        self.assertEqual(self.exit_code(rows, '--fail-if-behind'), 1)

    def test_a_missing_pin_is_a_row_with_no_pin_and_fails_the_gate(self):
        with Checkout() as c:
            c.write('Dockerfile', DOCKERFILE.replace('ARG NMAPVERSION=7.993\n', ''))
            rows = rows_of(answers(), c)
        self.assertIsNone(rows['nmap']['pinned'])
        self.assertEqual(self.exit_code(list(rows.values()), '--fail-if-behind'), 1)

    def test_a_version_argument_with_no_known_upstream_fails_the_gate(self):
        with Checkout() as c:
            c.write('Dockerfile', DOCKERFILE + 'ARG BRANDNEW_VERSION=1.2.3\n')
            rows = rows_of(answers(), c)
        self.assertEqual((rows['BRANDNEW_VERSION']['pinned'], rows['BRANDNEW_VERSION']['latest']), ('1.2.3', None))
        self.assertEqual(self.exit_code(list(rows.values()), '--fail-if-behind'), 1)

    def test_behind_exits_nonzero_only_with_the_flag(self):
        rows = [{'tool': 'x', 'pinned': '1', 'latest': '2', 'behind': True}]
        self.assertEqual(self.exit_code(rows), 0)
        self.assertEqual(self.exit_code(rows, '--fail-if-behind'), 1)

    def test_current_exits_zero_and_an_advisory_row_never_gates(self):
        rows = [{'tool': 'x', 'pinned': '2', 'latest': '2', 'behind': False},
                {'tool': 'chromium', 'pinned': '1', 'latest': '2', 'behind': False, 'ahead': True, 'advisory': True},
                {'tool': 'unreadable advisory', 'pinned': '1', 'latest': None, 'behind': False, 'advisory': True}]
        self.assertEqual(self.exit_code(rows, '--fail-if-behind'), 0)

    def test_one_unreachable_site_does_not_hide_the_others(self):
        table = answers()
        del table['https://nmap.org/dist/']
        with Checkout() as c:
            rows = rows_of(table, c)
        self.assertIsNone(rows['nmap']['latest'])
        self.assertEqual(rows['kingfisher']['latest'], '2.16.0')


class ReportTests(unittest.TestCase):
    def test_the_table_names_tool_pinned_latest_and_state(self):
        rows = [{'tool': 'nmap', 'pinned': '7.993', 'latest': '7.995', 'behind': True},
                {'tool': 'naabu', 'pinned': '2.7.0', 'latest': '2.7.0', 'behind': False},
                {'tool': 'bbot', 'pinned': '3.0.2', 'latest': None, 'behind': False}]
        text = tools.report(rows)
        self.assertIn('| Tool | Pinned | Latest | State |', text)
        self.assertRegex(text, r'\| nmap \| 7\.993 \| 7\.995 \| behind \|')
        self.assertRegex(text, r'\| naabu \| 2\.7\.0 \| 2\.7\.0 \| current \|')
        self.assertRegex(text, r'\| bbot \| 3\.0\.2 \| \? \| unknown \|')

    def test_json_output_and_the_warning_lines(self):
        rows = [{'tool': 'nmap', 'pinned': '7.993', 'latest': '7.995', 'behind': True}]
        with mock.patch.object(tools, 'collect', return_value=rows), redirect_stdout(io.StringIO()) as out:
            tools.main(['--json'])
        self.assertEqual(json.loads(out.getvalue()), rows)
        with mock.patch.object(tools, 'collect', return_value=rows), redirect_stdout(io.StringIO()) as out:
            tools.main(['--github-warnings'])
        self.assertIn('::warning::nmap: 7.993 is pinned, 7.995 is the newest release', out.getvalue())


class RealCheckoutTests(unittest.TestCase):
    """The script against this repository's own files, with every upstream answering 'unreachable': what it reads from the files must be complete."""
    def rows(self):
        def offline(url, as_json=True):
            raise OSError('offline')
        return tools.collect(offline)

    def test_every_version_pin_in_the_dockerfile_is_a_row_with_a_known_upstream(self):
        text = (ROOT / 'Dockerfile').read_text()
        args = re.findall(r'(?m)^ARG ([A-Z0-9_]*VERSION)=\S+$', text)
        self.assertTrue(args)
        unknown = [a for a in args if a not in tools.DOCKERFILE_ARGS]
        self.assertEqual(unknown, [], 'a new version ARG needs a row in DOCKERFILE_ARGS (its upstream), or the release gate fails closed')

    def test_every_requirements_pin_is_a_row(self):
        names = re.findall(r'(?m)^([A-Za-z0-9_.-]+)==', (ROOT / 'requirements.txt').read_text())
        rows = {r['tool'] for r in self.rows()}
        self.assertEqual([n for n in names if n.lower() not in rows], [])

    def test_every_requirement_with_a_version_is_an_exact_pin_the_checker_reads(self):
        """A range (Pillow>=13,<14) would never be compared: every package line must be name==version (S3)."""
        lines = [l.split('#')[0].strip() for l in (ROOT / 'requirements.txt').read_text().splitlines()]
        lines = [l for l in lines if l]
        self.assertEqual([l for l in lines if '==' not in l], [])
        self.assertIn('pillow', {r['tool'] for r in self.rows()})

    def test_the_urls_are_fixed_https_hosts(self):
        for row in self.rows():
            self.assertTrue(row['pinned'], row['tool'])
        for url in tools.all_urls():
            self.assertTrue(url.startswith('https://'), url)


class WorkflowTests(unittest.TestCase):
    def workflow(self, name):
        return (ROOT / '.github' / 'workflows' / name).read_text()

    def test_the_weekly_run_and_the_pull_request_job_use_the_script(self):
        text = self.workflow('tool-releases.yml')
        self.assertIn("cron:", text)
        self.assertIn('pull_request:', text)
        self.assertIn('scripts/check_tool_versions.py --github-warnings', text)  # the pull request job reports, it has no --fail-if-behind
        self.assertNotRegex(text.split('pull-request:')[1], r'--fail-if-behind')

    def test_tagging_a_release_waits_for_the_gate(self):
        text = self.workflow('tag-release.yml')
        self.assertIn('scripts/check_tool_versions.py --fail-if-behind', text)
        self.assertRegex(text, r'(?m)^  tag:\n    needs: tools$')


class WorkflowHardeningTests(unittest.TestCase):
    def workflow(self, name):
        return (ROOT / '.github' / 'workflows' / name).read_text()

    def job(self, text, name):
        return re.split(rf'(?m)^  {name}:\n', text, maxsplit=1)[1].split('\n\n  ')[0]

    def test_a_release_override_needs_a_reason_that_is_recorded(self):
        text = self.workflow('tag-release.yml')
        self.assertRegex(text, r'(?m)^      tools_reviewed_reason:')
        gate = self.job(text, 'tools')
        self.assertIn('REASON: ${{ inputs.tools_reviewed_reason }}', gate)
        self.assertRegex(gate, r'(?s)-z .*REASON.*::error::')  # an empty reason fails
        self.assertIn('GITHUB_STEP_SUMMARY', gate)
        self.assertIn('github.actor', gate)
        self.assertIn('inputs.ref', gate)

    def test_a_crash_of_the_check_is_not_overridable(self):
        gate = self.job(self.workflow('tag-release.yml'), 'tools')
        self.assertRegex(gate, r'status=\$\?')
        self.assertRegex(gate, r'(?s)"\$status" -ne 1.*exit "\$status"')
        self.assertLess(gate.index('-ne 1'), gate.index('REVIEWED" = "true"'))

    def test_read_only_jobs_get_a_read_only_token(self):
        gate = self.job(self.workflow('tag-release.yml'), 'tools')
        self.assertRegex(gate, r'(?s)permissions:\n\s+contents: read')
        self.assertRegex(self.job(self.workflow('tag-release.yml'), 'tag'), r'(?s)permissions:\n\s+contents: write')
        releases = self.workflow('tool-releases.yml')
        self.assertNotIn('issues: write', releases.split('\njobs:')[0])
        self.assertRegex(self.job(releases, 'pull-request'), r'(?s)permissions:\n\s+contents: read\n')
        self.assertNotIn('issues: write', self.job(releases, 'pull-request'))
        self.assertIn('issues: write', self.job(releases, 'weekly'))

    def test_the_weekly_issue_step_neither_duplicates_nor_files_an_empty_issue(self):
        weekly = self.job(self.workflow('tool-releases.yml'), 'weekly')
        self.assertNotIn('|| true', weekly)
        self.assertIn('set -euo pipefail', weekly)
        self.assertRegex(weekly, r'(?s)tee "\$RUNNER_TEMP/tools.md".*-ne 0')  # the first run's failure and a crash of the second stop the step


if __name__ == '__main__':
    unittest.main()
