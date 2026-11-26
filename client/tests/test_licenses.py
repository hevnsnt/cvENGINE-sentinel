"""The licence files, notices and source offer the repository and the image carry (docker/licenses, LICENSE, README.md, client/vendor/node2shell.py).

The image side is checked in the built image by scripts/ci_image_licenses.py (.github/workflows/image.yml); these tests hold the sources of those files
to the Dockerfile's pins, so a version bump that forgets the notices fails here, before any image is built.
"""
import os
import re
import sys
import tempfile
import unittest
import unittest.mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIC = os.path.join(ROOT, 'docker', 'licenses')


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as handle:
        return handle.read()


def dockerfile_args():
    return dict(re.findall(r'^ARG (\w+)=(\S+)', read('Dockerfile'), re.M))


class RepositoryLicenseTests(unittest.TestCase):
    def test_the_repository_carries_the_gpl_3_text_and_a_copyright_line(self):
        text = read('LICENSE')
        self.assertTrue(text.lstrip().startswith('GNU GENERAL PUBLIC LICENSE'))
        self.assertIn('Version 3, 29 June 2007', text)
        self.assertIn('END OF TERMS AND CONDITIONS', text)
        self.assertIn('license = "GPL-3.0-only"', read('pyproject.toml'))
        self.assertIn('Copyright (C) 2026 Bill Swearingen and contributors', read('README.md'))
        self.assertIn('Copyright (C) 2026 Bill Swearingen and contributors', read('docker', 'licenses', 'THIRD-PARTY-NOTICES.txt'))

    def test_the_vendored_node2shell_file_keeps_its_mit_notice(self):
        head = read('client', 'vendor', 'node2shell.py').split('"""', 1)[0]
        self.assertIn('Copyright (c) 2026 Assetnote', head)
        self.assertIn('Permission is hereby granted, free of charge', head)
        self.assertIn('The above copyright notice and this permission notice shall be included in all', head)
        self.assertIn('Copyright (c) 2026 Assetnote', read('docker', 'licenses', 'node2shell-scanner', 'LICENSE'))

    def test_the_nmap_text_is_the_npsl(self):
        text = read('docker', 'licenses', 'nmap', 'LICENSE')
        self.assertTrue(text.startswith('Nmap Public Source License Version 0.95'))
        self.assertGreater(len(text), 25000)  # the whole licence, GPLv2 exhibit included, not an excerpt

    def test_every_pinned_tool_version_is_in_the_notices(self):
        notices = read('docker', 'licenses', 'THIRD-PARTY-NOTICES.txt')
        versions = {name: value for name, value in dockerfile_args().items() if name.endswith('VERSION')}
        self.assertIn('WPSCAN_VERSION', versions)
        for name, value in versions.items():
            lines = [line for line in notices.splitlines() if f'(ARG {name})' in line]
            self.assertTrue(lines, f'THIRD-PARTY-NOTICES.txt names no (ARG {name})')
            self.assertTrue(any(value in line for line in lines), f'THIRD-PARTY-NOTICES.txt does not give {name}={value}: {lines}')

    def test_the_source_offer_names_the_pinned_sources(self):
        offer = read('docker', 'licenses', 'SOURCE-OFFER.txt')
        args = dockerfile_args()
        for name in ('NMAP_SHA256', 'GOWITNESS_SRC_SHA256'):
            self.assertIn(args[name], offer, name)
        for name in ('NMAPVERSION', 'GOWITNESS_VERSION', 'TESTSSL_VERSION', 'BBOT_VERSION', 'WPSCAN_VERSION', 'NUCLEI_VERSION', 'NAABU_VERSION',
                     'SSHAMBLE_VERSION', 'TRAJAN_VERSION', 'KINGFISHER_VERSION', 'NUCLEI_TEMPLATES_VERSION', 'GOVERSION', 'PLAYWRIGHT_CHROMIUM_VERSION'):
            self.assertIn(args[name], offer, name)
        self.assertIn('Written offer', offer)
        self.assertIn('MODIFIED', offer)

    def test_the_notices_keep_the_house_prose_rule(self):
        for name in ('THIRD-PARTY-NOTICES.txt', 'SOURCE-OFFER.txt'):
            text = read('docker', 'licenses', name)
            for bad in ('\u2014', '\u2013', '--'):
                self.assertNotIn(bad, text, name)

    def test_the_dockerfile_installs_the_licence_directory_and_checks_it(self):
        text = read('Dockerfile')
        for line in ('COPY LICENSE /usr/share/licenses/cvengine-sentinel/LICENSE',
                     'COPY docker/licenses/THIRD-PARTY-NOTICES.txt docker/licenses/SOURCE-OFFER.txt /usr/share/licenses/cvengine-sentinel/',
                     'COPY docker/licenses/nmap /usr/share/licenses/cvengine-sentinel/nmap',
                     'COPY docker/licenses/node2shell-scanner /usr/share/licenses/cvengine-sentinel/node2shell-scanner',
                     'COPY --from=gotools /out/doc /usr/share/licenses/cvengine-sentinel/',
                     'RUN python3 /tmp/collect-licenses.py'):
            self.assertIn(line, text)
        self.assertIn('cp /usr/local/go/LICENSE /usr/local/go/PATENTS /out/doc/go/', text)
        build = read('docker', 'gotools', 'build.sh')
        self.assertIn('cp go.mod go.sum "$doc/"', build)
        self.assertIn('"$doc/MODIFICATIONS"', build)
        self.assertIn('go list -deps', build)
        self.assertIn('ci_image_licenses.py', read('.github', 'workflows', 'image.yml'))
        ignore = read('.dockerignore')
        self.assertNotIn('docker/licenses', ignore)
        self.assertNotIn('*.txt', ignore)


class ImageCheckTests(unittest.TestCase):
    """scripts/ci_image_licenses.py and docker/licenses/collect.py agree on what a complete directory is, and name what is missing."""

    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, 'scripts'))
        sys.path.insert(0, LIC)
        self.addCleanup(sys.path.remove, os.path.join(ROOT, 'scripts'))
        self.addCleanup(sys.path.remove, LIC)
        import ci_image_licenses
        import collect
        self.check, self.collect = ci_image_licenses, collect

    def test_an_empty_directory_names_every_required_file(self):
        with tempfile.TemporaryDirectory() as empty:
            bad = self.check.problems(empty)
        for rel in ('LICENSE', 'nmap/LICENSE', 'wpscan/LICENSE', 'SOURCE-OFFER.txt', 'nuclei/LICENSE.md', 'naabu/LICENSE.md'):
            self.assertTrue(any(b.startswith(rel + ' ') for b in bad), rel)

    def test_a_complete_directory_passes_and_a_wrong_text_does_not(self):
        with tempfile.TemporaryDirectory() as root:
            def put(rel, text='licence text\n'):
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'w', encoding='utf-8') as handle:
                    handle.write(text)
            for rel, phrase in self.check.FILES.items():
                put(rel, (phrase or 'x') + '\n')
            for pattern in self.check.GLOBS:
                put(pattern.replace('*', '1.0'))
            self.assertEqual(self.check.problems(root), [])
            put('nmap/LICENSE', 'GNU GENERAL PUBLIC LICENSE\n')
            self.assertEqual(self.check.problems(root), ["nmap/LICENSE (does not say 'Nmap Public Source License')"])

    def test_the_build_check_requires_what_the_image_check_requires(self):
        for rel in ('LICENSE', 'THIRD-PARTY-NOTICES.txt', 'SOURCE-OFFER.txt', 'nmap/LICENSE', 'node2shell-scanner/LICENSE', 'wpscan/LICENSE'):
            self.assertIn(rel, self.collect.REQUIRED_FILES)
            self.assertIn(rel, self.check.FILES)
        for name in ('nuclei', 'naabu', 'sshamble', 'gowitness', 'trajan', 'go', 'testssl.sh', 'nuclei-templates', 'kingfisher'):
            self.assertIn(name, self.collect.REQUIRED_DIRS)

    def test_collect_reads_a_python_venv_and_a_gem_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = os.path.join(tmp, 'venv', 'lib', 'python3.14', 'site-packages', 'demo-1.2.dist-info')
            os.makedirs(os.path.join(info, 'licenses'))
            with open(os.path.join(info, 'METADATA'), 'w', encoding='utf-8') as handle:
                handle.write('Metadata-Version: 2.4\nName: demo\nVersion: 1.2\nLicense-Expression: AGPL-3.0-only\n\n')
            with open(os.path.join(info, 'licenses', 'LICENSE'), 'w', encoding='utf-8') as handle:
                handle.write('GNU AFFERO GENERAL PUBLIC LICENSE\n')
            dest = os.path.join(tmp, 'out')
            with unittest.mock.patch.object(self.collect, 'DEST', dest):
                self.collect.python_venv(os.path.join(tmp, 'venv'), 'venv')
            with open(os.path.join(dest, 'python', 'venv', 'INDEX.txt'), encoding='utf-8') as handle:
                self.assertIn('demo\t1.2\tAGPL-3.0-only', handle.read())
            self.assertTrue(os.path.isfile(os.path.join(dest, 'python', 'venv', 'demo-1.2', 'licenses', 'LICENSE')))


if __name__ == '__main__':
    unittest.main()
