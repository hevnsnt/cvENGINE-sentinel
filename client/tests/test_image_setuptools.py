"""Every setuptools the image installs is at least 78.1.1 (CVE-2025-47273, path traversal in PackageIndex).

Each venv in the Dockerfile is bootstrapped with a pinned `pip install pip==... setuptools==... wheel==...`; this keeps every such pin at or above
the fixed release and makes sure no venv's bootstrap line drops setuptools and falls back to whatever the base image or pip would pick."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
FLOOR = (78, 1, 1)


def _version(text):
    return tuple(int(p) for p in text.split('.'))


class SetuptoolsFloorTests(unittest.TestCase):
    def setUp(self):
        self.dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')

    def test_every_setuptools_pin_is_fixed(self):
        pins = re.findall(r'\bsetuptools==([0-9][0-9.]*)', self.dockerfile)
        self.assertTrue(pins, 'the Dockerfile pins no setuptools at all')
        for pin in pins:
            self.assertGreaterEqual(_version(pin), FLOOR, f'setuptools=={pin} is below 78.1.1 (CVE-2025-47273)')

    def test_no_unpinned_or_loose_setuptools(self):
        for line in self.dockerfile.splitlines():
            if line.lstrip().startswith('#'):
                continue
            for m in re.finditer(r'\bsetuptools(?![-_a-zA-Z])(\S*)', line):
                self.assertTrue(m.group(1).startswith('=='), f'setuptools is installed without an exact pin: {line.strip()}')

    def test_every_pip_bootstrap_pins_setuptools(self):
        for line in self.dockerfile.splitlines():
            if re.search(r'pip install .*\bpip==', line):
                self.assertRegex(line, r'\bsetuptools==', f'a venv bootstrap leaves setuptools to chance: {line.strip()}')


if __name__ == '__main__':
    unittest.main()
