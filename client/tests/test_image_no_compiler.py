"""The final image stage carries no compiler and no C library headers (linux-libc-dev is where every critical and high OS finding of the image was).

Nothing at run time compiles: client/bbot.py starts bbot with its no-deps flag. The final stage's base package list must not install build-essential, and
the steps that do compile while the image is built (nmap from source on arm64, WPScan's native gems, bbot's module dependencies) must be followed
by a purge of build-essential, libc6-dev and linux-libc-dev, which proves they are gone.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def _final_stage(text):
    stages = re.split(r'(?m)^FROM\s', text)
    return stages[-1]


def _runs(stage):
    """Each RUN instruction as one logical line (continuations joined, comments dropped)."""
    lines = [ln for ln in stage.splitlines() if not ln.lstrip().startswith('#')]
    joined = '\n'.join(lines).replace('\\\n', ' ')
    return [ln.strip() for ln in joined.splitlines() if ln.strip().startswith('RUN ')]


class FinalStageNoCompilerTests(unittest.TestCase):
    def setUp(self):
        self.stage = _final_stage((ROOT / 'Dockerfile').read_text(encoding='utf-8'))
        self.runs = _runs(self.stage)

    def test_base_packages_do_not_install_build_essential(self):
        base = [r for r in self.runs if 'apt-get install' in r and 'python3-venv' in r]
        self.assertEqual(len(base), 1, 'the final stage base package install was not found')
        self.assertNotIn('build-essential', base[0])

    def test_compiler_is_purged_after_last_compile_step(self):
        compile_markers = ('build-essential', 'gem install', 'kitchen-sink', 'make -j')
        last_compile = max(i for i, r in enumerate(self.runs) if any(m in r and 'apt-get purge' not in r for m in compile_markers))
        purges = [i for i, r in enumerate(self.runs)
                  if re.search(r'apt-get purge\b[^&]*\bbuild-essential\b', r) and 'linux-libc-dev' in r and 'libc6-dev' in r]
        self.assertTrue(purges, 'the final stage never purges build-essential, libc6-dev and linux-libc-dev')
        self.assertGreater(purges[-1], last_compile, 'a compile step runs after the compiler is purged')
        self.assertIn('! dpkg -s linux-libc-dev', self.runs[purges[-1]])

    def test_no_install_after_purge_brings_a_compiler_back(self):
        purge = max(i for i, r in enumerate(self.runs) if re.search(r'apt-get purge\b[^&]*\bbuild-essential\b', r))
        for r in self.runs[purge + 1:]:
            for pkg in ('build-essential', 'gcc', 'g++', 'libc6-dev', 'linux-libc-dev', '-dev '):
                if 'apt-get install' in r:
                    self.assertNotIn(pkg, r, f'a step after the purge installs {pkg}: {r}')


if __name__ == '__main__':
    unittest.main()
