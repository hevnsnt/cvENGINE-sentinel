"""The real, pinned Kingfisher (cvENGINE docs/SECRETS-PLAN.md 6.2 and 13): every flag the client passes exists in it, its version is the pin, and a
detection pass over synthetic pages finds the planted secrets. The CI job ``kingfisher`` downloads the attested binary and runs this module, once
normally and once (``DetectionTests``) inside a network namespace with no route, which proves the detection pass needs no network at all. Without
``CVENGINE_KINGFISHER_REAL`` (every other job) the module is skipped."""
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from cvengine_scanner import secrets as kf

REAL = os.environ.get('CVENGINE_KINGFISHER_REAL') == '1'
BIN = os.environ.get('CVENGINE_KINGFISHER_BIN', 'kingfisher')
ROOT = Path(__file__).resolve().parents[2]
PAGE = ('<html><script>var cfg = {apiKey: "AIzaSyA1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUVw", databaseURL: "https://example-app-default-rtdb.firebaseio.com",'
        ' storageBucket: "example-app.appspot.com"};</script></html>\n')
# Made-up values that only look like keys. Kingfisher skips the AWS documentation pair (it ends in EXAMPLE), so the test needs shapes it does
# report; they are put together at run time, so the repository never holds a string a secret scanner would take for a real key.
AWS_ID = 'AK' + 'IAQYLPMN5HHHFPZAM2'
AWS_SECRET = '1tUm636uS1yOEcfP5pvf' + 'qJ/ml36mF7AkyHsEU0IU'
SCRIPT = (f'const aws_access_key_id = "{AWS_ID}";\nconst aws_secret_access_key = "{AWS_SECRET}";\n'
          'const token = "ghp_R2d2C3p0BB8LuK3sKyw4lK3rTHx9vZ01aBcD";\n')


@unittest.skipUnless(REAL, 'runs in the kingfisher CI job, with the pinned binary (CVENGINE_KINGFISHER_REAL=1)')
class FlagTests(unittest.TestCase):
    def test_every_flag_the_client_passes_exists(self):
        help_text = subprocess.run([BIN, 'scan', '--help'], capture_output=True, text=True, timeout=30).stdout
        known = set(re.findall(r'--[a-z][a-z0-9-]+', help_text))
        used = {a.split('=')[0] for a in kf.scan_argv(BIN, 'in', 'out.json', rules_path='r.yml', skip_words=['EXAMPLE'], skip_regex=['^x$'])
                + kf.validation_argv(BIN, 'in', 'out.json', ['betterleaks.github-pat']) if a.startswith('--')}
        self.assertEqual(sorted(used - known), [])

    def test_the_binary_is_the_pin(self):
        version = kf.version_of(subprocess.run([BIN, '--version'], capture_output=True, text=True, timeout=30).stdout)
        dockerfile = re.search(r'^ARG KINGFISHER_VERSION=(\S+)$', (ROOT / 'Dockerfile').read_text(), re.M).group(1)
        self.assertEqual((version, dockerfile), (kf.KINGFISHER_VERSION, kf.KINGFISHER_VERSION))


@unittest.skipUnless(REAL, 'runs in the kingfisher CI job, with the pinned binary (CVENGINE_KINGFISHER_REAL=1)')
class DetectionTests(unittest.TestCase):
    def test_a_detection_pass_finds_the_planted_secrets_with_no_network(self):
        with tempfile.TemporaryDirectory() as work:
            inputs = Path(work) / 'in'
            inputs.mkdir()
            (inputs / '0.html').write_text(PAGE)
            (inputs / '1.js').write_text(SCRIPT)
            manifest = {'0.html': {'url': 'https://www.example.test/', 'kind': 'page'},
                        '1.js': {'url': 'https://www.example.test/app.js', 'kind': 'script'}}
            out = Path(work) / 'out.json'
            argv = kf.scan_argv(BIN, inputs, out)
            done = subprocess.run(argv, capture_output=True, timeout=kf.WALL_SECONDS, env=kf.env_without_egress(os.environ))
            self.assertIn(done.returncode, kf.SUCCESS_CODES, done.stderr[-500:])
            findings, truncated = kf.read_report(out.read_text(), manifest)
        found = {(f['rule_id'], f['url']) for f in findings}
        self.assertFalse(truncated)
        self.assertIn(('betterleaks.gcp-api-key', 'https://www.example.test/'), found)
        self.assertIn(('betterleaks.aws-access-token', 'https://www.example.test/app.js'), found)
        self.assertIn(('betterleaks.aws-secret-access-key', 'https://www.example.test/app.js'), found)  # the pair's secret half
        self.assertIn(('betterleaks.github-pat', 'https://www.example.test/app.js'), found)
        self.assertEqual({f['validation']['outcome'] for f in findings}, {'not_attempted'})
