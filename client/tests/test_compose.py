"""docker-compose.yml as compose itself reads it (`docker compose config`, which validates and starts nothing), with and without the openvas
profile: every container's log is capped, and the sentinel service stops gracefully, reaps its children and reports its health. Also what
.dockerignore keeps out of the build context."""
import fnmatch
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def compose_config(profiles):
    # Run against a copy, so a developer's own .env or docker-compose.override.yml cannot change the answer.
    with tempfile.TemporaryDirectory(prefix='sentinel-compose-') as tmp:
        shutil.copy(os.path.join(ROOT, 'docker-compose.yml'), tmp)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('COMPOSE_', 'CVENGINE_', 'OPENVAS_'))}
        env['COMPOSE_PROFILES'] = profiles
        out = subprocess.run(['docker', 'compose', 'config', '--format', 'json'], cwd=tmp, env=env, capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


def has_compose():
    if not shutil.which('docker'):
        return False
    return subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode == 0


@unittest.skipUnless(has_compose(), 'needs the docker compose plugin (only its config command is run)')
class ComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.light = compose_config('')
        cls.full = compose_config('openvas')

    def test_light_runs_only_the_sentinel(self):
        self.assertEqual(list(self.light['services']), ['sentinel'])

    def test_every_service_has_a_capped_log(self):
        self.assertGreater(len(self.full['services']), 10)
        for name, service in self.full['services'].items():
            logging = service.get('logging', {})
            self.assertEqual(logging.get('driver'), 'json-file', name)
            self.assertEqual(logging.get('options'), {'max-size': '10m', 'max-file': '3'}, name)

    def test_the_sentinel_stops_gracefully_reaps_children_and_reports_health(self):
        sentinel = self.full['services']['sentinel']
        self.assertTrue(sentinel.get('init'))
        self.assertEqual(sentinel.get('stop_grace_period'), '45s')
        self.assertEqual(sentinel.get('pids_limit'), 512)
        self.assertTrue(sentinel.get('mem_limit'))
        self.assertEqual(sentinel['healthcheck']['test'], ['CMD', 'python3', '-m', 'client.control', 'health'])

    def test_no_greenbone_service_gets_a_memory_limit(self):
        for name, service in self.full['services'].items():
            if name != 'sentinel':
                self.assertNotIn('mem_limit', service, name)

    def test_the_sentinel_image_is_built_here_and_never_pulled(self):
        sentinel = self.full['services']['sentinel']
        self.assertEqual(sentinel.get('pull_policy'), 'build')
        self.assertNotIn('/', sentinel['image'].split(':')[0])  # no registry namespace a pull could ask Docker Hub for

    def test_host_networking_lives_in_the_override_example_not_the_tracked_file(self):
        self.assertNotIn('network_mode', self.full['services']['sentinel'])
        with open(os.path.join(ROOT, 'docker-compose.yml')) as handle:
            self.assertNotIn('network_mode', handle.read())
        with open(os.path.join(ROOT, 'docker-compose.override.yml.example')) as handle:
            self.assertIn('network_mode: host', handle.read())

    def test_the_version_is_left_to_the_image_stamp(self):
        self.assertNotIn('CVENGINE_SENTINEL_VERSION', self.full['services']['sentinel'].get('environment', {}))


def dockerignored(path, rules):
    """Docker's rule for one path: the last pattern that matches the path or one of its parent directories decides, and a ! pattern re-includes
    it; a pattern starting with **/ matches at any depth. A simplified reading of the real matcher, enough for the patterns in .dockerignore."""
    parts = path.split('/')
    candidates = ['/'.join(parts[:i]) for i in range(1, len(parts) + 1)]

    def matches(candidate, pattern):
        if pattern.startswith('**/'):
            return fnmatch.fnmatchcase(candidate.split('/')[-1], pattern[3:])
        return fnmatch.fnmatchcase(candidate, pattern)

    excluded = False
    for rule in rules:
        negate = rule.startswith('!')
        if any(matches(c, rule.lstrip('!')) for c in candidates):
            excluded = not negate
    return excluded


class DockerignoreTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, '.dockerignore')) as handle:
            self.rules = [line.strip() for line in handle if line.strip() and not line.startswith('#')]

    def test_secrets_tests_and_history_stay_out(self):
        for path in ('.env', '.env.bak.20260101000000', 'client/tests/test_blob.py', 'client/__pycache__/x.pyc', 'README.md', 'docs/UPDATES.md',
                     '.git/objects/ab/cdef', '.git/config', '.deployed-commit', 'docker-compose.override.yml'):
            self.assertTrue(dockerignored(path, self.rules), path)

    def test_what_the_dockerfile_copies_stays_in(self):
        for path in ('client/daemon.py', 'requirements.txt', 'docker-entrypoint.sh', 'scripts/ci_openvas_bootstrap.py', 'Dockerfile',
                     '.git/HEAD', '.git/packed-refs', '.git/refs/heads/main'):
            self.assertFalse(dockerignored(path, self.rules), path)


if __name__ == '__main__':
    unittest.main()
