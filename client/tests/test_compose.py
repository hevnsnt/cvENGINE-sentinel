"""docker-compose.yml as compose itself reads it (`docker compose config`, which validates and starts nothing), with and without the openvas
profile: every container's log is capped, and the sentinel service stops gracefully, reaps its children and reports its health. Also what
.dockerignore keeps out of the build context, the pins in the Dockerfile and the CI workflows, and scripts/greenbone-digests.sh against a
stand-in registry."""
import fnmatch
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def compose_config(profiles, host_network=False):
    # Run against a copy, so a developer's own .env or docker-compose.override.yml cannot change the answer.
    with tempfile.TemporaryDirectory(prefix='sentinel-compose-') as tmp:
        shutil.copy(os.path.join(ROOT, 'docker-compose.yml'), tmp)
        shutil.copytree(os.path.join(ROOT, 'config'), os.path.join(tmp, 'config'))  # compose reads the seccomp profile the sentinel service names
        if host_network:  # what ./setup.sh --host-network writes
            shutil.copy(os.path.join(ROOT, 'docker-compose.override.yml.example'), os.path.join(tmp, 'docker-compose.override.yml'))
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
        cls.host = compose_config('', host_network=True)

    def test_light_runs_only_the_sentinel(self):
        self.assertEqual(sorted(self.light['services']), ['sentinel', 'sentinel-init'])  # the Sentinel and the one-shot that hands it its state volume

    def test_every_service_has_a_capped_log(self):
        self.assertGreater(len(self.full['services']), 10)
        for name, service in self.full['services'].items():
            logging = service.get('logging', {})
            self.assertEqual(logging.get('driver'), 'json-file', name)
            self.assertEqual(logging.get('options'), {'max-size': '10m', 'max-file': '3'}, name)

    def test_the_state_volume_is_handed_to_the_unprivileged_user_before_the_sentinel_starts(self):
        for config in (self.light, self.full):
            init, sentinel = config['services']['sentinel-init'], config['services']['sentinel']
            self.assertEqual(init['user'], '0:0')
            self.assertEqual(init['network_mode'], 'none')
            self.assertEqual(init['entrypoint'], ['chown', '-R', '10001:10001', '/var/lib/cvengine-sentinel'])
            self.assertEqual(sorted(init['cap_add']), ['CHOWN', 'DAC_OVERRIDE', 'FOWNER'])
            self.assertEqual(init['cap_drop'], ['ALL'])
            # nothing else is mounted but the state volume and the badkeys volume nested in it (so an older badkeys volume is handed over too)
            self.assertEqual(sorted(v['target'] for v in init['volumes']), ['/var/lib/cvengine-sentinel', '/var/lib/cvengine-sentinel/badkeys'])
            self.assertEqual(sentinel['depends_on']['sentinel-init']['condition'], 'service_completed_successfully')
            self.assertNotIn('user', sentinel)  # the image's own USER applies, so docker compose exec runs as the unprivileged user too

    def test_the_badkeys_data_has_a_named_volume_the_unprivileged_user_owns(self):
        for config in (self.light, self.full):
            mounts = {v['target']: v.get('source') for v in config['services']['sentinel']['volumes']}
            self.assertEqual(mounts['/var/lib/cvengine-sentinel/badkeys'], 'sentinel-badkeys')
            self.assertIn('sentinel-badkeys', config['volumes'])
            self.assertIn('CVENGINE_BADKEYS_REFRESH', config['services']['sentinel']['environment'])
            self.assertNotIn('CVENGINE_BADKEYS_URL', json.dumps(config))  # the source is fixed inside the tool: not configurable
        with open(os.path.join(ROOT, 'Dockerfile')) as handle:
            text = handle.read()
        self.assertRegex(text, r'(?m)^\s*&& chown sentinel:sentinel /var/lib/cvengine-sentinel /var/lib/cvengine-sentinel/badkeys$')

    def test_the_image_runs_unprivileged_with_capabilities_on_the_two_raw_socket_tools_only(self):
        with open(os.path.join(ROOT, 'Dockerfile')) as handle:
            text = handle.read()
        self.assertRegex(text, r'(?m)^USER sentinel$')
        self.assertIn('--uid 10001', text)
        for binary in ('nmap', 'naabu'):  # one setcap per file: libcap's setcap takes a single file for each capability spec
            self.assertRegex(text, rf'setcap cap_net_raw\+eip /usr/local/bin/{binary}\b')  # NET_RAW alone: a file capability the container's set lacks stops the program starting
        self.assertNotIn('cap_net_admin', text.replace('NET_ADMIN', ''))  # (the comment may name it)
        self.assertEqual(text.count('setcap'), 2)  # exactly these two: nothing else is given a capability
        self.assertIn('NMAP_PRIVILEGED=1', text)
        self.assertIn('GOBIN=/usr/local/bin', text)  # the tools are installed where the unprivileged user can run them
        self.assertLess(text.index('RUN useradd'), text.index('USER sentinel'))
        self.assertNotIn('nuclei -update-templates', text)  # templates are pinned, not downloaded at build or start
        self.assertIn('NUCLEI_TEMPLATES_SHA256=', text)

    # The capability set (SN-8), for the default stack and with host networking. Every entry is proven by CI:
    # scripts/ci_scan_smoke.sh runs the scans in the built image under exactly these settings (.github/workflows/image.yml).

    def test_the_sentinel_keeps_net_raw_and_sys_chroot_and_nothing_else(self):
        for name, config in (('light', self.light), ('full', self.full), ('host network', self.host)):
            sentinel = config['services']['sentinel']
            self.assertEqual(sentinel.get('cap_drop'), ['ALL'], name)
            self.assertEqual(sorted(sentinel.get('cap_add')), ['NET_RAW', 'SYS_CHROOT'], name)  # NET_ADMIN is gone: no scan needs it (the nmap and naabu smoke runs in CI); SYS_CHROOT is Chromium's sandbox
            self.assertFalse(sentinel.get('privileged'), name)
            self.assertNotIn('NET_ADMIN', json.dumps(sentinel), name)
            self.assertNotIn('SYS_ADMIN', json.dumps(sentinel), name)

    def test_host_networking_changes_the_network_and_nothing_about_the_privileges(self):
        light, host = self.light['services']['sentinel'], self.host['services']['sentinel']
        self.assertEqual(host.get('network_mode'), 'host')
        self.assertNotIn('network_mode', light)
        for key in ('cap_add', 'cap_drop', 'read_only', 'security_opt', 'privileged', 'pids_limit', 'mem_limit'):
            self.assertEqual(host.get(key), light.get(key), key)

    def test_the_root_filesystem_stays_writable_and_the_file_says_what_blocks_read_only(self):
        # read_only: true was tried in CI with memory-backed ~/.config, ~/.cache, ~/.bbot/{cache,logs,temp} and /tmp: every scan tool worked except bbot's
        # discovery, which makes a working directory inside ~/.bbot/tools (907 MB of tools baked into the image) and dies when it is read-only. A tmpfs there
        # would hide the tools, so for 1.4.0 the root is writable; this test fails when someone sets it without the work that remains (the tools moved out).
        for name, config in (('light', self.light), ('full', self.full), ('host network', self.host)):
            sentinel = config['services']['sentinel']
            self.assertFalse(sentinel.get('read_only'), name)
            self.assertFalse(sentinel.get('tmpfs'), name)  # a tmpfs over a baked directory would hide what the image keeps there
        compose = text('docker-compose.yml')
        self.assertIn('~/.bbot/tools', compose)
        self.assertIn('Why the root filesystem is not read-only', text('.github', 'workflows', 'image.yml'))

    def test_no_new_privileges_is_not_set_because_it_would_switch_off_the_file_capabilities(self):
        # The kernel ignores file capabilities under no-new-privileges, so nmap and naabu would lose raw sockets for an unprivileged user (CI shows it).
        for config in (self.light, self.full, self.host):
            self.assertFalse([o for o in config['services']['sentinel'].get('security_opt', []) if 'no-new-privileges' in o])
        self.assertIn('no-new-privileges', text('docker-compose.yml'))  # and the file says why

    def test_the_other_services_are_not_given_more_than_before(self):
        init = self.full['services']['sentinel-init']
        self.assertEqual((init['cap_drop'], sorted(init['cap_add'])), (['ALL'], ['CHOWN', 'DAC_OVERRIDE', 'FOWNER']))
        ospd = self.full['services']['openvas-ospd']  # Greenbone's own scanner image, on its own network: its capabilities are its own (README.md)
        self.assertEqual(sorted(ospd['cap_add']), ['NET_ADMIN', 'NET_RAW'])

    def test_ci_runs_the_scans_in_the_built_image_under_the_compose_settings(self):
        workflow = text('.github', 'workflows', 'image.yml')
        self.assertIn('docker compose run --rm --no-deps -T', workflow)  # the real service definition, not a copy of its flags
        self.assertIn('scripts/ci_scan_smoke.sh', workflow)
        smoke = text('scripts', 'ci_scan_smoke.sh')
        for needle in ('nmap -sS -O', 'nmap -sU', 'naabu -host', '-scan-type s', 'nuclei -u', 'wpscan --url', 'testssl.sh', 'kingfisher scan', 'ci_bbot_start.py'):
            self.assertIn(needle, smoke)

    def test_the_sentinel_container_carries_the_seccomp_profile_chromiums_sandbox_needs(self):
        # Playwright's profile, vendored unchanged (its hash is the one THIRD-PARTY-style note in docker-compose.yml names), on the sentinel service
        # only: the browser runs there and nowhere else, so no other service is loosened.
        profile = os.path.join(ROOT, 'config', 'seccomp', 'playwright-chromium.json')
        with open(profile, 'rb') as handle:
            raw = handle.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), 'cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849')
        body = json.loads(raw)
        self.assertEqual(body['defaultAction'], 'SCMP_ACT_ERRNO')
        allowed = {name for rule in body['syscalls'] if rule['action'] == 'SCMP_ACT_ALLOW' for name in rule['names']}
        self.assertTrue({'clone', 'setns', 'unshare'} <= allowed)
        for config in (self.light, self.full):
            options = config['services']['sentinel'].get('security_opt') or []
            self.assertEqual(len(options), 1, options)
            self.assertTrue(options[0].startswith('seccomp='), options)
            self.assertTrue(options[0].endswith('config/seccomp/playwright-chromium.json'), options)  # the file, whatever way compose spells its path
            for name, service in config['services'].items():
                if name != 'sentinel':
                    self.assertFalse([o for o in service.get('security_opt', []) if 'playwright' in o or 'chromium' in o], name)

    def test_the_image_carries_the_browser_as_the_screenshot_kind_needs_it(self):
        dockerfile, requirements = text('Dockerfile'), text('requirements.txt')
        pin = re.search(r'(?m)^playwright==([0-9.]+)', requirements)
        self.assertTrue(pin, 'Playwright is pinned in requirements.txt')
        self.assertIn('playwright install --with-deps --only-shell chromium', dockerfile)  # the headless shell only, as the server image did
        self.assertRegex(dockerfile, r'ARG PLAYWRIGHT_CHROMIUM_VERSION=\d+\.\d+\.\d+\.\d+')
        self.assertIn('ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers', dockerfile)
        self.assertIn('runuser -u sentinel', dockerfile.split('playwright install')[1].split('# bbot (GPLv3')[0])  # launched as the run-time user too
        self.assertLess(dockerfile.index('playwright install'), dockerfile.index('USER sentinel'))  # installed as root, run as the account
        self.assertIn(f'v{pin.group(1)}', text('docker-compose.yml'))  # the vendored profile is the one of the pinned release

    def test_the_entrypoint_does_not_refresh_templates_unless_asked(self):
        with open(os.path.join(ROOT, 'docker-entrypoint.sh')) as handle:
            text = handle.read()
        self.assertIn('CVENGINE_SENTINEL_UPDATE_TEMPLATES', text)
        self.assertIn('exec "$@"', text)
        runs = [ln for ln in text.splitlines() if ln.strip().startswith('timeout 120 nuclei')]
        self.assertEqual(len(runs), 1)  # the only refresh is the opt-in one

    def test_the_sentinel_stops_gracefully_reaps_children_and_reports_health(self):
        sentinel = self.full['services']['sentinel']
        self.assertTrue(sentinel.get('init'))
        self.assertIn(sentinel.get('stop_grace_period'), ('75s', '1m15s'))  # compose normalises the unit
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
            self.assertNotIn('network_mode: host', handle.read())  # (the state-volume one-shot uses network_mode: none)
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


def text(*path):
    with open(os.path.join(ROOT, *path)) as handle:
        return handle.read()


class PinTests(unittest.TestCase):
    def test_the_base_image_is_pinned_by_digest(self):
        self.assertRegex(text('Dockerfile'), r'(?m)^FROM ubuntu:[0-9.]+@sha256:[0-9a-f]{64}$')

    def test_the_pip_bootstrap_is_pinned(self):
        line = next(l for l in text('Dockerfile').splitlines() if 'pip install' in l and 'requirements' not in l)
        for package in ('pip==', 'setuptools==', 'wheel=='):
            self.assertIn(package, line)
        self.assertNotIn('--upgrade', line)

    def test_the_go_toolchain_and_caches_leave_with_the_layer_that_used_them(self):
        dockerfile = text('Dockerfile')
        step = next(block for block in dockerfile.split('\nRUN ') if 'go install' in block)
        self.assertIn('go.dev/dl/', step)
        self.assertIn('go clean -cache -modcache', step)
        self.assertIn('rm -rf "${GOROOT}" "${GOPATH}/pkg"', step)
        self.assertNotIn('/go/pkg/*', dockerfile)

    def test_no_root_only_directory_is_on_the_path_of_the_run_time_user(self):
        # /root is mode 0700: a PATH entry under it makes a lookup of a program that is not found fail with EACCES (PermissionError) instead of
        # ENOENT, which is how bbot's `sudo -K` probe crashed it
        dockerfile = text('Dockerfile')
        for line in dockerfile.splitlines():
            if line.startswith('ENV PATH') or re.match(r'\s*PATH=', line):
                self.assertNotIn('/root', line)
                self.assertNotIn('GOPATH', line)
        self.assertNotRegex(dockerfile, r'(?m)^\s*(ENV\s+)?GO(PATH|ROOT)=')  # set only inside the build step that runs go

    def test_every_bbot_module_dependency_is_installed_at_build_and_the_client_start_is_checked(self):
        dockerfile = text('Dockerfile')
        self.assertIn('-p kitchen-sink --force --dry-run', dockerfile)
        self.assertIn('scripts/ci_bbot_start.py', dockerfile)
        self.assertIn('--no-deps', dockerfile)
        self.assertLess(dockerfile.index('-p kitchen-sink'), dockerfile.index('apt-get purge -y git'))

    def test_ci_starts_bbot_in_the_built_image_as_the_unprivileged_user(self):
        workflow = text('.github', 'workflows', 'image.yml')
        self.assertRegex(workflow, r'docker run --rm --hostname \S+ --user 10001 --entrypoint python3 cvengine-sentinel-local:ci /opt/sentinel/scripts/ci_bbot_start\.py')

    def test_the_openvas_bootstrap_check_is_in_the_image(self):
        self.assertIn('COPY scripts/ci_openvas_bootstrap.py /opt/sentinel/scripts/', text('Dockerfile'))

    def test_the_template_refresh_at_start_is_bounded(self):
        entrypoint = text('docker-entrypoint.sh')
        self.assertIn('timeout 120 nuclei -update-templates', entrypoint)
        self.assertTrue(entrypoint.rstrip().endswith('exec "$@"'))

    def test_every_action_is_pinned_by_commit(self):
        for path in glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml')):
            for ref in re.findall(r'uses:\s*(\S+)', text(path)):
                self.assertRegex(ref, r'@[0-9a-f]{40}$', path)

    def test_every_container_image_in_ci_is_pinned_by_digest(self):
        for path in glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml')):
            for image in re.findall(r'\b((?:python|alpine):[0-9][\w.-]*\S*)', text(path)):
                self.assertIn('@sha256:', image, path)

    def test_the_digest_check_fails_its_step(self):
        workflow = text('.github', 'workflows', 'openvas-integration.yml')
        self.assertRegex(workflow, r'defaults:\s+run:\s+shell: bash\n')  # explicit bash runs with pipefail
        for trigger_path in ('Dockerfile', 'scripts/greenbone-digests.sh', '.github/workflows/openvas-integration.yml'):
            self.assertEqual(workflow.count(f'- {trigger_path}\n'), 2, trigger_path)  # pull requests and pushes to main


REGISTRY_SHIM = """#!/bin/sh
# stand-in curl: a token for any image, the manifest of a digest exists unless it is listed in GONE, stable points to STABLE_<image>
url=""
for arg in "$@"; do case "$arg" in https://*) url="$arg" ;; esac; done
case "$url" in
  */service/token*) echo '{"token": "t"}' ;;
  */manifests/stable) image=${url%/manifests/stable}; image=${image##*/}; image=$(echo "$image" | tr - _)
    eval "digest=\\${STABLE_$image:-}"; printf 'HTTP/1.1 200 OK\\r\\ndocker-content-digest: %s\\r\\n' "$digest" ;;
  */manifests/*) case " $GONE " in *" ${url##*/} "*) exit 22 ;; esac; printf 'HTTP/1.1 200 OK\\r\\n' ;;
esac
"""


@unittest.skipUnless(shutil.which('sh') and shutil.which('python3'), 'needs sh and python3')
class GreenboneDigestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sentinel-digests-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        os.makedirs(os.path.join(self.tmp, 'scripts'))
        os.makedirs(os.path.join(self.tmp, 'bin'))
        shutil.copy(os.path.join(ROOT, 'scripts', 'greenbone-digests.sh'), os.path.join(self.tmp, 'scripts'))
        with open(os.path.join(self.tmp, 'bin', 'curl'), 'w') as handle:
            handle.write(REGISTRY_SHIM)
        os.chmod(os.path.join(self.tmp, 'bin', 'curl'), 0o755)
        self.a, self.b, self.c = ('sha256:' + ch * 64 for ch in 'abc')
        compose = (f'image: "registry.community.greenbone.net/community/gvmd:stable@{self.a}"\n'
                   f'image: "registry.community.greenbone.net/community/openvas-scanner:stable@{self.a}"\n'
                   f'image: "registry.community.greenbone.net/community/openvas-scanner:stable@{self.b}"\n')
        with open(os.path.join(self.tmp, 'docker-compose.yml'), 'w') as handle:
            handle.write(compose)

    def check(self, gone='', **stable):
        env = {**os.environ, 'PATH': f'{self.tmp}/bin:{os.environ["PATH"]}', 'GONE': gone}
        env.update({f'STABLE_{k}': v for k, v in stable.items()})
        return subprocess.run(['sh', os.path.join(self.tmp, 'scripts', 'greenbone-digests.sh')], env=env, capture_output=True, text=True)

    def test_drift_is_reported_but_does_not_fail(self):
        out = self.check(gvmd=self.a, openvas_scanner=self.a)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn(f'ok       gvmd {self.a}', out.stdout)
        self.assertIn(f'CHANGED  openvas-scanner pinned={self.b} now={self.a}', out.stdout)  # the second pin of the same image is checked too

    def test_a_pin_gone_from_the_registry_fails(self):
        out = self.check(gone=self.b, gvmd=self.a, openvas_scanner=self.a)
        self.assertEqual(out.returncode, 1)
        self.assertIn(f'MISSING  openvas-scanner {self.b}', out.stdout)


if __name__ == '__main__':
    unittest.main()
