"""The approved nuclei template bundle: downloaded, hash-checked, unpacked without trusting the archive, cached, pruned; the HTTP download; and how
the daemon and run_nuclei use it."""
import hashlib
import io
import os
import shutil
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

from client import daemon, httpclient, templates, tools
from client.tests.test_daemon import FakeClient


def make_tgz(members):
    """A tar.gz of ``members``: a list of (name, bytes|None for a directory) or a ready TarInfo with data."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
        for item in members:
            if isinstance(item, tarfile.TarInfo):
                tar.addfile(item, io.BytesIO(b'x' * item.size) if item.isreg() else None)
                continue
            name, data = item
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(data)
                info.mode = 0o777
                tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class BundleClient:
    """Stands in for httpclient.Client: serves one archive, or fails."""

    def __init__(self, data=None, error=None):
        self.data, self.error, self.calls = data, error, []

    def download(self, path, destination, max_bytes, timeout=None):
        self.calls.append((path, max_bytes, timeout))
        if self.error:
            raise self.error
        destination.write(self.data)
        return hashlib.sha256(self.data).hexdigest(), len(self.data)


class BundleTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sentinel-templates-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        patcher = mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_TOKEN_FILE': os.path.join(self.tmp, 'token.json')})
        patcher.start()
        self.addCleanup(patcher.stop)

    def leftovers(self):
        root = templates.bundles_dir()
        return sorted(os.listdir(root)) if os.path.isdir(root) else []


class EnsureBundleTests(BundleTestCase):
    GOOD = [('http/', None), ('http/a.yaml', b'id: a\n'), ('http/sub/b.yaml', b'id: b\n'), ('helpers/words.txt', b'one\n')]

    def test_it_downloads_verifies_unpacks_and_returns_the_directory(self):
        data = make_tgz(self.GOOD)
        sha = hashlib.sha256(data).hexdigest()
        client = BundleClient(data)
        path = templates.ensure_bundle(client, sha)
        self.assertEqual(path, os.path.join(templates.bundles_dir(), sha))
        with open(os.path.join(path, 'http/a.yaml'), 'rb') as handle:
            self.assertEqual(handle.read(), b'id: a\n')
        self.assertTrue(os.path.isfile(os.path.join(path, 'http/sub/b.yaml')))
        with open(os.path.join(path, templates.VERIFIED)) as handle:
            self.assertEqual(handle.read().strip(), sha)
        self.assertEqual(client.calls[0][0], templates.BUNDLE_PATH)
        self.assertEqual(self.leftovers(), [sha])  # no temporary download or unpack directory is left behind

    def test_permissions_are_ours_never_the_archives(self):
        data = make_tgz(self.GOOD)
        path = templates.ensure_bundle(BundleClient(data), hashlib.sha256(data).hexdigest())
        self.assertEqual(os.stat(os.path.join(path, 'http/a.yaml')).st_mode & 0o777, 0o644)  # the archive said 0777

    def test_a_bundle_already_unpacked_is_reused_without_a_download(self):
        data = make_tgz(self.GOOD)
        sha = hashlib.sha256(data).hexdigest()
        client = BundleClient(data)
        templates.ensure_bundle(client, sha)
        templates.ensure_bundle(client, sha.upper())  # the hash is compared in lower case
        self.assertEqual(len(client.calls), 1)

    def test_a_download_that_does_not_match_the_approved_hash_runs_nothing(self):
        data = make_tgz(self.GOOD)
        wrong = hashlib.sha256(b'something else').hexdigest()
        with self.assertRaises(templates.TemplateError) as ctx:
            templates.ensure_bundle(BundleClient(data), wrong)
        self.assertIn('does not match the approved hash', str(ctx.exception))
        self.assertEqual(self.leftovers(), [])

    def test_a_task_without_a_usable_hash_is_refused_before_any_download(self):
        client = BundleClient(b'')
        for value in (None, '', 'abc', 'z' * 64, 'a' * 63, 'a' * 65, 5):
            with self.subTest(value=value), self.assertRaises(templates.TemplateError):
                templates.ensure_bundle(client, value)
        self.assertEqual(client.calls, [])

    def test_a_failed_download_is_a_template_error_and_leaves_nothing(self):
        for error in (httpclient.ApiError(404, 'no policy'), httpclient.ApiError(401, 'no'), OSError('disk full')):
            with self.subTest(error=error), self.assertRaises(templates.TemplateError) as ctx:
                templates.ensure_bundle(BundleClient(error=error), 'a' * 64)
            self.assertIn('could not be fetched', str(ctx.exception))
            self.assertEqual(self.leftovers(), [])

    def test_something_that_is_not_a_gzip_tar_is_refused(self):
        junk = b'not an archive at all'
        with self.assertRaises(templates.TemplateError):
            templates.ensure_bundle(BundleClient(junk), hashlib.sha256(junk).hexdigest())
        self.assertEqual(self.leftovers(), [])


class HostileArchiveTests(BundleTestCase):
    def refused(self, members):
        data = make_tgz(members)
        with self.assertRaises(templates.TemplateError):
            templates.ensure_bundle(BundleClient(data), hashlib.sha256(data).hexdigest())
        self.assertEqual(self.leftovers(), [])
        return data

    def test_paths_that_leave_the_bundle_are_refused(self):
        for name in ('../escape.yaml', 'a/../../escape.yaml', '/etc/cron.d/x', 'a\\b.yaml', 'x' * 500):
            with self.subTest(name=name):
                self.refused([('ok.yaml', b'id: ok\n'), (name, b'evil')])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'escape.yaml')))

    def test_links_devices_and_other_special_entries_are_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            info = tarfile.TarInfo('link')
            info.type = kind
            info.linkname = '/etc/passwd'
            with self.subTest(kind=kind):
                self.refused([('ok.yaml', b'id: ok\n'), info])

    def test_an_archive_with_too_many_entries_or_too_many_bytes_is_refused(self):
        with mock.patch.object(templates, 'MAX_ENTRIES', 3):
            self.refused([(f't{i}.yaml', b'id: x\n') for i in range(4)])
        with mock.patch.object(templates, 'MAX_EXTRACTED_BYTES', 10):
            self.refused([('big.yaml', b'x' * 11)])

    def test_an_empty_bundle_is_refused(self):
        self.refused([('only-a-dir/', None)])


class PruneTests(BundleTestCase):
    def test_old_unused_bundles_beyond_the_newest_are_removed_and_the_current_one_kept(self):
        root = templates.bundles_dir()
        os.makedirs(root)
        old = time.time() - templates.UNUSED_SECONDS - 100
        shas = [f'{i:064x}' for i in range(1, 7)]
        for i, sha in enumerate(shas):
            os.makedirs(os.path.join(root, sha))
            os.utime(os.path.join(root, sha), (old - i, old - i))  # all stale; the first is the newest
        os.makedirs(os.path.join(root, '.unpack-stale'))
        os.utime(os.path.join(root, '.unpack-stale'), (old, old))
        data = make_tgz([('a.yaml', b'id: a\n')])
        current = templates.ensure_bundle(BundleClient(data), hashlib.sha256(data).hexdigest())
        remaining = set(os.listdir(root))
        self.assertIn(os.path.basename(current), remaining)
        self.assertNotIn('.unpack-stale', remaining)
        self.assertLessEqual(len([n for n in remaining if templates.SHA256.match(n)]), templates.KEEP_BUNDLES + 1)

    def test_a_recently_used_bundle_is_not_removed(self):
        root = templates.bundles_dir()
        os.makedirs(root)
        fresh = [f'{i:064x}' for i in range(1, 7)]
        for sha in fresh:
            os.makedirs(os.path.join(root, sha))
        data = make_tgz([('a.yaml', b'id: a\n')])
        templates.ensure_bundle(BundleClient(data), hashlib.sha256(data).hexdigest())
        self.assertTrue(all(os.path.isdir(os.path.join(root, sha)) for sha in fresh))  # used within a day: a running scan may need it


class FakeResponse:
    def __init__(self, status=200, chunks=(b'abc', b'def')):
        self.status_code, self.chunks, self.closed = status, chunks, False

    def iter_content(self, chunk_size=None):
        return iter(self.chunks)

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, response):
        self.response, self.calls = response, []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.response


class DownloadTests(unittest.TestCase):
    def client(self, response):
        session = FakeSession(response)
        return httpclient.Client('https://cve.example.test', 'tok', session=session), session

    def test_it_streams_hashes_and_counts_exactly_what_it_wrote(self):
        client, session = self.client(FakeResponse())
        sink = io.BytesIO()
        digest, size = client.download('sentinel/template-policy/bundle', sink, 100)
        self.assertEqual((digest, size, sink.getvalue()), (hashlib.sha256(b'abcdef').hexdigest(), 6, b'abcdef'))
        method, url, kwargs = session.calls[0]
        self.assertEqual((method, url), ('GET', 'https://cve.example.test/api/v1/sentinel/template-policy/bundle'))
        self.assertEqual(kwargs['headers']['Authorization'], 'Bearer tok')
        self.assertIs(kwargs['allow_redirects'], False)
        self.assertIs(kwargs['stream'], True)
        self.assertTrue(session.response.closed)

    def test_errors_redirects_and_oversize_bodies_are_api_errors(self):
        for status in (301, 302, 401, 404, 500):
            client, session = self.client(FakeResponse(status=status))
            with self.subTest(status=status), self.assertRaises(httpclient.ApiError) as ctx:
                client.download('x', io.BytesIO(), 100)
            self.assertEqual(ctx.exception.status, status)
            self.assertTrue(session.response.closed)
        client, session = self.client(FakeResponse(chunks=(b'a' * 60, b'b' * 60)))
        with self.assertRaises(httpclient.ApiError) as ctx:
            client.download('x', io.BytesIO(), 100)
        self.assertEqual(ctx.exception.status, 413)
        self.assertTrue(session.response.closed)


class RunNucleiTemplatesTests(unittest.TestCase):
    def test_a_template_directory_is_passed_to_nuclei_and_nothing_else_changes(self):
        with tempfile.TemporaryDirectory() as bundle, mock.patch.object(tools, '_run', return_value='') as run, \
                mock.patch('client.tools._resolver', return_value=lambda *a, **k: []):
            tools.run_nuclei(['www.example.test'], tags=['tech'], templates=bundle)
            argv = run.call_args[0][0]
        self.assertEqual(argv[argv.index('-t') + 1], bundle)
        self.assertIn('-etags', argv)  # the exclusion floor still applies on top of the approved set

    def test_without_a_directory_there_is_no_template_flag(self):
        with mock.patch.object(tools, '_run', return_value='') as run, mock.patch('client.tools._resolver', return_value=lambda *a, **k: []):
            tools.run_nuclei(['www.example.test'])
        self.assertNotIn('-t', run.call_args[0][0])

    def test_a_directory_that_is_not_usable_is_refused(self):
        for bad in ('relative/path', '/definitely/not/here', 5, ''):
            with self.subTest(bad=bad), mock.patch('client.tools._resolver', return_value=lambda *a, **k: []):
                with self.assertRaises(tools.TargetError):
                    tools.run_nuclei(['www.example.test'], templates=bad)


class DaemonTemplateTests(unittest.TestCase):
    def make(self):
        return daemon.Daemon('https://x.example', 'tok', client=FakeClient())

    def test_a_task_naming_a_bundle_runs_on_exactly_that_bundle(self):
        d = self.make()
        with mock.patch('client.templates.ensure_bundle', return_value='/state/templates/abc') as ensure, \
                mock.patch.dict(tools.RUNNERS, {'nuclei_light': mock.Mock(return_value={'findings': []})}):
            out = d._execute({'kind': 'nuclei_light', 'target': {'targets': ['www.example.test'], 'bundle_sha256': 'a' * 64,
                                                                   'template_policy': {'rev': 'readonly-2', 'read_only': True}}}, None)
            runner = tools.RUNNERS['nuclei_light']
        ensure.assert_called_once_with(d.client, 'a' * 64)
        self.assertEqual(runner.call_args.kwargs['templates'], '/state/templates/abc')
        self.assertEqual(out['outcome'], 'done')

    def test_a_bundle_that_cannot_be_had_is_an_error_and_nothing_runs(self):
        d = self.make()
        runner = mock.Mock()
        with mock.patch('client.templates.ensure_bundle', side_effect=templates.TemplateError('the approved template bundle could not be fetched')), \
                mock.patch.dict(tools.RUNNERS, {'nuclei_deep': runner}):
            with self.assertRaises(tools.TargetError) as ctx:
                d._execute({'kind': 'nuclei_deep', 'target': {'targets': ['www.example.test'], 'bundle_sha256': 'b' * 64}}, None)
        self.assertIn('could not be fetched', str(ctx.exception))
        runner.assert_not_called()

    def test_the_read_only_policy_without_a_bundle_is_an_error(self):
        d = self.make()
        runner = mock.Mock()
        with mock.patch.dict(tools.RUNNERS, {'nuclei_targeted': runner}), self.assertRaises(templates.BundlePending):
            d._execute({'kind': 'nuclei_targeted', 'target': {'targets': ['www.example.test'], 'template_policy': {'read_only': True}}}, None)
        runner.assert_not_called()

    def test_a_task_with_no_policy_uses_the_image_templates(self):
        d = self.make()
        with mock.patch.dict(tools.RUNNERS, {'nuclei_light': mock.Mock(return_value={'findings': []})}):
            d._execute({'kind': 'nuclei_light', 'target': {'targets': ['www.example.test']}}, None)
            self.assertIsNone(tools.RUNNERS['nuclei_light'].call_args.kwargs['templates'])
        with mock.patch.dict(tools.RUNNERS, {'nuclei_light': mock.Mock(return_value={'findings': []})}):
            d._execute({'kind': 'nuclei_light', 'target': {'targets': ['www.example.test'], 'template_policy': {'read_only': False}}}, None)
            self.assertIsNone(tools.RUNNERS['nuclei_light'].call_args.kwargs['templates'])


def _fixture_target(kind):
    """A target exactly as cvENGINE's own fixtures write it (cvengine_scanner/fixtures/targets)."""
    import json
    from cvengine_scanner import contract
    return json.loads((contract.FIXTURES / 'targets' / f'{kind}.json').read_text(encoding='utf-8'))


class ServerTemplatePolicyShapeTests(unittest.TestCase):
    """The server puts ``bundle_sha256`` inside ``template_policy`` (sentinel_dispatch._nuclei_target), not at the top of the target."""

    def make(self):
        return daemon.Daemon('https://x.example', 'tok', client=FakeClient())

    def test_the_bundle_the_server_names_in_its_template_policy_is_the_one_run(self):
        d = self.make()
        target = _fixture_target('nuclei_light')
        target['template_policy']['bundle_sha256'] = 'c' * 64
        runner = mock.Mock(return_value={'findings': []})
        with mock.patch('client.templates.ensure_bundle', return_value='/state/templates/ccc') as ensure, \
                mock.patch.dict(tools.RUNNERS, {'nuclei_light': runner}):
            out = d._execute({'kind': 'nuclei_light', 'target': target}, None)
        ensure.assert_called_once_with(d.client, 'c' * 64)
        self.assertEqual(runner.call_args.kwargs['templates'], '/state/templates/ccc')
        self.assertEqual(out['outcome'], 'done')

    def test_a_read_only_task_whose_bundle_is_not_packed_yet_is_retryable_not_an_error(self):
        d = self.make()
        runner = mock.Mock()
        with mock.patch.dict(tools.RUNNERS, {'nuclei_light': runner}):
            with self.assertRaises(templates.BundlePending) as ctx:
                d._execute({'kind': 'nuclei_light', 'target': _fixture_target('nuclei_light')}, None)
        self.assertIsInstance(ctx.exception, templates.TemplateError)
        self.assertNotIsInstance(ctx.exception, tools.TargetError)  # a TargetError is final; this one is retried
        runner.assert_not_called()

    def test_the_daemon_gives_such_a_task_back_to_the_server_instead_of_reporting_an_error(self):
        d = self.make()
        task = {'id': 77, 'kind': 'nuclei_light', 'target': _fixture_target('nuclei_light')}
        state = {'runnable': True, 'kind': 'nuclei_light', 'done': threading.Event(), 'dropped': False, 'finishing': False, 'pgids': set()}
        with mock.patch.dict(tools.RUNNERS, {'nuclei_light': mock.Mock()}), \
                mock.patch.object(d, '_release') as release, mock.patch.object(d, '_report') as report, mock.patch.object(d, '_write_control'):
            d._run_task(task, state)
        report.assert_not_called()
        release.assert_called_once()
        self.assertEqual(release.call_args.args[0], 77)
        self.assertIn('retry later', release.call_args.args[1])

    def test_every_target_fixture_runs_through_execute_with_mocked_runners(self):
        """The contract check: each kind's fixture target goes through Daemon._execute and comes back done (or the one refusal it is
        meant to give). Every runner is mocked, so nothing scans anything; the target is the one the server's schema accepts."""
        import glob
        from cvengine_scanner import contract
        expected_refusals = {  # kinds whose fixture the Sentinel is meant to refuse here, and why
            'nuclei_light': templates.BundlePending,  # the fixture is read-only with bundle_sha256 still null (not packed yet)
            'route_probe_signed': tools.TargetError,  # signed-in work needs the built-in scanner and a sign-in in the task
            'secrets_scan': None,
        }
        stems = sorted(os.path.splitext(os.path.basename(p))[0] for p in glob.glob(str(contract.FIXTURES / 'targets' / '*.json')))
        self.assertGreater(len(stems), 30)
        for kind in stems:
            d = self.make()
            fake = {k: mock.Mock(return_value={'findings': [], 'items': [], 'hosts': [], 'ports': {}, 'outcome': 'done'}) for k in tools.RUNNERS}
            with self.subTest(kind=kind), mock.patch.dict(tools.RUNNERS, fake), \
                    mock.patch('client.config._local_internal', return_value=True), \
                    mock.patch('client.config.builtin', return_value=True), \
                    mock.patch('client.templates.ensure_bundle', return_value='/state/templates/ddd'), \
                    mock.patch('client.templates.secret_rules', return_value=None):
                target = _fixture_target(kind)
                if kind in expected_refusals and expected_refusals[kind] is not None:
                    with self.assertRaises(expected_refusals[kind]):
                        d._execute({'id': 1, 'kind': kind, 'target': target, 'signed_in': None}, None)
                    continue
                out = d._execute({'id': 1, 'kind': kind, 'target': target, 'signed_in': None}, None)
                self.assertEqual(out['outcome'], 'done')


class HeartbeatRunningTests(unittest.TestCase):
    def test_the_heartbeat_lists_the_tasks_this_sentinel_is_running(self):
        fc = FakeClient()
        d = daemon.Daemon('https://x.example', 'tok', client=fc)
        d._in_flight = {7: {'kind': 'nmap', 'done': mock.Mock()}, 'abc': {'kind': 'naabu', 'done': mock.Mock()}}
        with mock.patch('client.tools.detect_tools', return_value=[]):
            d._heartbeat_once()
        body = fc.body_for('sentinel/heartbeat')
        self.assertCountEqual(body['running'], [7, 'abc'])
        self.assertIn('info', body)

    def test_with_nothing_running_the_list_is_empty(self):
        fc = FakeClient()
        d = daemon.Daemon('https://x.example', 'tok', client=fc)
        with mock.patch('client.tools.detect_tools', return_value=[]):
            d._heartbeat_once()
        self.assertEqual(fc.body_for('sentinel/heartbeat')['running'], [])


if __name__ == '__main__':
    unittest.main()


def _index(templates_):
    """A template index of ``{path: (bytes, verdicts)}``: what ``cvengine_scanner.template_index.load`` returns."""
    reasons = ['template not validated: it uses \'payloads\'', 'template not validated: it sends a credential of its own', 'template not validated: it is tagged default-login, a check that sends credentials']
    entries = {path: {'sha256': hashlib.sha256(raw).hexdigest(), 'id': os.path.basename(path).rsplit('.', 1)[0], **verdicts}
               for path, (raw, verdicts) in templates_.items()}
    return {'nuclei_templates': 'v10.5.2', 'rules': 1, 'reasons': reasons, 'templates': entries, 'sha256': 'e' * 64}


class IndexSetTests(BundleTestCase):
    """Contract 11: the approved set is built from the baked templates and the library's template index, never fetched."""
    FILES = {'http/ok.yaml': (b'id: ok\n', {}), 'http/write.yaml': (b'id: write\n', {'ro': 0}), 'http/cred.yaml': (b'id: cred\n', {'cred': 1}),
             'http/login.yaml': (b'id: login\n', {'ctag': 2, 'cred': 1}), 'http/missing.yaml': (b'id: missing\n', {})}

    def baked(self, files=None, changed=()):
        source = os.path.join(self.tmp, 'baked')
        for path, (raw, _v) in (files or self.FILES).items():
            if path == 'http/missing.yaml':
                continue
            full = os.path.join(source, *path.split('/'))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, 'wb') as handle:
                handle.write(raw + (b'# changed\n' if path in changed else b''))
        return source

    def listed(self, path):
        return sorted(os.path.relpath(os.path.join(base, f), path) for base, _d, files in os.walk(path) for f in files if f != templates.VERIFIED)

    def test_each_policy_gets_exactly_the_templates_its_verdicts_allow(self):
        index, source = _index(self.FILES), self.baked()
        want = {(True, False): ['http/ok.yaml'], (True, True): ['http/cred.yaml', 'http/login.yaml', 'http/ok.yaml'],
                (False, False): ['http/ok.yaml', 'http/write.yaml'], (False, True): ['http/cred.yaml', 'http/login.yaml', 'http/ok.yaml', 'http/write.yaml']}
        for (read_only, credentials), files in want.items():
            with self.subTest(read_only=read_only, credentials=credentials):
                path = templates.ensure_index_set(read_only, credentials, source=source, index=index)
                self.assertEqual(self.listed(path), files)
                self.assertTrue(os.path.basename(path).startswith(templates.INDEX_PREFIX))

    def test_a_file_that_differs_from_the_index_or_is_a_link_is_left_out(self):
        index = _index(self.FILES)
        source = self.baked(changed={'http/ok.yaml'})
        os.symlink(os.path.join(source, 'http', 'ok.yaml'), os.path.join(source, 'http', 'cred-link.yaml'))
        index['templates']['http/cred-link.yaml'] = index['templates']['http/ok.yaml']
        path = templates.ensure_index_set(False, True, source=source, index=index)
        self.assertEqual(self.listed(path), ['http/cred.yaml', 'http/login.yaml', 'http/write.yaml'])

    def test_nothing_approved_in_this_image_or_no_index_is_an_error(self):
        index = _index({'http/ok.yaml': (b'id: ok\n', {})})
        with self.assertRaises(templates.TemplateError):
            templates.ensure_index_set(True, False, source=self.baked(changed={'http/ok.yaml'}), index=index)
        with self.assertRaises(templates.TemplateError):
            templates.ensure_index_set(True, False, source=self.baked(), index={'nuclei_templates': '', 'rules': 0, 'reasons': [], 'templates': {}, 'sha256': ''})
        with self.assertRaises(templates.TemplateError):
            templates.ensure_index_set(True, False, source=os.path.join(self.tmp, 'nowhere'), index=index)
        self.assertFalse([name for name in self.leftovers() if name.startswith(templates.INDEX_PREFIX)])

    def test_a_set_already_built_is_reused(self):
        index, source = _index(self.FILES), self.baked()
        first = templates.ensure_index_set(True, False, source=source, index=index)
        with mock.patch('cvengine_scanner.template_index.approved', side_effect=AssertionError('built again')):
            self.assertEqual(templates.ensure_index_set(True, False, source=source, index=index), first)

    def test_an_installed_template_is_read_only_when_index_and_file_agree(self):
        index, source = _index(self.FILES), self.baked(changed={'http/write.yaml'})
        sha = index['templates']['http/ok.yaml']['sha256']
        self.assertEqual(templates.installed_text('http/ok.yaml', sha, source=source, index=index), 'id: ok\n')
        for path, digest in (('http/ok.yaml', 'f' * 64), ('http/write.yaml', index['templates']['http/write.yaml']['sha256']),
                             ('http/missing.yaml', index['templates']['http/missing.yaml']['sha256']), ('http/none.yaml', sha), ('../http/ok.yaml', sha)):
            with self.subTest(path=path), self.assertRaises(templates.TemplateError):
                templates.installed_text(path, digest, source=source, index=index)


class DaemonIndexPolicyTests(unittest.TestCase):
    def make(self):
        return daemon.Daemon('https://x.example', 'tok', client=FakeClient())

    def test_an_index_policy_builds_the_set_and_never_fetches_a_bundle(self):
        d = self.make()
        target = {**_fixture_target('nuclei_light'), 'template_policy': {'rev': 'readonly-5', 'read_only': True, 'source': 'index'}}
        runner = mock.Mock(return_value={'findings': []})
        with mock.patch('client.templates.ensure_index_set', return_value='/state/templates/index-x-readonly') as build, \
                mock.patch('client.templates.ensure_bundle') as bundle, mock.patch.dict(tools.RUNNERS, {'nuclei_light': runner}):
            out = d._execute({'kind': 'nuclei_light', 'target': target}, None)
            d._execute({'kind': 'nuclei_light', 'target': {**target, 'allow_credential_checks': True,
                                                           'template_policy': {**target['template_policy'], 'read_only': False}}}, None)
            d._execute({'kind': 'nuclei_light', 'target': {**target, 'template_policy': {'rev': 'x', 'read_only': 'no', 'source': 'index'}}}, None)
        self.assertEqual(out['outcome'], 'done')
        self.assertEqual([c.args for c in build.call_args_list], [(True, False), (False, True), (True, False)])  # read-only unless plainly not
        self.assertNotIn('external', runner.call_args.kwargs)
        self.assertEqual(runner.call_args.kwargs['templates'], '/state/templates/index-x-readonly')
        with mock.patch('client.templates.ensure_index_set', return_value='/x'), mock.patch.dict(tools.RUNNERS, {'nuclei_light': runner}):
            d._execute({'kind': 'nuclei_light', 'target': {**target, 'external': True}}, None)
        self.assertIs(runner.call_args.kwargs['external'], True)
        bundle.assert_not_called()

    def test_a_set_that_cannot_be_built_is_an_error_and_nothing_runs(self):
        d = self.make()
        runner = mock.Mock()
        target = {**_fixture_target('nuclei_light'), 'template_policy': {'rev': 'readonly-5', 'read_only': True, 'source': 'index'}}
        with mock.patch('client.templates.ensure_index_set', side_effect=templates.TemplateError('no index')), \
                mock.patch.dict(tools.RUNNERS, {'nuclei_light': runner}), self.assertRaises(tools.TargetError):
            d._execute({'kind': 'nuclei_light', 'target': target}, None)
        runner.assert_not_called()

    def test_a_test_by_template_path_runs_the_baked_text(self):
        d = self.make()
        runner = mock.Mock(return_value={'outcomes': []})
        target = {'mode': 'test', 'template_path': 'http/cves/2021/CVE-2021-44228.yaml', 'template_sha256': 'a' * 64, 'targets': ['www.example.test']}
        with mock.patch('client.config.builtin', return_value=True), mock.patch('client.templates.installed_text', return_value='id: x\n') as read, \
                mock.patch.dict(tools.RUNNERS, {'nuclei_validate': runner}):
            d._execute({'id': 3, 'kind': 'nuclei_validate', 'target': target}, None)
        read.assert_called_once_with('http/cves/2021/CVE-2021-44228.yaml', 'a' * 64)
        self.assertEqual(runner.call_args.args[1], 'id: x\n')
        with mock.patch('client.config.builtin', return_value=True), mock.patch('client.templates.installed_text', return_value='id: x\n'), \
                mock.patch.dict(tools.RUNNERS, {'nuclei_validate': runner}):
            out = d._execute({'id': 3, 'kind': 'nuclei_validate', 'target': target}, None)
        self.assertEqual(out['template'], 'id: x\n')  # the text it ran goes back, for the server to read a hit
        with mock.patch('client.config.builtin', return_value=True), mock.patch.dict(tools.RUNNERS, {'nuclei_validate': runner}):
            out = d._execute({'id': 3, 'kind': 'nuclei_validate', 'target': {k: v for k, v in target.items() if k != 'template_path'} | {'template': 'id: y\n'}}, None)
        self.assertNotIn('template', out)  # a text the server sent is never sent back
        with mock.patch('client.config.builtin', return_value=True), \
                mock.patch('client.templates.installed_text', side_effect=templates.TemplateError('differs')), \
                mock.patch.dict(tools.RUNNERS, {'nuclei_validate': runner}), self.assertRaises(tools.Refused):
            d._execute({'id': 3, 'kind': 'nuclei_validate', 'target': target}, None)
        with mock.patch('client.config.builtin', return_value=True), mock.patch.dict(tools.RUNNERS, {'nuclei_validate': runner}), \
                self.assertRaises(tools.TargetError):
            d._execute({'id': 3, 'kind': 'nuclei_validate', 'target': {**target, 'mode': 'validate'}}, None)


def _nuclei_runs(run):
    """The calls of a patched ``tools._run`` that ran nuclei (the targets go in a list file, so they are not in the call)."""
    return [c for c in run.call_args_list if c.args and c.args[0] and c.args[0][0] == 'nuclei']


class RefusedTargetTests(unittest.TestCase):
    """Contract 11: a nuclei target scope refuses is named and left out; the other targets still run."""

    def test_a_refused_name_is_named_and_the_rest_runs(self):
        def resolve(host, *_a, **_k):
            return [(2, 1, 6, '', ('10.0.0.5' if host == 'inside.example.test' else '93.184.216.34', 0))]
        with mock.patch.object(tools, '_run', return_value='') as run, mock.patch('client.tools._resolver', return_value=resolve):
            out = tools.run_nuclei(['www.example.test', 'inside.example.test'], tags=['tech'])
        # in an image that carries a template directory the credential-template scan also calls _run with its own arguments: only nuclei runs count
        self.assertEqual(len(_nuclei_runs(run)), 1)
        self.assertIn('inside.example.test', out['unreachable'])
        refused = [n for n in out['not_checked'] if n['target'] == 'inside.example.test']
        self.assertTrue(refused and refused[0]['reason'].startswith(tools.flags.NUCLEI_REFUSED_PREFIX))
        self.assertNotIn('www.example.test', out['unreachable'])

    def test_every_target_refused_is_an_answer_with_nothing_run(self):
        with mock.patch.object(tools, '_run', return_value='') as run, \
                mock.patch('client.tools._resolver', return_value=lambda *a, **k: [(2, 1, 6, '', ('169.254.169.254', 0))]):
            out = tools.run_nuclei(['inside.example.test'])
        self.assertEqual(_nuclei_runs(run), [])  # the credential-template scan may still call _run with its own arguments
        self.assertEqual(out['unreachable'], ['inside.example.test'])
        self.assertEqual(out['findings'], [])
        self.assertNotIn('no_templates', out)

    def test_a_malformed_list_still_fails_the_task(self):
        for bad in ([], 'x', ['a.example.test'] * (tools.MAX_TARGETS + 1)):
            with self.subTest(bad=bad), self.assertRaises(tools.TargetError):
                tools.run_nuclei(bad)

    def test_the_release_names_an_index_set(self):
        self.assertEqual(tools._release_of('/state/templates/index-0123456789abcdef-readonly-cred').split(':')[2], 'readonly-cred')
        self.assertTrue(tools._release_of('/state/templates/index-0123456789abcdef-all').startswith('index:'))
        self.assertEqual(tools._release_of('/state/templates/' + 'a' * 64), 'approved:' + 'a' * 64)
        self.assertTrue(tools._release_of(None).startswith('image:'))
