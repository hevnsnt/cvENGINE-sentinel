"""The approved nuclei template bundle: downloaded, hash-checked, unpacked without trusting the archive, cached, pruned; the HTTP download; and how
the daemon and run_nuclei use it."""
import hashlib
import io
import os
import shutil
import tarfile
import tempfile
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
        with mock.patch.dict(tools.RUNNERS, {'nuclei_targeted': runner}), self.assertRaises(tools.TargetError):
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
