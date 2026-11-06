"""The web_screenshot kind on the Sentinel (client/shot.py): what the browser's connections may reach, the pictures that come back, the sandbox
proof, the result's shape and the kind's wiring. The browser child is replaced here (the real one has its own module, test_shot_browser)."""
import base64
import json
import os
import tempfile
import unittest
from unittest import mock

from client import config, daemon, shot, tools
from client.shotproxy import VettingProxy  # noqa: F401 - the module imports
from cvengine_scanner import contract
from cvengine_scanner.probes import screenshots as lib
from cvengine_scanner.tests.probes.test_screenshots import png

NAMES = {'www.example.com': ['93.184.215.14'], 'fonts.example.net': ['93.184.215.20'], 'inside.example.com': ['10.0.0.5'], 'admin.example.com': ['93.184.215.30'],
         'self.example.com': ['172.19.0.4']}


def resolver(host, port, policy):
    """transport.resolve with the answers fixed: the policy and the floor judge the names and the addresses as in production."""
    policy.check_host(host)
    if host not in NAMES:
        raise OSError('no such host')
    out = []
    for address in NAMES[host]:
        if policy.address_refusal(address):
            raise ValueError('probe destination is prohibited')
        out.append((2, (address, port)))
    return tuple(out)


def target(**changes):
    out = json.loads((contract.FIXTURES / 'targets' / 'web_screenshot.json').read_text())
    out.update(changes)
    return out


def policy(open_web=True, **scope):
    doc = {'hosts': ['www.example.com'], 'excluded': ['admin.example.com'], 'private': False}
    doc.update(scope)
    return lib.ShotPolicy(doc, open_web=open_web, internal=False)


class GuardTests(unittest.TestCase):
    def guard(self, open_web=True, **kw):
        return shot.Guard(policy(open_web), 'www.example.com', stack=kw.get('stack', frozenset()), resolver=resolver)

    def test_a_listed_page_is_admitted_to_the_vetted_address(self):
        addresses, why = self.guard(False).admit('www.example.com', 443)
        self.assertEqual((addresses, why), (((2, ('93.184.215.14', 443)),), ''))

    def test_the_open_web_reaches_other_public_hosts_the_closed_policy_does_not(self):
        self.assertEqual(self.guard(True).admit('fonts.example.net', 443)[1], '')
        addresses, why = self.guard(False).admit('fonts.example.net', 443)
        self.assertIsNone(addresses)
        self.assertIn('not visited', why)

    def test_excluded_and_internal_hosts_are_never_reached_even_with_the_open_web(self):
        guard = self.guard(True)
        for host in ('admin.example.com', 'inside.example.com', 'localhost', 'redis', 'web'):
            addresses, why = guard.admit(host, 80)
            self.assertIsNone(addresses, host)
            self.assertTrue(why, host)
        self.assertEqual([h for h, _ in guard.denied], ['admin.example.com', 'inside.example.com', 'localhost', 'redis', 'web'])
        self.assertEqual(guard.policy.refused, ['admin.example.com', 'inside.example.com', 'localhost', 'redis', 'web'])

    def test_an_address_of_this_installations_own_services_is_refused(self):
        guard = shot.Guard(policy(True, private=True), 'www.example.com', stack=frozenset({'172.19.0.4'}), resolver=resolver)
        guard.policy.internal = True
        addresses, why = guard.admit('self.example.com', 80)
        self.assertIsNone(addresses)
        self.assertIn('own services', why)

    def test_a_name_that_does_not_resolve_is_refused_and_remembered(self):
        guard = self.guard(True)
        self.assertIn('could not be resolved', guard.admit('nowhere.example.net', 443)[1])
        self.assertEqual(guard.admit('nowhere.example.net', 443), guard.admit('nowhere.example.net', 443))  # one verdict per host for a page
        self.assertEqual(len(guard.denied), 1)

    def test_blocked_is_this_sides_call(self):
        guard = self.guard(True)
        self.assertFalse(guard.relabel('timeout'))
        guard.admit('inside.example.com', 443)  # a sub-resource only
        self.assertFalse(guard.relabel('timeout'))
        self.assertFalse(guard.relabel('error'))
        self.assertTrue(guard.relabel('unreachable'))  # the connection failed and a hop was refused: the redirect
        self.assertIn('Redirects to inside.example.com', guard.blocked_reason())
        primary = shot.Guard(policy(False), 'fonts.example.net', stack=frozenset(), resolver=resolver)
        primary.admit('fonts.example.net', 443)
        self.assertTrue(primary.relabel('timeout'))  # the page's own host was refused
        self.assertTrue(primary.blocked_reason().startswith('fonts.example.net is not visited'))


class PictureTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(self.dir, ignore_errors=True))

    def write(self, name, data):
        with open(os.path.join(self.dir, name), 'wb') as handle:
            handle.write(data)

    def page(self, **message):
        guard = shot.Guard(policy(True), 'www.example.com', stack=frozenset(), resolver=resolver)
        base = {'outcome': 'ok', 'reason': '', 'final_url': 'https://www.example.com/', 'status': 200, 'title': 'T'}
        base.update(message)
        return shot.finish_page(base, guard, self.dir, '0', lib.MAX_IMAGE_BYTES)

    def test_a_good_picture_is_sent_as_base64_under_the_servers_id(self):
        data = png()
        self.write('0.png', data)
        page = self.page()
        self.assertEqual((page['id'], page['outcome'], page['status'], page['title']), ('0', 'ok', 200, 'T'))
        self.assertEqual(base64.b64decode(page['image']), data)

    def test_the_file_is_the_one_this_side_named_whatever_the_child_says(self):
        self.write('0.png', png())
        self.write('other.png', b'x')
        self.assertEqual(self.page(out='/etc/passwd', image='other.png')['outcome'], 'ok')

    def test_what_the_browser_wrote_is_checked(self):
        self.assertIn('not written', self.page()['reason'])  # nothing there
        self.write('0.png', b'not a png at all' * 10)
        self.assertEqual(self.page()['outcome'], 'error')
        self.write('0.png', png(lib.MAX_IMAGE_SIDE + 1, 2))
        self.assertEqual(self.page()['outcome'], 'error')

    def test_a_link_is_never_followed(self):
        self.write('real.png', png())
        os.symlink(os.path.join(self.dir, 'real.png'), os.path.join(self.dir, '0.png'))
        self.assertEqual(self.page()['outcome'], 'error')

    def test_a_flat_picture_is_blank_when_pillow_can_tell(self):
        self.write('0.png', png(tones=1))
        try:
            import PIL  # noqa: F401
        except ImportError:
            self.skipTest('needs Pillow')
        self.assertEqual(self.page()['outcome'], 'blank')

    def test_a_failed_page_carries_no_picture(self):
        self.write('0.png', png())
        page = self.page(outcome='timeout', reason='slow')
        self.assertEqual((page['outcome'], page['reason']), ('timeout', 'slow'))
        self.assertNotIn('image', page)

    def test_a_picture_over_the_cap_is_reduced_or_refused(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('needs Pillow')
        import io
        noise = Image.frombytes('RGB', (800, 600), os.urandom(800 * 600 * 3))
        out = io.BytesIO()
        noise.save(out, 'PNG')
        big = out.getvalue()
        self.assertGreater(len(big), lib.MIN_IMAGE_BYTES * 4)
        fitted = shot.fit_png(big, lib.MIN_IMAGE_BYTES * 4)
        self.assertTrue(fitted is None or len(fitted) <= lib.MIN_IMAGE_BYTES * 4)
        self.assertIsNone(shot.fit_png(big, 100))
        self.assertEqual(shot.fit_png(png(), 10 ** 6), png())


class FakeProxy:
    def __init__(self, admit, connect, secret):
        self.admit, self.server = admit, '127.0.0.1:1'

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def child_for(answers, fatal='', engaged=True, keep=None):
    """A stand-in for the browser child: answers each page as ``answers`` says (a dict of key -> message, or a callable that may also write the picture)."""
    def child(job, on_message, wall, workdir, register=None):
        if keep is not None:
            keep.append(job)
        if engaged is not None:
            on_message({'op': 'sandbox', 'engaged': engaged, 'version': '156.0.8078.4'})
        for item in job['targets']:
            answer = answers(item) if callable(answers) else answers.get(item['key'])
            if answer is not None:
                if answer.get('outcome') == 'ok':
                    with open(item['out'], 'wb') as handle:
                        handle.write(png())
                on_message(dict(answer, op='result', key=item['key']))
        return fatal
    return child


class RunTests(unittest.TestCase):
    def setUp(self):
        for patcher in (mock.patch.object(shot, 'available', return_value=True), mock.patch.object(shot, 'stack_addresses', return_value=frozenset())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_task(self, child, task=None, **kw):
        guard = lambda pol, primary: shot.Guard(pol, primary, stack=frozenset(), resolver=resolver)  # noqa: E731
        return shot.run(task or target(), child=child, proxy_factory=FakeProxy, guard_factory=guard, **kw)

    def ok(self, **extra):
        return dict({'outcome': 'ok', 'reason': '', 'final_url': 'https://www.example.com/', 'status': 200, 'title': 'T'}, **extra)

    def test_the_result_has_the_contract_shape_and_the_servers_ids(self):
        out = self.run_task(child_for({'0': self.ok(), '1': {'outcome': 'unreachable', 'reason': 'The connection was refused.'}}))
        self.assertEqual(out['sandbox'], {'engaged': True, 'reason': '', 'version': '156.0.8078.4'})
        self.assertEqual([(p['id'], p['outcome']) for p in out['pages']], [('1', 'ok'), ('2', 'unreachable')])
        self.assertEqual(sorted(out), ['dropped_requests', 'pages', 'refused', 'sandbox', 'touched'])
        self.assertTrue(base64.b64decode(out['pages'][0]['image']).startswith(b'\x89PNG'))

    def test_the_result_validates_against_the_contract_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('needs jsonschema')
        out = self.run_task(child_for({'0': self.ok(), '1': {'outcome': 'timeout', 'reason': 'slow'}}))
        out['outcome'] = 'done'
        jsonschema.validate(out, contract.result_schema('web_screenshot'))

    def test_the_browser_is_told_this_sides_keys_and_never_a_server_id_or_a_name(self):
        seen = []
        self.run_task(child_for({'0': self.ok(), '1': self.ok()}, keep=seen))
        job = seen[0]
        self.assertEqual([t['key'] for t in job['targets']], ['0', '1'])
        self.assertEqual([t['url'] for t in job['targets']], ['https://www.example.com/', 'http://www.example.com:8080/'])
        self.assertTrue(all(os.path.basename(t['out']) == f"{t['key']}.png" for t in job['targets']))
        self.assertNotIn('scope', json.dumps(job))

    def test_a_browser_that_could_not_prove_its_sandbox_opens_nothing_and_says_why(self):
        out = self.run_task(child_for({}, fatal=lib.SANDBOX_PREFIX + 'user namespaces refused', engaged=None))
        self.assertEqual(out['sandbox'], {'engaged': False, 'reason': 'user namespaces refused', 'version': ''})
        self.assertEqual((out['pages'], out['touched']), ([], []))

    def test_a_task_the_browser_never_started_for_is_unavailable_and_not_a_result(self):
        with self.assertRaises(shot.Unavailable):
            self.run_task(child_for({}, fatal='the browser process ended before it finished (status -9)', engaged=None))
        with self.assertRaises(shot.Unavailable):
            self.run_task(child_for({}, engaged=None))

    def test_pages_the_browser_never_reported_are_unavailable_pages(self):
        out = self.run_task(child_for({'0': self.ok()}, fatal='the browser process ended before it finished (status -9)'))
        self.assertEqual([(p['id'], p['outcome']) for p in out['pages']], [('1', 'ok'), ('2', 'unavailable')])
        self.assertIn('could not run', out['pages'][1]['reason'])

    def test_a_page_that_held_the_browser_over_its_memory_ceiling_is_too_big(self):
        out = self.run_task(child_for({'0': self.ok()}, fatal='too_big:2000'))
        self.assertEqual([(p['id'], p['outcome']) for p in out['pages']], [('1', 'ok'), ('2', 'too_big')])

    def test_a_message_for_a_page_nobody_asked_about_or_twice_is_ignored(self):
        def answers(item):
            return self.ok(title='first')
        def child(job, on_message, wall, workdir, register=None):
            child_for(answers)(job, on_message, wall, workdir)
            on_message({'op': 'result', 'key': '99', 'outcome': 'ok'})
            on_message({'op': 'result', 'key': '0', 'outcome': 'error', 'reason': 'second'})
            return ''
        out = self.run_task(child)
        self.assertEqual([p['title'] for p in out['pages']], ['first', 'first'])

    def test_a_refused_redirect_makes_a_blocked_page_not_a_picture(self):
        def child(job, on_message, wall, workdir, register=None):
            on_message({'op': 'sandbox', 'engaged': True, 'version': '1'})
            key = job['targets'][0]['key']
            admit = self.admit
            self.assertIsNone(admit(key, 'inside.example.com', 80)[0])  # the proxy asked and was refused
            on_message({'op': 'result', 'key': key, 'outcome': 'unreachable', 'reason': 'x'})
            return ''
        guards = {}

        def make(pol, primary):
            guards[primary] = shot.Guard(pol, primary, stack=frozenset(), resolver=resolver)
            return guards[primary]

        class Capture(FakeProxy):
            def __init__(inner, admit, connect, secret):
                super().__init__(admit, connect, secret)
                self.admit = admit
        task = target(pages=[{'id': 'a', 'url': 'https://www.example.com/'}])
        out = shot.run(task, child=child, proxy_factory=Capture, guard_factory=make)
        self.assertEqual((out['pages'][0]['outcome'], out['refused']), ('blocked', ['inside.example.com']))
        self.assertIn('Redirects to inside.example.com', out['pages'][0]['reason'])

    def test_a_task_that_is_not_usable_is_a_value_error(self):
        with self.assertRaises(ValueError):
            self.run_task(child_for({}), task=target(pages=[]))

    def test_no_browser_in_the_image_is_unavailable(self):
        with mock.patch.object(shot, 'available', return_value=False), self.assertRaises(shot.Unavailable):
            self.run_task(child_for({}))

    def test_the_working_directory_is_gone_afterwards(self):
        seen = []
        self.run_task(child_for({'0': self.ok()}, keep=seen))
        self.assertFalse(os.path.exists(os.path.dirname(seen[0]['targets'][0]['out'])))


class WiringTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(config.set_server_contract, {})

    def test_declared_only_to_a_server_that_knows_it_and_only_with_the_browser(self):
        with mock.patch.object(tools, 'gvm_ready', return_value=False), mock.patch.object(shot, 'available', return_value=True):
            config.set_server_contract({'contract': {'version': 2, 'min_supported': 1}})
            self.assertNotIn('web_screenshot', daemon.runnable_kinds())
            config.set_server_contract({'contract': {'version': 3, 'min_supported': 1}})
            self.assertIn('web_screenshot', daemon.runnable_kinds())
        with mock.patch.object(tools, 'gvm_ready', return_value=False), mock.patch.object(shot, 'available', return_value=False):
            self.assertNotIn('web_screenshot', daemon.runnable_kinds())

    def test_the_kind_has_a_runner_and_a_contract_version(self):
        self.assertIs(tools.RUNNERS['web_screenshot'], tools.run_web_screenshot)
        self.assertEqual(config.KIND_SINCE['web_screenshot'], 3)

    def test_the_runner_turns_a_bad_task_into_a_target_error_and_no_browser_into_a_tool_error(self):
        with self.assertRaises(tools.TargetError):
            tools.run_web_screenshot({'pages': []})
        with mock.patch.object(shot, 'available', return_value=False), self.assertRaises(tools.ToolOutputError):
            tools.run_web_screenshot(target())

    def test_the_child_never_inherits_the_sentinels_environment(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_BLOB': 'secret', 'CVENGINE_SERVER_TOKEN': 'tok', 'PATH': '/usr/bin'}):
            env = shot.child_env('/work')
        self.assertEqual(env['HOME'], '/work')
        self.assertEqual(env['TMPDIR'], '/work')
        self.assertNotIn('CVENGINE_SENTINEL_BLOB', env)
        self.assertFalse([k for k in env if k.startswith('CVENGINE')])


if __name__ == '__main__':
    unittest.main()
