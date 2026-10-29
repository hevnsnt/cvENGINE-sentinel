import json
import os
import stat
import tempfile
import time
import unittest
from contextlib import contextmanager
from unittest import mock
from xml.etree import ElementTree as ET

from client import openvas


def xml(text):
    return ET.fromstring(text)


class FakeGMP:
    """A minimal stand-in for a python-gvm GMP session, scripted per test: each keyword is a GMP method name mapped
    to a fixed return value or a callable(*args, **kwargs) -> value. Every call is recorded in ``self.calls``."""

    def __init__(self, **responses):
        self.calls = []
        self.responses = responses

    def __getattr__(self, name):
        def method(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            handler = self.responses.get(name)
            if callable(handler):
                return handler(*args, **kwargs)
            if handler is not None:
                return handler
            raise AssertionError(f'unscripted GMP call: {name}({args!r}, {kwargs!r})')
        return method

    def names(self):
        return [c[0] for c in self.calls]


@contextmanager
def _ctx(value):
    yield value


def sessions(gmp):
    """Patch ``openvas.session`` so every short session the code opens yields ``gmp``."""
    return mock.patch('client.openvas.session', side_effect=lambda *a, **kw: _ctx(gmp))


HOST = '52.151.200.60'  # a public address the scope floor allows (the documentation ranges are refused now)


class OpenvasTestCase(unittest.TestCase):
    """Never the host's real gvmd socket, credential files or KEEP setting; no address lookups."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        env = mock.patch.dict('os.environ', {'CVENGINE_OPENVAS_CREDENTIALS_FILE': os.path.join(self.dir.name, 'creds.json'),
                                             'CVENGINE_OPENVAS_SOCKET': os.path.join(self.dir.name, 'gvmd.sock')})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('CVENGINE_OPENVAS_KEEP_TASKS', None)
        os.environ.pop('CVENGINE_OPENVAS_MAX_HOURS', None)
        for patcher in (mock.patch('client.scope.own_addresses', return_value=frozenset()),
                        mock.patch('client.openvas.STOP_WAIT', 0)):  # a fake task never winds down: do not wait on it
            patcher.start()
            self.addCleanup(patcher.stop)


RESULT_WITH_CVE = """
<result id="r1">
  <nvt oid="1.3.6.1.4.1.25623.1.0.100001">
    <name>Test NVT</name>
    <family>Web application abuses</family>
    <cve>NOCVE</cve>
    <tags>summary=Summary text|solution_type=Mitigation</tags>
    <solution>Patch it</solution>
    <refs>
      <ref type="cve" id="CVE-2024-12345"/>
      <ref type="url" id="https://example.test/advisory"/>
    </refs>
  </nvt>
  <host>192.0.2.10<hostname>www.example.test</hostname></host>
  <port>443/tcp</port>
  <severity>7.5</severity>
  <threat>High</threat>
  <qod><value>95</value><type>remote_banner</type></qod>
  <description>Vulnerable version detected</description>
</result>
"""

RESULT_NO_CVE = """
<result id="r2">
  <nvt oid="1.3.6.1.4.1.25623.1.0.100002">
    <name>Informational NVT</name>
    <family>General</family>
  </nvt>
  <host>192.0.2.20</host>
  <port>80/tcp</port>
  <severity>0</severity>
  <qod><value>70</value><type>general_note</type></qod>
  <description>Nothing much</description>
</result>
"""

RESULT_UNUSABLE = """
<result id="r3">
  <nvt oid="not-an-oid-at-all"/>
  <host>192.0.2.30</host>
</result>
"""


class ParseResultTests(OpenvasTestCase):
    def test_a_result_with_a_cve_is_read_with_its_cves_qod_and_severity(self):
        parsed = openvas.parse_result(xml(RESULT_WITH_CVE))
        self.assertEqual(parsed['oid'], '1.3.6.1.4.1.25623.1.0.100001')
        self.assertEqual(parsed['address'], '192.0.2.10')
        self.assertEqual(parsed['hostname'], 'www.example.test')
        self.assertEqual(parsed['port'], '443/tcp')
        self.assertEqual(parsed['port_number'], 443)
        self.assertEqual(parsed['severity'], 7.5)
        self.assertEqual(parsed['qod'], 95)
        self.assertEqual(parsed['cves'], ['CVE-2024-12345'])
        self.assertEqual(parsed['urls'], ['https://example.test/advisory'])
        self.assertEqual(parsed['summary'], 'Summary text')
        self.assertEqual(parsed['solution'], 'Patch it')

    def test_a_result_without_a_cve_still_parses_with_an_empty_list(self):
        parsed = openvas.parse_result(xml(RESULT_NO_CVE))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['cves'], [])
        self.assertEqual(parsed['address'], '192.0.2.20')

    def test_a_malformed_oid_or_missing_host_is_unusable(self):
        self.assertIsNone(openvas.parse_result(xml(RESULT_UNUSABLE)))
        self.assertIsNone(openvas.parse_result(xml('<result><nvt oid="1.2.3"/></result>')))

    def test_severity_and_qod_are_bounded(self):
        bad = xml('<result><nvt oid="1.2.3"/><host>192.0.2.1</host><severity>99</severity>'
                  '<qod><value>500</value></qod></result>')
        parsed = openvas.parse_result(bad)
        self.assertEqual(parsed['severity'], 10.0)
        self.assertEqual(parsed['qod'], 100)


class FetchResultsTests(OpenvasTestCase):
    def _page(self, elements):
        inner = ''.join(ET.tostring(e, encoding='unicode') for e in elements)
        return xml(f'<get_results_response><results>{inner}</results></get_results_response>')

    def test_counts_cve_bearing_no_cve_and_unusable_results(self):
        page = self._page([xml(RESULT_WITH_CVE), xml(RESULT_NO_CVE), xml(RESULT_UNUSABLE)])
        gmp = FakeGMP(get_results=lambda **kw: page)
        items, no_cve, unusable = openvas.fetch_results(gmp, 'task-1')
        self.assertEqual(len(items), 2)  # the unusable one is dropped, the no-cve one is kept
        self.assertEqual(no_cve, 1)
        self.assertEqual(unusable, 1)
        self.assertEqual({i['address'] for i in items}, {'192.0.2.10', '192.0.2.20'})

    def test_pages_until_a_short_page_ends_it(self):
        full_page = self._page([xml(RESULT_WITH_CVE)] * openvas.RESULT_PAGE)
        short_page = self._page([xml(RESULT_NO_CVE)])
        calls = {'n': 0}

        def get_results(**kwargs):
            calls['n'] += 1
            return full_page if calls['n'] == 1 else short_page
        gmp = FakeGMP(get_results=get_results)
        items, _no_cve, _unusable = openvas.fetch_results(gmp, 'task-1')
        self.assertEqual(calls['n'], 2)
        self.assertEqual(len(items), openvas.RESULT_PAGE + 1)

    def test_stops_at_the_result_cap(self):
        full_page = self._page([xml(RESULT_WITH_CVE)] * openvas.RESULT_PAGE)
        gmp = FakeGMP(get_results=lambda **kw: full_page)
        items, _no_cve, _unusable = openvas.fetch_results(gmp, 'task-1')
        self.assertLessEqual(len(items), openvas.MAX_RESULTS + openvas.RESULT_PAGE)


class ScannedAddressesTests(OpenvasTestCase):
    def test_unions_result_addresses_with_the_reports_host_list(self):
        items = [{'address': '192.0.2.10'}]
        status = xml('<get_tasks_response><task><last_report><report id="rep1"/></last_report></task></get_tasks_response>')
        report_detail = xml('<get_report_response><report><host><ip>192.0.2.10</ip></host>'
                            '<host><ip>192.0.2.99</ip></host></report></get_report_response>')
        gmp = FakeGMP(get_report=lambda *a, **kw: report_detail)
        seen = openvas.scanned_addresses(gmp, status, items)
        self.assertEqual(seen, {'192.0.2.10', '192.0.2.99'})

    def test_a_report_read_failure_falls_back_to_just_the_results(self):
        items = [{'address': '192.0.2.10'}]
        status = xml('<get_tasks_response><task><last_report><report id="rep1"/></last_report></task></get_tasks_response>')
        gmp = FakeGMP(get_report=mock.Mock(side_effect=RuntimeError('boom')))
        seen = openvas.scanned_addresses(gmp, status, items)
        self.assertEqual(seen, {'192.0.2.10'})

    def test_no_report_at_all_is_just_the_results(self):
        items = [{'address': '192.0.2.10'}]
        status = xml('<get_tasks_response><task/></get_tasks_response>')
        gmp = FakeGMP()
        self.assertEqual(openvas.scanned_addresses(gmp, status, items), {'192.0.2.10'})


FULL_AND_FAST_XML = f'<config id="{openvas.FULL_AND_FAST[0]}"><name>{openvas.FULL_AND_FAST[1]}</name></config>'
EXISTING_CONFIG_XML = f'<config id="cfg-existing"><name>{openvas.CONFIG_NAME}</name></config>'
FAMILIES_XML = ('<get_nvt_families_response><families>'
                '<family><name>Denial of Service</name></family>'
                '<family><name>Web application abuses</name></family>'
                '<family><name>General</name></family>'
                '</families></get_nvt_families_response>')


def config_detail(selected=(), nvt_count=100, safe_checks='yes', all_families=('Denial of Service', 'Web application abuses', 'General')):
    """A get_scan_config answer as gvmd 22.x shapes it: every family listed, the selected ones growing with their NVTs counted."""
    families = ''.join(f'<family><name>{name}</name><nvt_count>{10 if name in selected else 0}</nvt_count><max_nvt_count>10</max_nvt_count>'
                       f'<growing>{1 if name in selected else 0}</growing></family>' for name in all_families)
    return xml(f'<get_configs_response status="200"><config id="cfg"><name>{openvas.CONFIG_NAME}</name>'
               f'<family_count>{len(selected)}<growing>0</growing></family_count><nvt_count>{nvt_count}<growing>1</growing></nvt_count>'
               f'<families>{families}</families><preferences><preference><nvt oid=""><name/></nvt><name>safe_checks</name>'
               f'<value>{safe_checks}</value></preference></preferences></config></get_configs_response>')


class EnsureConfigTests(OpenvasTestCase):
    def test_builds_a_new_config_from_full_and_fast_when_none_exists(self):
        gmp = FakeGMP(
            get_scan_configs=lambda **kw: xml(f'<get_configs_response>{FULL_AND_FAST_XML}</get_configs_response>'),
            create_scan_config=lambda *a, **kw: xml('<create_scan_config_response id="new-cfg"/>'),
            get_nvt_families=lambda: xml(FAMILIES_XML),
            # a fresh copy of Full and fast selects everything; after the change, what was asked for
            get_scan_config=mock.Mock(side_effect=[config_detail(selected=('Denial of Service', 'Web application abuses', 'General')),
                                                   config_detail(selected=('Web application abuses', 'General'))]),
            modify_scan_config_set_family_selection=lambda *a, **kw: None,
            modify_scan_config_set_scanner_preference=lambda *a, **kw: None,
        )
        config_id = openvas.ensure_config(gmp, ['Denial of Service'])
        self.assertEqual(config_id, 'new-cfg')
        self.assertIn('create_scan_config', gmp.names())
        family_call = next(c for c in gmp.calls if c[0] == 'modify_scan_config_set_family_selection')
        wanted_names = [w[0] for w in family_call[1][1]]
        self.assertNotIn('Denial of Service', wanted_names)
        self.assertIn('Web application abuses', wanted_names)
        # gvmd answers 400 to a family that includes all VTs without also growing, so every kept family must be (name, growing, all VTs) = True, True
        self.assertTrue(all(w[1] is True and w[2] is True for w in family_call[1][1]), family_call[1][1])
        self.assertIn('modify_scan_config_set_scanner_preference', gmp.names())

    def test_reuses_an_existing_config_by_name_but_still_reapplies_family_selection(self):
        gmp = FakeGMP(
            get_scan_configs=lambda **kw: xml(f'<get_configs_response>{EXISTING_CONFIG_XML}</get_configs_response>'),
            get_nvt_families=lambda: xml(FAMILIES_XML),
            get_scan_config=lambda *a, **kw: config_detail(selected=('Web application abuses',)),  # an earlier task's narrower selection
            modify_scan_config_set_family_selection=lambda *a, **kw: None,
            modify_scan_config_set_scanner_preference=lambda *a, **kw: None,
        )
        config_id = openvas.ensure_config(gmp, [])
        self.assertEqual(config_id, 'cfg-existing')
        self.assertNotIn('create_scan_config', gmp.names())
        self.assertIn('modify_scan_config_set_family_selection', gmp.names())

    def test_raises_when_full_and_fast_is_missing(self):
        gmp = FakeGMP(get_scan_configs=lambda **kw: xml('<get_configs_response/>'))
        with self.assertRaises(openvas.OpenvasError):
            openvas.ensure_config(gmp, [])


def wait(gmp, deadline, run=None):
    run = run or openvas.OpenvasRun()
    run.task_id = 'task-1'
    with sessions(gmp), mock.patch('client.openvas.POLL_INTERVAL', 0):
        return openvas._wait_for_task(run, 'task-1', deadline=deadline)


class WaitForTaskTests(OpenvasTestCase):
    def test_returns_the_status_once_done(self):
        done = xml('<get_tasks_response><task><status>Done</status></task></get_tasks_response>')
        gmp = FakeGMP(get_task=lambda *a: done)
        self.assertIs(wait(gmp, deadline=999999999), done)

    def test_loops_while_active_then_returns_on_done(self):
        running = xml('<get_tasks_response><task><status>Running</status></task></get_tasks_response>')
        done = xml('<get_tasks_response><task><status>Done</status></task></get_tasks_response>')
        calls = {'n': 0}

        def get_task(*a):
            calls['n'] += 1
            return running if calls['n'] < 3 else done
        gmp = FakeGMP(get_task=get_task)
        result = wait(gmp, deadline=999999999)
        self.assertEqual(calls['n'], 3)
        self.assertIs(result, done)

    def test_raises_on_an_unknown_terminal_status(self):
        stopped = xml('<get_tasks_response><task><status>Stopped</status></task></get_tasks_response>')
        gmp = FakeGMP(get_task=lambda *a: stopped)
        with self.assertRaises(openvas.OpenvasError):
            wait(gmp, deadline=999999999)

    def test_stops_the_task_and_raises_once_the_deadline_passes(self):
        running = xml('<get_tasks_response><task><status>Running</status></task></get_tasks_response>')
        gmp = FakeGMP(get_task=lambda *a: running, stop_task=lambda *a: None)
        with self.assertRaises(openvas.OutOfBudget) as raised:
            wait(gmp, deadline=0)  # already past
        self.assertIsInstance(raised.exception, openvas.OpenvasError)
        self.assertIn('stop_task', gmp.names())


def happy_gmp():
    """A gvmd that runs one task to Done with one CVE-bearing result on a host its report lists."""
    results_page = xml(f'<get_results_response><results>{RESULT_WITH_CVE}</results></get_results_response>')
    report_detail = xml('<get_report_response><report><host><ip>192.0.2.10</ip></host></report></get_report_response>')
    done_status = xml('<get_tasks_response><task><status>Done</status>'
                      '<last_report><report id="rep1"/></last_report></task></get_tasks_response>')
    return FakeGMP(
        get_scan_configs=lambda **kw: xml(f'<get_configs_response>{EXISTING_CONFIG_XML}</get_configs_response>'),
        get_nvt_families=lambda: xml(FAMILIES_XML),
        get_scan_config=lambda *a, **kw: config_detail(selected=('Web application abuses', 'General')),
        modify_scan_config_set_family_selection=lambda *a, **kw: None,
        modify_scan_config_set_scanner_preference=lambda *a, **kw: None,
        get_scanners=lambda **kw: xml(f'<get_scanners_response><scanner id="{openvas.OPENVAS_SCANNER[0]}">'
                                      f'<name>{openvas.OPENVAS_SCANNER[1]}</name></scanner></get_scanners_response>'),
        get_port_lists=lambda **kw: xml(f'<get_port_lists_response><port_list id="{openvas.PORT_LIST[0]}">'
                                        f'<name>{openvas.PORT_LIST[1]}</name></port_list></get_port_lists_response>'),
        create_target=lambda *a, **kw: xml('<create_target_response id="target-1"/>'),
        create_task=lambda *a, **kw: xml('<create_task_response id="task-1"/>'),
        start_task=lambda *a: None,
        get_task=lambda *a: done_status,
        get_results=lambda **kw: results_page,
        get_report=lambda *a, **kw: report_detail,
        delete_task=lambda *a, **kw: None,
        delete_target=lambda *a, **kw: None,
    )


class RunOpenvasTests(OpenvasTestCase):
    def _happy_gmp(self):
        return happy_gmp()

    def test_the_happy_path_returns_the_shape_the_server_expects(self):
        gmp = self._happy_gmp()
        with sessions(gmp):
            result = openvas.run_openvas({HOST: 'www.example.test'}, excluded_families=['Denial of Service'], max_hours_=1)
        self.assertEqual(len(result['results']), 1)
        self.assertEqual(result['results'][0]['cves'], ['CVE-2024-12345'])
        self.assertEqual(result['scanned_addresses'], ['192.0.2.10'])
        self.assertEqual(result['without_cve'], 0)
        self.assertEqual(result['unusable'], 0)
        self.assertIn('delete_task', gmp.names())
        self.assertIn('delete_target', gmp.names())
        create_target_call = next(c for c in gmp.calls if c[0] == 'create_target')
        self.assertEqual(create_target_call[2]['hosts'], [HOST])

    def test_the_result_is_not_partial_when_the_task_finished(self):
        with sessions(self._happy_gmp()):
            self.assertIs(openvas.run_openvas({HOST: 'www.example.test'})['partial'], False)

    def _out_of_budget_gmp(self, results=True):
        gmp = self._happy_gmp()
        gmp.responses['get_task'] = lambda *a: xml('<get_tasks_response><task><status>Running</status>'
                                                   '<current_report><report id="rep1"/></current_report></task></get_tasks_response>')
        gmp.responses['stop_task'] = lambda *a: None
        if not results:
            gmp.responses['get_results'] = lambda **kw: xml('<get_results_response><results></results></get_results_response>')
        return gmp

    def test_a_task_past_its_budget_is_stopped_and_what_it_found_is_returned_as_partial(self):
        gmp = self._out_of_budget_gmp()
        with sessions(gmp), mock.patch('client.openvas.time.monotonic', side_effect=[0, 10 ** 9, 10 ** 9]):
            result = openvas.run_openvas({HOST: 'www.example.test'}, max_hours_=1)
        self.assertIs(result['partial'], True)
        self.assertEqual(result['results'][0]['cves'], ['CVE-2024-12345'])
        self.assertEqual(result['scanned_addresses'], ['192.0.2.10'])  # only a host that has a result counts as scanned
        self.assertIn('stop_task', gmp.names())
        self.assertIn('delete_task', gmp.names())  # still cleaned up

    def test_a_task_past_its_budget_with_nothing_found_is_a_failure(self):
        gmp = self._out_of_budget_gmp(results=False)
        with sessions(gmp), mock.patch('client.openvas.time.monotonic', side_effect=[0, 10 ** 9, 10 ** 9]):
            with self.assertRaises(openvas.OpenvasError) as raised:
                openvas.run_openvas({HOST: 'www.example.test'}, max_hours_=1)
        self.assertIn('time budget', str(raised.exception))
        self.assertIn('rep1', str(raised.exception))  # the report id, to find it in gvmd or the logs
        self.assertIn('delete_target', gmp.names())

    def test_the_servers_max_checks_is_used_within_bounds_and_one_host_at_a_time_always(self):
        self.assertEqual(openvas.task_preferences(None), {'max_checks': '4', 'max_hosts': '1'})
        self.assertEqual(openvas.task_preferences({'max_checks': 2, 'max_hosts': 9}), {'max_checks': '2', 'max_hosts': '1'})
        self.assertEqual(openvas.task_preferences({'max_checks': '99'})['max_checks'], '10')
        self.assertEqual(openvas.task_preferences({'max_checks': 0})['max_checks'], '1')
        self.assertEqual(openvas.task_preferences({'max_checks': 'many'})['max_checks'], '4')
        gmp = self._happy_gmp()
        with sessions(gmp):
            openvas.run_openvas({HOST: 'www.example.test'}, preferences={'max_checks': 3})
        self.assertEqual(next(c for c in gmp.calls if c[0] == 'create_task')[2]['preferences'], {'max_checks': '3', 'max_hosts': '1'})

    def test_no_hosts_raises_without_opening_a_session(self):
        with mock.patch('client.openvas.session') as session_mock:
            with self.assertRaises(openvas.OpenvasError):
                openvas.run_openvas({})
        session_mock.assert_not_called()

    def test_cleans_up_the_target_and_task_even_when_fetching_results_fails(self):
        gmp = self._happy_gmp()
        gmp.responses['get_results'] = mock.Mock(side_effect=RuntimeError('gvmd hiccup'))
        with sessions(gmp):
            with self.assertRaises(RuntimeError):
                openvas.run_openvas({HOST: 'www.example.test'})
        self.assertIn('delete_task', gmp.names())
        self.assertIn('delete_target', gmp.names())

    def test_register_is_called_with_a_handle_that_reports_the_run_finished(self):
        gmp = self._happy_gmp()
        register = mock.Mock()
        with sessions(gmp):
            openvas.run_openvas({HOST: 'www.example.test'}, register=register)
        register.assert_called_once()
        handle = register.call_args[0][0]
        self.assertEqual(handle.poll(), 0)


class CredentialsTests(OpenvasTestCase):
    def test_round_trips_and_is_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'sub', 'creds.json')
            openvas.save_credentials('admin', 's3cret', path=path)
            self.assertEqual(openvas.load_credentials(path=path), ('admin', 's3cret'))
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)

    def test_missing_or_corrupt_file_reads_as_no_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(openvas.load_credentials(path=os.path.join(tmp, 'nope.json')))
            bad = os.path.join(tmp, 'bad.json')
            with open(bad, 'w', encoding='utf-8') as handle:
                handle.write('not json')
            self.assertIsNone(openvas.load_credentials(path=bad))

    def test_ensure_credentials_bootstraps_only_when_nothing_is_saved(self):
        with mock.patch('client.openvas.load_credentials', return_value=('u', 'p')), \
                mock.patch('client.openvas.bootstrap_credentials') as bootstrap:
            self.assertEqual(openvas.ensure_credentials(), ('u', 'p'))
        bootstrap.assert_not_called()
        with mock.patch('client.openvas.load_credentials', return_value=None), \
                mock.patch('client.openvas.bootstrap_credentials', return_value=('admin', 'new')) as bootstrap:
            self.assertEqual(openvas.ensure_credentials(), ('admin', 'new'))
        bootstrap.assert_called_once()


class BootstrapCredentialsTests(OpenvasTestCase):
    def test_replaces_the_default_password_and_persists_it(self):
        admin_user = xml('<get_users_response><user id="u1"><name>admin</name></user></get_users_response>')
        gmp = FakeGMP(authenticate=lambda *a: None, get_users=lambda **kw: admin_user, modify_user=lambda *a, **kw: None)
        with mock.patch('client.openvas._open_gmp', side_effect=lambda *a, **kw: _ctx(gmp)), \
                mock.patch('client.openvas.save_credentials') as save:
            username, password = openvas.bootstrap_credentials()
        self.assertEqual(username, 'admin')
        self.assertTrue(password)
        save.assert_called_once_with('admin', password)
        self.assertIn('modify_user', gmp.names())

    def test_no_admin_user_raises(self):
        gmp = FakeGMP(authenticate=lambda *a: None, get_users=lambda **kw: xml('<get_users_response/>'))
        with mock.patch('client.openvas._open_gmp', side_effect=lambda *a, **kw: _ctx(gmp)):
            with self.assertRaises(openvas.OpenvasError):
                openvas.bootstrap_credentials()


class BootstrapFallbackTests(OpenvasTestCase):
    """gvmd answers "Failed to find user" (404) when the default user changes its own password; the Sentinel then makes a login of its own."""

    def _gvm(self, **extra):
        from gvm.errors import GvmResponseError
        admin_user = xml('<get_users_response><user id="u1"><name>admin</name></user></get_users_response>')
        roles = xml('<get_roles_response><role id="r-admin"><name>Admin</name></role><role id="r-user"><name>User</name></role></get_roles_response>')
        calls = {'users': [admin_user]}

        def get_users(**kw):
            return calls['users'][-1] if kw.get('filter_string') == 'name=admin' else xml('<get_users_response/>')

        def modify_user(user_id, **kw):
            if user_id == 'u1':
                raise GvmResponseError('Failed to find user u1', 404)
        responses = dict(authenticate=lambda *a: None, get_users=get_users, modify_user=modify_user, get_roles=roles,
                         create_user=lambda *a, **kw: None)
        responses.update(extra)
        return FakeGMP(**responses)

    def _run(self, gmp):
        with mock.patch('client.openvas._open_gmp', side_effect=lambda *a, **kw: _ctx(gmp)), \
                mock.patch('client.openvas.save_credentials') as save:
            result = openvas.bootstrap_credentials()
        return result, save

    def test_a_refused_password_change_falls_back_to_a_login_of_the_sentinels_own(self):
        gmp = self._gvm()
        (username, password), save = self._run(gmp)
        self.assertEqual(username, openvas.DEDICATED_USER)
        save.assert_called_once_with(openvas.DEDICATED_USER, password)
        create = next(c for c in gmp.calls if c[0] == 'create_user')
        self.assertEqual((create[1], create[2]['role_ids']), ((openvas.DEDICATED_USER,), ['r-admin']))
        self.assertIn(('authenticate', (openvas.DEDICATED_USER, password), {}), gmp.calls)  # confirmed before it is trusted

    def test_a_dedicated_user_left_by_an_earlier_attempt_gets_a_new_password_instead(self):
        mine = xml(f'<get_users_response><user id="u2"><name>{openvas.DEDICATED_USER}</name></user></get_users_response>')
        admin_user = xml('<get_users_response><user id="u1"><name>admin</name></user></get_users_response>')
        gmp = self._gvm(get_users=lambda **kw: admin_user if kw.get('filter_string') == 'name=admin' else mine)
        (username, _), _save = self._run(gmp)
        self.assertEqual(username, openvas.DEDICATED_USER)
        self.assertNotIn('create_user', gmp.names())
        self.assertIn('u2', [c[1][0] for c in gmp.calls if c[0] == 'modify_user'])

    def test_when_both_are_refused_the_error_carries_what_gvmd_said_and_never_the_password(self):
        from gvm.errors import GvmResponseError

        def refuse(*a, **kw):
            raise GvmResponseError('Permission denied for create_user', 403)
        gmp = self._gvm(create_user=refuse)
        with mock.patch('client.openvas._open_gmp', side_effect=lambda *a, **kw: _ctx(gmp)), mock.patch('client.openvas.save_credentials') as save:
            with self.assertRaises(openvas.OpenvasError) as raised:
                openvas.bootstrap_credentials()
        message = str(raised.exception)
        self.assertIn('Failed to find user u1', message)
        self.assertIn('Permission denied for create_user', message)
        self.assertIn('GvmResponseError', message)
        save.assert_not_called()
        passwords = [c[2].get('password') for c in gmp.calls if c[0] in ('modify_user', 'create_user')]
        self.assertTrue(passwords and not any(p in message for p in passwords if p))

    def test_a_default_login_that_does_not_work_says_why(self):
        from gvm.errors import GvmResponseError
        gmp = FakeGMP(authenticate=mock.Mock(side_effect=GvmResponseError('Authentication failed', 400)))
        with mock.patch('client.openvas._open_gmp', side_effect=lambda *a, **kw: _ctx(gmp)):
            with self.assertRaises(openvas.OpenvasError) as raised:
                openvas.bootstrap_credentials()
        self.assertIn('Authentication failed', str(raised.exception))


class ReadinessTests(OpenvasTestCase):
    CONFIGS = '<get_configs_response><config id="daba56c8-73ec-11df-a475-002264764cea"><name>Full and fast</name></config></get_configs_response>'
    SCANNERS = '<get_scanners_response><scanner id="08b69003-5fc2-4037-a479-93b440211c73"><name>OpenVAS Default</name></scanner></get_scanners_response>'
    PORTS = '<get_port_lists_response><port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"><name>All IANA assigned TCP</name></port_list></get_port_lists_response>'
    EMPTY = '<get_configs_response/>'
    SYNCING = '<get_feeds_response><feed><type>SCAP</type><currently_syncing><timestamp>2026</timestamp></currently_syncing></feed></get_feeds_response>'
    SYNCED = '<get_feeds_response><feed><type>SCAP</type><name>SCAP</name></feed><feed><type>CERT</type></feed></get_feeds_response>'

    def socket(self):
        open(os.path.join(self.dir.name, 'gvmd.sock'), 'w').close()

    def check(self, configs=CONFIGS, scanners=SCANNERS, ports=PORTS, feeds=SYNCED):
        gmp = FakeGMP(get_scan_configs=xml(configs), get_scanners=xml(scanners), get_port_lists=xml(ports), get_feeds=xml(feeds))
        with sessions(gmp):
            return openvas.readiness()

    def test_no_socket_is_not_ready_and_says_the_stack_is_starting(self):
        ready, why = openvas.readiness()
        self.assertFalse(ready)
        self.assertIn('socket', why)

    def test_a_socket_with_no_scan_configuration_is_still_loading_feeds(self):
        self.socket()
        ready, why = self.check(configs=self.EMPTY, feeds=self.SYNCING)
        self.assertFalse(ready)
        self.assertIn('still loading its feeds', why)

    def test_missing_scanner_or_port_list_is_not_ready(self):
        self.socket()
        self.assertIn('scanner', self.check(scanners='<get_scanners_response/>')[1])
        self.assertIn('port lists', self.check(ports='<get_port_lists_response/>')[1])

    def test_feeds_still_syncing_for_the_first_time_block_readiness_with_a_clear_reason(self):
        self.socket()
        ready, why = self.check(feeds=self.SYNCING)
        self.assertEqual((ready, why), (False, 'GVM is still syncing its SCAP feed(s)'))
        self.assertFalse(os.path.exists(openvas._ready_marker()))

    def test_ready_once_everything_is_loaded_and_a_later_routine_sync_does_not_take_it_away(self):
        self.socket()
        self.assertEqual(self.check(), (True, ''))
        self.assertTrue(os.path.exists(openvas._ready_marker()))
        self.assertEqual(self.check(feeds=self.SYNCING), (True, ''))  # the daily feed update: the scan data is already there
        self.assertFalse(self.check(configs=self.EMPTY)[0])  # but a wiped scan configuration is not ready

    def test_a_gmp_failure_is_a_reason_not_a_crash(self):
        self.socket()
        with mock.patch('client.openvas.session', side_effect=openvas.OpenvasError('gvmd refused the GMP login (GvmResponseError: nope)')):
            ready, why = openvas.readiness()
        self.assertEqual((ready, why), (False, 'gvmd refused the GMP login (GvmResponseError: nope)'))

    def test_a_task_dispatched_while_feeds_sync_fails_with_that_reason_before_building_anything(self):
        gmp = FakeGMP(get_feeds=xml(self.SYNCING))
        with sessions(gmp):
            with self.assertRaises(openvas.OpenvasError) as raised:
                openvas.run_openvas({HOST: 'x'})
        self.assertIn('still syncing its SCAP feed', str(raised.exception))
        self.assertEqual(gmp.names(), ['get_feeds'])


class SessionErrorTextTests(OpenvasTestCase):
    def test_gvmd_errors_keep_their_own_text(self):
        from gvm.errors import GvmResponseError

        class ClosingFakeGMP(FakeGMP):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False
        gmp = ClosingFakeGMP(authenticate=mock.Mock(side_effect=GvmResponseError('Failed to find user', 404)))
        with mock.patch('client.openvas.ensure_credentials', return_value=('u', 'p')), mock.patch('client.openvas._open_gmp', return_value=gmp):
            with self.assertRaises(openvas.OpenvasError) as raised:
                with openvas.session():
                    pass
        self.assertIn('Failed to find user', str(raised.exception))
        self.assertIn('404', str(raised.exception))


class SessionTests(OpenvasTestCase):
    def test_yields_an_authenticated_gmp_and_closes_it(self):
        closed = {'value': False}

        class ClosingFakeGMP(FakeGMP):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                closed['value'] = True
                return False

        gmp = ClosingFakeGMP(authenticate=lambda *a: None)
        with mock.patch('client.openvas.ensure_credentials', return_value=('u', 'p')), \
                mock.patch('client.openvas._open_gmp', return_value=gmp):
            with openvas.session() as session_gmp:
                self.assertIs(session_gmp, gmp)
        self.assertTrue(closed['value'])
        self.assertIn('authenticate', gmp.names())

    def test_a_gvm_error_on_authenticate_is_reported_as_openvaserror(self):
        from gvm.errors import GvmError

        class ClosingFakeGMP(FakeGMP):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        gmp = ClosingFakeGMP(authenticate=mock.Mock(side_effect=GvmError('nope')))
        with mock.patch('client.openvas.ensure_credentials', return_value=('u', 'wrong')), \
                mock.patch('client.openvas._open_gmp', return_value=gmp):
            with self.assertRaises(openvas.OpenvasError):
                with openvas.session():
                    pass



# ----------------------------------------------------------------------------- what the server sends is checked (C1 to C3)

class HostsValidationTests(OpenvasTestCase):
    def test_only_plain_allowed_addresses_reach_gvmd(self):
        refused = ['10.0.0.0/8', '0.0.0.0/1', '52.151.200.1-52.151.200.9', '52.151.200.1,52.151.200.2', '52.151.200.1 52.151.200.2',
                   'example.com', 'localhost', '127.0.0.1', '169.254.169.254', '::1', '0.0.0.0', '10.0.0.5', '2130706433', '', ' ']
        for key in refused:
            with self.subTest(key=key), mock.patch('client.openvas.session') as session_mock:
                with self.assertRaises(openvas.OpenvasError):
                    openvas.run_openvas({key: 'x'})
                session_mock.assert_not_called()

    def test_the_hosts_must_be_a_small_mapping(self):
        for hosts in ([HOST], HOST, None, {}, {f'52.151.200.{i}': '' for i in range(1, openvas.MAX_HOSTS + 2)}):
            with self.subTest(hosts=str(hosts)[:40]), mock.patch('client.openvas.session') as session_mock:
                with self.assertRaises(openvas.OpenvasError):
                    openvas.run_openvas(hosts)
                session_mock.assert_not_called()

    def test_canonical_addresses_and_clean_labels(self):
        addresses, labels = openvas.check_hosts({' 2606:4700:4700:0:0:0:0:1111 ': 'a\x00b\x07', HOST: 42})
        self.assertEqual(addresses, sorted(['2606:4700:4700::1111', HOST]))
        self.assertEqual(labels, {'2606:4700:4700::1111': 'ab', HOST: ''})

    def test_private_space_only_on_an_internal_sentinel(self):
        with mock.patch('client.config._local_internal', return_value=True):
            self.assertEqual(openvas.check_hosts({'10.0.0.5': 'db'})[0], ['10.0.0.5'])
        with mock.patch('client.config._local_internal', return_value=False):
            self.assertRaises(openvas.OpenvasError, openvas.check_hosts, {'10.0.0.5': 'db'})


class BudgetTests(OpenvasTestCase):
    def test_the_server_can_lower_the_budget_but_never_raise_it(self):
        self.assertEqual(openvas.budget_hours(None), 24)
        self.assertEqual(openvas.budget_hours('1.5'), 1.5)
        self.assertEqual(openvas.budget_hours(10 ** 6), 24)
        self.assertEqual(openvas.budget_hours(0), 1)
        self.assertEqual(openvas.budget_hours(-5), 1)
        self.assertEqual(openvas.budget_hours('many'), 24)
        self.assertEqual(openvas.budget_hours(float('nan')), 24)
        self.assertEqual(openvas.budget_hours(float('inf')), 24)
        with mock.patch.dict('os.environ', {'CVENGINE_OPENVAS_MAX_HOURS': '6'}):
            self.assertEqual(openvas.budget_hours(10), 6)

    def test_the_run_deadline_uses_the_clamped_budget(self):
        gmp = happy_gmp()
        with sessions(gmp), mock.patch('client.openvas._wait_for_task', side_effect=openvas.OpenvasError('x')) as waited:
            with self.assertRaises(openvas.OpenvasError):
                openvas.run_openvas({HOST: ''}, max_hours_=10 ** 6)
        deadline = waited.call_args[0][2]
        self.assertLessEqual(deadline - time.monotonic(), 24 * 3600 + 5)


class ExcludedFamiliesTests(OpenvasTestCase):
    def test_a_list_of_names_is_required_and_the_local_minimum_is_always_kept(self):
        for bad in ('Denial of Service', [1], ['ok', None], {'a': 1}, ['x'] * (openvas.MAX_EXCLUDED + 1)):
            with self.subTest(bad=str(bad)[:30]):
                self.assertRaises(openvas.OpenvasError, openvas.check_excluded_families, bad)
        self.assertEqual(set(openvas.check_excluded_families(None)), set(openvas.MIN_EXCLUDED_FAMILIES))
        self.assertEqual(set(openvas.check_excluded_families([' General '])), set(openvas.MIN_EXCLUDED_FAMILIES) | {'General'})

    def test_names_match_without_case_and_an_unknown_one_is_logged(self):
        gmp = FakeGMP(
            get_scan_configs=lambda **kw: xml(f'<get_configs_response>{EXISTING_CONFIG_XML}</get_configs_response>'),
            get_nvt_families=lambda: xml(FAMILIES_XML),
            get_scan_config=mock.Mock(side_effect=[config_detail(), config_detail(selected=('Web application abuses',))]),
            modify_scan_config_set_family_selection=lambda *a, **kw: None,
            modify_scan_config_set_scanner_preference=lambda *a, **kw: None,
        )
        with self.assertLogs('sentinel.openvas', 'WARNING') as logs:
            openvas.ensure_config(gmp, ['denial of service', 'GENERAL', 'Web aplication abuses'])
        wanted = next(c for c in gmp.calls if c[0] == 'modify_scan_config_set_family_selection')[1][1]
        self.assertEqual(wanted, [('Web application abuses', True, True)])
        self.assertTrue(any('Web aplication abuses' in line for line in logs.output))


# ----------------------------------------------------------------------------- empty configurations and empty runs (C5, C6, C8)

class ConfigGuardTests(OpenvasTestCase):
    def gmp(self, families=FAMILIES_XML, details=None, modify=None):
        return FakeGMP(
            get_scan_configs=lambda **kw: (self.assertTrue(openvas._CONFIG_LOCK.locked()),
                                           xml(f'<get_configs_response>{EXISTING_CONFIG_XML}</get_configs_response>'))[1],
            get_nvt_families=lambda: xml(families),
            get_scan_config=mock.Mock(side_effect=details or [config_detail(), config_detail(selected=('Web application abuses', 'General'))]),
            modify_scan_config_set_family_selection=modify or (lambda *a, **kw: None),
            modify_scan_config_set_scanner_preference=lambda *a, **kw: None,
        )

    def test_no_families_at_all_is_an_error_not_an_empty_selection(self):
        gmp = self.gmp(families='<get_nvt_families_response><families/></get_nvt_families_response>')
        with self.assertRaises(openvas.OpenvasError):
            openvas.ensure_config(gmp, [])
        self.assertNotIn('modify_scan_config_set_family_selection', gmp.names())

    def test_a_config_with_no_nvts_after_the_change_is_an_error(self):
        gmp = self.gmp(details=[config_detail(), config_detail(selected=('General',), nvt_count=0)])
        with self.assertRaises(openvas.OpenvasError) as raised:
            openvas.ensure_config(gmp, [])
        self.assertIn('no NVTs', str(raised.exception))

    def test_an_unchanged_selection_is_not_written_again(self):
        gmp = self.gmp(details=[config_detail(selected=('Web application abuses', 'General'))])
        self.assertEqual(openvas.ensure_config(gmp, []), 'cfg-existing')
        self.assertNotIn('modify_scan_config_set_family_selection', gmp.names())
        self.assertNotIn('modify_scan_config_set_scanner_preference', gmp.names())
        self.assertEqual(gmp.names().count('get_scan_configs'), 1)

    def test_safe_checks_off_is_written_again(self):
        gmp = self.gmp(details=[config_detail(selected=('Web application abuses', 'General'), safe_checks='no'),
                                config_detail(selected=('Web application abuses', 'General'))])
        openvas.ensure_config(gmp, [])
        self.assertIn('modify_scan_config_set_scanner_preference', gmp.names())

    def test_a_config_in_use_is_scanned_with_as_it_is_when_it_excludes_at_least_as_much(self):
        from gvm.errors import GvmResponseError

        def in_use(*a, **kw):
            raise GvmResponseError('400', 'Config is in use')
        narrower = config_detail(selected=('General',))
        gmp = self.gmp(details=[narrower, narrower], modify=in_use)
        with self.assertLogs('sentinel.openvas', 'WARNING'):
            self.assertEqual(openvas.ensure_config(gmp, []), 'cfg-existing')

    def test_a_config_in_use_that_scans_an_excluded_family_fails_the_task(self):
        from gvm.errors import GvmResponseError

        def in_use(*a, **kw):
            raise GvmResponseError('400', 'Config is in use')
        gmp = self.gmp(details=[config_detail(selected=('Denial of Service', 'General'))] * 2, modify=in_use)
        with self.assertRaises(openvas.OpenvasError) as raised:
            openvas.ensure_config(gmp, [])
        self.assertIn('in use', str(raised.exception))

    def test_other_gvmd_refusals_are_not_swallowed(self):
        from gvm.errors import GvmResponseError

        def refuse(*a, **kw):
            raise GvmResponseError('400', 'Family must be growing')
        with self.assertRaises(GvmResponseError):
            openvas.ensure_config(self.gmp(modify=refuse), [])


class RunOutcomeTests(OpenvasTestCase):
    def happy(self):
        return happy_gmp()

    def test_a_done_run_with_no_result_and_no_host_is_an_error_naming_the_report(self):
        gmp = self.happy()
        gmp.responses['get_results'] = lambda **kw: xml('<get_results_response><results/></get_results_response>')
        gmp.responses['get_report'] = lambda *a, **kw: xml(
            '<get_reports_response><report id="rep1"><report id="rep1"><hosts><count>0</count></hosts><result_count><full>0</full></result_count>'
            '<errors><error><host>' + HOST + '</host><description>Host dead</description></error></errors></report></report></get_reports_response>')
        with sessions(gmp), self.assertRaises(openvas.OpenvasError) as raised:
            openvas.run_openvas({HOST: ''})
        message = str(raised.exception)
        for part in ('scanned no host', 'rep1', 'Host dead', '0 host(s), 0 result(s)'):
            self.assertIn(part, message)
        self.assertIn('delete_task', gmp.names())

    def test_a_summary_is_logged_before_the_task_is_removed(self):
        gmp = self.happy()
        with sessions(gmp), self.assertLogs('sentinel.openvas', 'INFO') as logs:
            openvas.run_openvas({HOST: 'www.example.test'})
        summary = next(line for line in logs.output if 'GVM task task-1' in line)
        for part in ('status Done', 'report rep1', 'www.example.test'):
            self.assertIn(part, summary)

    def test_keep_tasks_leaves_task_target_and_report_in_gvmd(self):
        gmp = self.happy()
        with mock.patch.dict('os.environ', {'CVENGINE_OPENVAS_KEEP_TASKS': '1'}), sessions(gmp):
            openvas.run_openvas({HOST: ''})
        self.assertNotIn('delete_task', gmp.names())
        self.assertNotIn('delete_target', gmp.names())

    def test_an_interrupted_task_returns_what_it_found_as_partial(self):
        gmp = self.happy()
        gmp.responses['get_task'] = lambda *a: xml('<get_tasks_response><task><status>Interrupted</status>'
                                                   '<last_report><report id="rep1"/></last_report></task></get_tasks_response>')
        with sessions(gmp):
            result = openvas.run_openvas({HOST: ''})
        self.assertIs(result['partial'], True)
        self.assertEqual(result['scanned_addresses'], ['192.0.2.10'])

    def test_an_interrupted_task_with_nothing_found_is_an_error(self):
        gmp = self.happy()
        gmp.responses['get_task'] = lambda *a: xml('<get_tasks_response><task><status>Interrupted</status></task></get_tasks_response>')
        gmp.responses['get_results'] = lambda **kw: xml('<get_results_response><results/></get_results_response>')
        with sessions(gmp), self.assertRaises(openvas.OpenvasError) as raised:
            openvas.run_openvas({HOST: ''})
        self.assertIn('Interrupted', str(raised.exception))


# ----------------------------------------------------------------------------- results payload (C9, C10)

class PayloadTests(OpenvasTestCase):
    def item(self, address, port, severity, cves=(), size=0):
        return {'address': address, 'port': port, 'severity': severity, 'cves': list(cves), 'oid': '1.2.3', 'result': 'x' * size}

    def test_items_without_a_cve_are_compacted_and_deduplicated(self):
        items = [self.item('192.0.2.1', '80/tcp', 0.0), self.item('192.0.2.1', '80/tcp', 2.0), self.item('192.0.2.2', '22/tcp', 0.0),
                 self.item('192.0.2.1', '443/tcp', 9.0, cves=['CVE-2024-0001'])]
        results, dropped_compact, dropped_cve = openvas.bound_results(items)
        self.assertEqual(results[0], items[3])  # unchanged
        self.assertEqual(results[1:], [{'address': '192.0.2.1', 'port': '80/tcp'}, {'address': '192.0.2.2', 'port': '22/tcp'}])
        self.assertEqual((dropped_compact, dropped_cve), (0, 0))

    def test_the_size_bound_drops_items_without_a_cve_first_then_the_lowest_severity(self):
        items = [self.item(f'192.0.2.{i}', '80/tcp', float(i % 10)) for i in range(50)]
        items += [self.item('192.0.2.200', f'{p}/tcp', float(p % 10), cves=['CVE-2024-0001'], size=1000) for p in range(1, 11)]
        results, dropped_compact, dropped_cve = openvas.bound_results(items, limit=8000)
        self.assertEqual(dropped_compact, 50)
        self.assertGreater(dropped_cve, 0)
        self.assertLessEqual(len(json.dumps(results)), 8000)
        kept = [r['severity'] for r in results]
        self.assertEqual(kept, sorted(kept, reverse=True))
        self.assertGreaterEqual(min(kept), max(i['severity'] for i in items[50:] if i not in results))

    def test_a_cut_result_set_is_partial(self):
        gmp = happy_gmp()
        with sessions(gmp), mock.patch('client.openvas.MAX_PAYLOAD_BYTES', 10):
            result = openvas.run_openvas({HOST: ''})
        self.assertIs(result['partial'], True)

    def test_solution_type_is_read_from_the_solution_element_first(self):
        modern = xml(RESULT_WITH_CVE.replace('<solution>Patch it</solution>', '<solution type="VendorFix">Patch it</solution>'))
        self.assertEqual(openvas.parse_result(modern)['solution_type'], 'VendorFix')
        self.assertEqual(openvas.parse_result(xml(RESULT_WITH_CVE))['solution_type'], 'Mitigation')  # the old tag still works


# ----------------------------------------------------------------------------- stopping a run, leftovers, retries (C11 to C13)

class StopTests(OpenvasTestCase):
    def running_gmp(self):
        gmp = happy_gmp()
        gmp.responses['get_task'] = lambda *a: xml('<get_tasks_response><task><status>Running</status></task></get_tasks_response>')
        gmp.responses['stop_task'] = lambda *a: None
        return gmp

    def test_the_daemon_can_kill_a_run_through_its_handle(self):
        import threading
        gmp = self.running_gmp()
        handles, outcome = [], {}

        def run():
            try:
                openvas.run_openvas({HOST: ''}, register=handles.append)
            except openvas.OpenvasError as exc:
                outcome['error'] = str(exc)
        with sessions(gmp), mock.patch('client.openvas.POLL_INTERVAL', 0.05):
            thread = threading.Thread(target=run)
            thread.start()
            for _ in range(200):
                if handles and 'get_task' in gmp.names():
                    break
                threading.Event().wait(0.01)
            handle = handles[0]
            self.assertIsNone(handle.poll())
            handle.kill()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcome['error'], 'the task was stopped')
        self.assertEqual(handle.poll(), 1)
        self.assertIn('stop_task', gmp.names())
        self.assertEqual(gmp.names().count('delete_task'), 1)  # removed once, by the kill
        self.assertEqual(gmp.names().count('delete_target'), 1)

    def test_kill_never_raises(self):
        run = openvas.OpenvasRun()
        run.task_id, run.target_id = 'task-1', 'target-1'
        with mock.patch('client.openvas.session', side_effect=PermissionError('socket')):
            run.kill()
        self.assertTrue(run.cancelled.is_set())

    def test_the_wait_loop_stops_the_task_once_cancelled(self):
        running = xml('<get_tasks_response><task><status>Running</status></task></get_tasks_response>')
        gmp = FakeGMP(get_task=lambda *a: running, stop_task=lambda *a: None)
        run = openvas.OpenvasRun()
        run.cancelled.set()
        with self.assertRaises(openvas.OpenvasError) as raised:
            wait(gmp, deadline=999999999, run=run)
        self.assertEqual(str(raised.exception), 'the task was stopped')
        self.assertIn('stop_task', gmp.names())


class OrphanTests(OpenvasTestCase):
    NOW = '2026-10-28T12:00:00+00:00'

    def gmp(self):
        tasks = xml(
            '<get_tasks_response>'
            '<task id="t-done"><name>cvengine-sentinel-aaa</name><status>Done</status><creation_time>2026-10-28T11:00:00Z</creation_time>'
            '<target id="g-done"/></task>'
            '<task id="t-young"><name>cvengine-sentinel-bbb</name><status>Running</status><creation_time>2026-10-28T11:00:00Z</creation_time>'
            '<target id="g-young"/></task>'
            '<task id="t-old"><name>cvengine-sentinel-ccc</name><status>Running</status><creation_time>2026-10-26T11:00:00Z</creation_time>'
            '<target id="g-old"/></task>'
            '<task id="t-mine"><name>cvengine-sentinel-ddd</name><status>Done</status><creation_time>2026-10-28T11:00:00Z</creation_time>'
            '<target id="g-mine"/></task>'
            '<task id="t-other"><name>someone else</name><status>Done</status><creation_time>2020-01-01T00:00:00Z</creation_time>'
            '<target id="g-other"/></task>'
            '</get_tasks_response>')
        targets = xml(
            '<get_targets_response>' + ''.join(f'<target id="g-{n}"><name>cvengine-sentinel-{n}</name></target>'
                                               for n in ('done', 'young', 'old', 'mine', 'free'))
            + '<target id="g-other"><name>someone else</name></target><target id="g-x"><name>cvengine-sentinelx</name></target>'
            '</get_targets_response>')
        statuses = {'t-old': 'Stopped'}
        return FakeGMP(get_tasks=lambda **kw: tasks, get_targets=lambda **kw: targets, stop_task=lambda *a: None,
                       get_task=lambda task_id: xml(f'<get_tasks_response><task><status>{statuses.get(task_id, "Done")}</status></task>'
                                                    f'</get_tasks_response>'),
                       delete_task=lambda *a, **kw: None, delete_target=lambda *a, **kw: None)

    def sweep(self, gmp):
        from datetime import datetime
        openvas._active(['t-mine', 'g-mine'], True)
        self.addCleanup(openvas._active, ['t-mine', 'g-mine'], False)
        with sessions(gmp):
            return openvas.cleanup_orphans(max_age_hours=24, now=datetime.fromisoformat(self.NOW))

    def test_only_this_sentinels_leftovers_are_removed(self):
        gmp = self.gmp()
        removed = self.sweep(gmp)
        deleted_tasks = [c[1][0] for c in gmp.calls if c[0] == 'delete_task']
        deleted_targets = [c[1][0] for c in gmp.calls if c[0] == 'delete_target']
        self.assertEqual(deleted_tasks, ['t-done', 't-old'])
        self.assertEqual(sorted(deleted_targets), ['g-done', 'g-free', 'g-old'])
        self.assertEqual([c[1][0] for c in gmp.calls if c[0] == 'stop_task'], ['t-old'])  # stopped before it was deleted
        self.assertEqual(removed, {'tasks': 2, 'targets': 3})

    def test_keep_tasks_keeps_finished_ones_and_only_stops_old_running_ones(self):
        gmp = self.gmp()
        with mock.patch.dict('os.environ', {'CVENGINE_OPENVAS_KEEP_TASKS': '1'}):
            self.sweep(gmp)
        self.assertNotIn('delete_task', gmp.names())
        self.assertEqual([c[1][0] for c in gmp.calls if c[0] == 'delete_target'], ['g-free'])
        self.assertIn('stop_task', gmp.names())

    def test_never_raises(self):
        for error in (OSError('no socket'), openvas.OpenvasError('refused'), RuntimeError('boom')):
            with self.subTest(error=error), mock.patch('client.openvas.session', side_effect=error):
                self.assertEqual(openvas.cleanup_orphans(), {'tasks': 0, 'targets': 0})


class ClosingFake(FakeGMP):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class RetryTests(OpenvasTestCase):
    def setUp(self):
        super().setUp()
        for name, value in (('RETRY_DELAY', 0), ('POLL_INTERVAL', 0)):
            patcher = mock.patch(f'client.openvas.{name}', value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_dropped_connection_is_retried_with_a_fresh_session(self):
        from gvm.errors import GvmError
        gmp = ClosingFake(authenticate=lambda *a: None, get_task=lambda *a: 'answer')
        attempts = [ConnectionRefusedError('gvmd restarting'), gmp, gmp]

        def open_gmp(*a, **kw):
            value = attempts.pop(0)
            if isinstance(value, Exception):
                raise value
            return value
        flaky = {'n': 0}

        def step(session_gmp):
            flaky['n'] += 1
            if flaky['n'] == 1:
                raise GvmError('Remote closed the connection')
            return session_gmp.get_task('t')
        with mock.patch('client.openvas.ensure_credentials', return_value=('u', 'p')), mock.patch('client.openvas._open_gmp', side_effect=open_gmp):
            self.assertEqual(openvas.with_session(step), 'answer')

    def test_gvmd_refusals_are_not_retried(self):
        from gvm.errors import GvmResponseError
        gmp = ClosingFake(authenticate=lambda *a: None)
        calls = {'n': 0}

        def step(session_gmp):
            calls['n'] += 1
            raise GvmResponseError('404', 'Failed to find task')
        with mock.patch('client.openvas.ensure_credentials', return_value=('u', 'p')), mock.patch('client.openvas._open_gmp', return_value=gmp):
            with self.assertRaises(openvas.OpenvasError) as raised:
                openvas.with_session(step)
        self.assertNotIsInstance(raised.exception, openvas.TransientError)
        self.assertEqual(calls['n'], 1)

    def test_it_gives_up_after_a_few_tries(self):
        with mock.patch('client.openvas.session', side_effect=openvas.TransientError('down')) as session_mock:
            with self.assertRaises(openvas.TransientError):
                openvas.with_session(lambda gmp: None)
        self.assertEqual(session_mock.call_count, openvas.RETRIES + 1)

    def test_a_poll_survives_a_gvmd_restart(self):
        done = xml('<get_tasks_response><task><status>Done</status></task></get_tasks_response>')
        gmp = FakeGMP(get_task=lambda *a: done)
        answers = [openvas.TransientError('restarting'), _ctx(gmp)]

        def session(*a, **kw):
            value = answers.pop(0)
            if isinstance(value, Exception):
                raise value
            return value
        run = openvas.OpenvasRun()
        with mock.patch('client.openvas.session', side_effect=session):
            self.assertIs(openvas._wait_for_task(run, 'task-1', 999999999), done)


# ----------------------------------------------------------------------------- readiness and credentials (C16 to C19)

class ReadinessNeverRaisesTests(OpenvasTestCase):
    def test_any_failure_is_a_reason(self):
        from gvm.errors import GvmError
        open(openvas.socket_path(), 'w').close()
        for error in (OSError('nope'), TimeoutError('slow'), PermissionError('denied'), GvmError('odd'), ValueError('bad')):
            with self.subTest(error=type(error).__name__), mock.patch('client.openvas.session', side_effect=error):
                ready, why = openvas.readiness()
            self.assertFalse(ready)
            self.assertIn(type(error).__name__, why)

    def test_a_permission_error_from_the_connection_is_a_reason(self):
        open(openvas.socket_path(), 'w').close()
        with mock.patch('client.openvas.ensure_credentials', return_value=('u', 'p')), \
                mock.patch('client.openvas._open_gmp', side_effect=PermissionError('gvmd.sock')):
            ready, why = openvas.readiness()
        self.assertFalse(ready)
        self.assertIn('PermissionError', why)

    def test_a_bootstrap_failure_is_a_reason(self):
        open(openvas.socket_path(), 'w').close()
        with mock.patch('client.openvas._open_gmp', side_effect=OSError('socket gone')):
            ready, why = openvas.readiness()
        self.assertFalse(ready)
        self.assertIn('socket gone', why)


class CredentialFileTests(OpenvasTestCase):
    def test_non_object_json_reads_as_no_credentials(self):
        path = openvas.credentials_path()
        for text in ('[1, 2]', '"admin"', '42', 'null'):
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(text)
            self.assertIsNone(openvas.load_credentials(), text)

    def test_the_save_is_atomic(self):
        openvas.save_credentials('u', 'old')
        with mock.patch('client.openvas.json.dump', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                openvas.save_credentials('u', 'new')
        self.assertEqual(openvas.load_credentials(), ('u', 'old'))  # never truncated
        self.assertEqual(os.listdir(self.dir.name), ['creds.json'])  # no temporary file left behind
        self.assertEqual(stat.S_IMODE(os.stat(openvas.credentials_path()).st_mode), 0o600)


class TrackingGMP(ClosingFake):
    """A gvmd with real logins: ``passwords`` maps user to password; authenticate checks it, modify_user changes it."""

    def __init__(self, passwords, refuse_self_change=False, **extra):
        from gvm.errors import GvmResponseError
        self.passwords, self.user = passwords, None
        ids = {'u1': 'admin', 'u2': openvas.DEDICATED_USER}

        def authenticate(username, password):
            if self.passwords.get(username) != password:
                raise GvmResponseError('400', 'Authentication failed')
            self.user = username

        def modify_user(user_id, password=None, **kw):
            if refuse_self_change and ids[user_id] == self.user:
                raise GvmResponseError('404', 'Failed to find user')
            self.passwords[ids[user_id]] = password

        def create_user(name, password=None, **kw):
            self.passwords[name] = password

        def get_users(filter_string=''):
            name = filter_string.split('=', 1)[1]
            user_id = {v: k for k, v in ids.items()}[name]
            return xml(f'<get_users_response><user id="{user_id}"><name>{name}</name></user></get_users_response>'
                       if name in self.passwords else '<get_users_response/>')
        responses = dict(authenticate=authenticate, modify_user=modify_user, create_user=create_user, get_users=get_users,
                         get_roles=xml('<get_roles_response><role id="r-admin"><name>Admin</name></role></get_roles_response>'))
        responses.update(extra)
        super().__init__(**responses)


class BootstrapSafetyTests(OpenvasTestCase):
    def open_with(self, gmp):
        return mock.patch('client.openvas._open_gmp', side_effect=lambda *a, **kw: gmp)

    def test_the_new_login_is_on_disk_before_gvmd_changes_the_password(self):
        gmp = TrackingGMP({'admin': 'admin'})
        original = gmp.responses['modify_user']

        def modify_user(user_id, password=None, **kw):
            self.assertEqual(openvas.load_credentials(openvas.pending_credentials_path()), ('admin', password))
            original(user_id, password=password)
        gmp.responses['modify_user'] = modify_user
        with self.open_with(gmp):
            username, password = openvas.bootstrap_credentials()
        self.assertEqual(openvas.load_credentials(), ('admin', password))
        self.assertFalse(os.path.exists(openvas.pending_credentials_path()))

    def test_a_failed_save_after_the_change_is_recovered_on_the_next_attempt(self):
        gmp = TrackingGMP({'admin': 'admin'})
        with self.open_with(gmp), mock.patch('client.openvas.save_credentials', side_effect=OSError('read-only')):
            with self.assertRaises(openvas.OpenvasError):
                openvas.bootstrap_credentials()
        changed = gmp.passwords['admin']
        self.assertNotEqual(changed, 'admin')  # gvmd has the new password; only the pending file knows it
        gmp.calls.clear()
        with self.open_with(gmp):
            self.assertEqual(openvas.bootstrap_credentials(), ('admin', changed))
        self.assertNotIn('modify_user', gmp.names())
        self.assertEqual(openvas.load_credentials(), ('admin', changed))

    def test_a_stale_pending_login_falls_back_to_the_default_one(self):
        openvas._write_credentials(openvas.pending_credentials_path(), 'admin', 'never-applied')
        gmp = TrackingGMP({'admin': 'admin'})
        with self.open_with(gmp):
            username, password = openvas.bootstrap_credentials()
        self.assertEqual(gmp.passwords['admin'], password)
        self.assertNotEqual(password, 'never-applied')

    def test_concurrent_callers_change_the_password_once(self):
        import threading
        gmp = TrackingGMP({'admin': 'admin'})
        original = gmp.responses['modify_user']

        def slow_modify(user_id, password=None, **kw):
            threading.Event().wait(0.05)
            original(user_id, password=password)
        gmp.responses['modify_user'] = slow_modify
        results = []
        with self.open_with(gmp):
            threads = [threading.Thread(target=lambda: results.append(openvas.ensure_credentials())) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)
        self.assertEqual(gmp.names().count('modify_user'), 1)
        self.assertEqual(len(set(results)), 1)

    def test_raw_errors_become_openvas_errors(self):
        for error in (OSError('socket'), TimeoutError('slow'), PermissionError('denied')):
            with self.subTest(error=type(error).__name__), mock.patch('client.openvas._open_gmp', side_effect=error):
                with self.assertRaises(openvas.OpenvasError):
                    openvas.bootstrap_credentials()

    def test_after_the_fallback_login_the_default_admin_login_stops_working(self):
        gmp = TrackingGMP({'admin': 'admin'}, refuse_self_change=True)
        with self.open_with(gmp):
            username, password = openvas.bootstrap_credentials()
        self.assertEqual(username, openvas.DEDICATED_USER)
        self.assertNotEqual(gmp.passwords['admin'], 'admin')
        self.assertNotEqual(gmp.passwords['admin'], password)
        self.assertEqual(openvas.load_credentials(), (openvas.DEDICATED_USER, password))  # the admin password is saved nowhere


class ReBootstrapTests(OpenvasTestCase):
    def test_saved_credentials_gvmd_no_longer_accepts_are_replaced_once(self):
        openvas.save_credentials('admin', 'from-an-old-volume')
        gmp = TrackingGMP({'admin': 'admin'})  # gvmd's volume was recreated
        with mock.patch('client.openvas._open_gmp', side_effect=lambda *a, **kw: gmp):
            with openvas.session() as session_gmp:
                self.assertIs(session_gmp, gmp)
        username, password = openvas.load_credentials()
        self.assertEqual(gmp.passwords['admin'], password)

    def test_when_the_new_login_cannot_be_made_either_both_reasons_are_given(self):
        openvas.save_credentials('admin', 'old')
        gmp = TrackingGMP({'admin': 'changed by hand'})
        with mock.patch('client.openvas._open_gmp', side_effect=lambda *a, **kw: gmp):
            with self.assertRaises(openvas.OpenvasError) as raised:
                with openvas.session():
                    pass
        self.assertIn('refused the GMP login', str(raised.exception))
        self.assertIn('default GVM login did not work', str(raised.exception))

    def test_credentials_another_thread_already_replaced_are_used_without_a_new_bootstrap(self):
        from gvm.errors import GvmResponseError
        openvas.save_credentials('admin', 'fresh')
        with mock.patch('client.openvas.bootstrap_credentials') as bootstrap:
            self.assertEqual(openvas._rebootstrap(None, ('admin', 'stale'), GvmResponseError('400', 'Authentication failed')), ('admin', 'fresh'))
        bootstrap.assert_not_called()

if __name__ == '__main__':
    unittest.main()
