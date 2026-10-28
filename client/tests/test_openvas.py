import json
import os
import stat
import tempfile
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


class ParseResultTests(unittest.TestCase):
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


class FetchResultsTests(unittest.TestCase):
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


class ScannedAddressesTests(unittest.TestCase):
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


class EnsureConfigTests(unittest.TestCase):
    def test_builds_a_new_config_from_full_and_fast_when_none_exists(self):
        gmp = FakeGMP(
            get_scan_configs=lambda: xml(f'<get_configs_response>{FULL_AND_FAST_XML}</get_configs_response>'),
            create_scan_config=lambda *a, **kw: xml('<create_scan_config_response id="new-cfg"/>'),
            get_nvt_families=lambda: xml(FAMILIES_XML),
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
            get_scan_configs=lambda: xml(f'<get_configs_response>{EXISTING_CONFIG_XML}</get_configs_response>'),
            get_nvt_families=lambda: xml(FAMILIES_XML),
            modify_scan_config_set_family_selection=lambda *a, **kw: None,
            modify_scan_config_set_scanner_preference=lambda *a, **kw: None,
        )
        config_id = openvas.ensure_config(gmp, [])
        self.assertEqual(config_id, 'cfg-existing')
        self.assertNotIn('create_scan_config', gmp.names())
        self.assertIn('modify_scan_config_set_family_selection', gmp.names())

    def test_raises_when_full_and_fast_is_missing(self):
        gmp = FakeGMP(get_scan_configs=lambda: xml('<get_configs_response/>'))
        with self.assertRaises(openvas.OpenvasError):
            openvas.ensure_config(gmp, [])


class WaitForTaskTests(unittest.TestCase):
    def test_returns_the_status_once_done(self):
        done = xml('<get_tasks_response><task><status>Done</status></task></get_tasks_response>')
        gmp = FakeGMP(get_task=lambda *a: done)
        self.assertIs(openvas._wait_for_task(gmp, 'task-1', deadline=999999999), done)

    def test_loops_while_active_then_returns_on_done(self):
        running = xml('<get_tasks_response><task><status>Running</status></task></get_tasks_response>')
        done = xml('<get_tasks_response><task><status>Done</status></task></get_tasks_response>')
        calls = {'n': 0}

        def get_task(*a):
            calls['n'] += 1
            return running if calls['n'] < 3 else done
        gmp = FakeGMP(get_task=get_task)
        with mock.patch('client.openvas.time.sleep'):
            result = openvas._wait_for_task(gmp, 'task-1', deadline=999999999)
        self.assertEqual(calls['n'], 3)
        self.assertIs(result, done)

    def test_raises_on_an_unknown_terminal_status(self):
        stopped = xml('<get_tasks_response><task><status>Stopped</status></task></get_tasks_response>')
        gmp = FakeGMP(get_task=lambda *a: stopped)
        with self.assertRaises(openvas.OpenvasError):
            openvas._wait_for_task(gmp, 'task-1', deadline=999999999)

    def test_stops_the_task_and_raises_once_the_deadline_passes(self):
        running = xml('<get_tasks_response><task><status>Running</status></task></get_tasks_response>')
        gmp = FakeGMP(get_task=lambda *a: running, stop_task=lambda *a: None)
        with self.assertRaises(openvas.OutOfBudget) as raised:
            openvas._wait_for_task(gmp, 'task-1', deadline=0)  # already past
        self.assertIsInstance(raised.exception, openvas.OpenvasError)
        self.assertIn('stop_task', gmp.names())


class RunOpenvasTests(unittest.TestCase):
    def _happy_gmp(self):
        results_page = xml(f'<get_results_response><results>{RESULT_WITH_CVE}</results></get_results_response>')
        report_detail = xml('<get_report_response><report><host><ip>192.0.2.10</ip></host></report></get_report_response>')
        done_status = xml('<get_tasks_response><task><status>Done</status>'
                          '<last_report><report id="rep1"/></last_report></task></get_tasks_response>')
        return FakeGMP(
            get_scan_configs=lambda: xml(f'<get_configs_response>{EXISTING_CONFIG_XML}</get_configs_response>'),
            get_nvt_families=lambda: xml(FAMILIES_XML),
            modify_scan_config_set_family_selection=lambda *a, **kw: None,
            modify_scan_config_set_scanner_preference=lambda *a, **kw: None,
            get_scanners=lambda: xml(f'<get_scanners_response><scanner id="{openvas.OPENVAS_SCANNER[0]}">'
                                     f'<name>{openvas.OPENVAS_SCANNER[1]}</name></scanner></get_scanners_response>'),
            get_port_lists=lambda: xml(f'<get_port_lists_response><port_list id="{openvas.PORT_LIST[0]}">'
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

    def test_the_happy_path_returns_the_shape_the_server_expects(self):
        gmp = self._happy_gmp()
        with mock.patch('client.openvas.session', return_value=_ctx(gmp)):
            result = openvas.run_openvas({'192.0.2.10': 'www.example.test'}, excluded_families=['Denial of Service'], max_hours_=1)
        self.assertEqual(len(result['results']), 1)
        self.assertEqual(result['results'][0]['cves'], ['CVE-2024-12345'])
        self.assertEqual(result['scanned_addresses'], ['192.0.2.10'])
        self.assertEqual(result['without_cve'], 0)
        self.assertEqual(result['unusable'], 0)
        self.assertIn('delete_task', gmp.names())
        self.assertIn('delete_target', gmp.names())
        create_target_call = next(c for c in gmp.calls if c[0] == 'create_target')
        self.assertEqual(create_target_call[2]['hosts'], ['192.0.2.10'])

    def test_the_result_is_not_partial_when_the_task_finished(self):
        with mock.patch('client.openvas.session', return_value=_ctx(self._happy_gmp())):
            self.assertIs(openvas.run_openvas({'192.0.2.10': 'www.example.test'})['partial'], False)

    def _out_of_budget_gmp(self, results=True):
        gmp = self._happy_gmp()
        gmp.responses['get_task'] = lambda *a: xml('<get_tasks_response><task><status>Running</status></task></get_tasks_response>')
        gmp.responses['stop_task'] = lambda *a: None
        if not results:
            gmp.responses['get_results'] = lambda **kw: xml('<get_results_response><results></results></get_results_response>')
        return gmp

    def test_a_task_past_its_budget_is_stopped_and_what_it_found_is_returned_as_partial(self):
        gmp = self._out_of_budget_gmp()
        with mock.patch('client.openvas.session', return_value=_ctx(gmp)), mock.patch('client.openvas.time.monotonic', side_effect=[0, 10 ** 9, 10 ** 9]):
            result = openvas.run_openvas({'192.0.2.10': 'www.example.test'}, max_hours_=1)
        self.assertIs(result['partial'], True)
        self.assertEqual(result['results'][0]['cves'], ['CVE-2024-12345'])
        self.assertEqual(result['scanned_addresses'], ['192.0.2.10'])  # only a host that has a result counts as scanned
        self.assertIn('stop_task', gmp.names())
        self.assertIn('delete_task', gmp.names())  # still cleaned up

    def test_a_task_past_its_budget_with_nothing_found_is_a_failure(self):
        gmp = self._out_of_budget_gmp(results=False)
        with mock.patch('client.openvas.session', return_value=_ctx(gmp)), mock.patch('client.openvas.time.monotonic', side_effect=[0, 10 ** 9, 10 ** 9]):
            with self.assertRaises(openvas.OpenvasError) as raised:
                openvas.run_openvas({'192.0.2.10': 'www.example.test'}, max_hours_=1)
        self.assertIn('time budget', str(raised.exception))
        self.assertIn('delete_target', gmp.names())

    def test_the_servers_max_checks_is_used_within_bounds_and_one_host_at_a_time_always(self):
        self.assertEqual(openvas.task_preferences(None), {'max_checks': '4', 'max_hosts': '1'})
        self.assertEqual(openvas.task_preferences({'max_checks': 2, 'max_hosts': 9}), {'max_checks': '2', 'max_hosts': '1'})
        self.assertEqual(openvas.task_preferences({'max_checks': '99'})['max_checks'], '10')
        self.assertEqual(openvas.task_preferences({'max_checks': 0})['max_checks'], '1')
        self.assertEqual(openvas.task_preferences({'max_checks': 'many'})['max_checks'], '4')
        gmp = self._happy_gmp()
        with mock.patch('client.openvas.session', return_value=_ctx(gmp)):
            openvas.run_openvas({'192.0.2.10': 'www.example.test'}, preferences={'max_checks': 3})
        self.assertEqual(next(c for c in gmp.calls if c[0] == 'create_task')[2]['preferences'], {'max_checks': '3', 'max_hosts': '1'})

    def test_no_hosts_raises_without_opening_a_session(self):
        with mock.patch('client.openvas.session') as session_mock:
            with self.assertRaises(openvas.OpenvasError):
                openvas.run_openvas({})
        session_mock.assert_not_called()

    def test_cleans_up_the_target_and_task_even_when_fetching_results_fails(self):
        gmp = self._happy_gmp()
        gmp.responses['get_results'] = mock.Mock(side_effect=RuntimeError('gvmd hiccup'))
        with mock.patch('client.openvas.session', return_value=_ctx(gmp)):
            with self.assertRaises(RuntimeError):
                openvas.run_openvas({'192.0.2.10': 'www.example.test'})
        self.assertIn('delete_task', gmp.names())
        self.assertIn('delete_target', gmp.names())

    def test_register_is_accepted_but_never_called(self):
        gmp = self._happy_gmp()
        register = mock.Mock()
        with mock.patch('client.openvas.session', return_value=_ctx(gmp)):
            openvas.run_openvas({'192.0.2.10': 'www.example.test'}, register=register)
        register.assert_not_called()


class CredentialsTests(unittest.TestCase):
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


class BootstrapCredentialsTests(unittest.TestCase):
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


class BootstrapFallbackTests(unittest.TestCase):
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


class ReadinessTests(unittest.TestCase):
    CONFIGS = '<get_configs_response><config id="daba56c8-73ec-11df-a475-002264764cea"><name>Full and fast</name></config></get_configs_response>'
    SCANNERS = '<get_scanners_response><scanner id="08b69003-5fc2-4037-a479-93b440211c73"><name>OpenVAS Default</name></scanner></get_scanners_response>'
    PORTS = '<get_port_lists_response><port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"><name>All IANA assigned TCP</name></port_list></get_port_lists_response>'
    EMPTY = '<get_configs_response/>'
    SYNCING = '<get_feeds_response><feed><type>SCAP</type><currently_syncing><timestamp>2026</timestamp></currently_syncing></feed></get_feeds_response>'
    SYNCED = '<get_feeds_response><feed><type>SCAP</type><name>SCAP</name></feed><feed><type>CERT</type></feed></get_feeds_response>'

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        env = mock.patch.dict('os.environ', {'CVENGINE_OPENVAS_CREDENTIALS_FILE': os.path.join(self.dir.name, 'creds.json'),
                                             'CVENGINE_OPENVAS_SOCKET': os.path.join(self.dir.name, 'gvmd.sock')})
        env.start()
        self.addCleanup(env.stop)

    def socket(self):
        open(os.path.join(self.dir.name, 'gvmd.sock'), 'w').close()

    def check(self, configs=CONFIGS, scanners=SCANNERS, ports=PORTS, feeds=SYNCED):
        gmp = FakeGMP(get_scan_configs=xml(configs), get_scanners=xml(scanners), get_port_lists=xml(ports), get_feeds=xml(feeds))
        with mock.patch('client.openvas.session', return_value=_ctx(gmp)):
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
        with mock.patch('client.openvas.session', return_value=_ctx(gmp)):
            with self.assertRaises(openvas.OpenvasError) as raised:
                openvas.run_openvas({'192.0.2.10': 'x'})
        self.assertIn('still syncing its SCAP feed', str(raised.exception))
        self.assertEqual(gmp.names(), ['get_feeds'])


class SessionErrorTextTests(unittest.TestCase):
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


class SessionTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
