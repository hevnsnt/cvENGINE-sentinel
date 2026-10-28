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
        with self.assertRaises(openvas.OpenvasError):
            openvas._wait_for_task(gmp, 'task-1', deadline=0)  # already past
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
