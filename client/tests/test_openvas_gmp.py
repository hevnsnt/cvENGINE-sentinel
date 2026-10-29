"""OpenVAS runs against a scripted gvmd socket, through the real python-gvm request builders: these tests assert on the XML python-gvm actually
sends, which a fake GMP object that accepts any arguments cannot (the rejected family tuples were such a bug)."""
import os
import tempfile
import unittest
from unittest import mock
from xml.etree import ElementTree as ET

from client import openvas

HOST = '52.151.200.60'
REPORT = (f'<get_reports_response status="200" status_text="OK"><report id="rep1"><report id="rep1">'
          f'<scan_run_status>Done</scan_run_status><hosts><count>1</count></hosts><host><ip>{HOST}</ip></host>'
          f'<result_count><full>0</full><high><full>0</full></high><log><full>0</full></log></result_count>'
          f'<scan_start>2026-10-28T10:00:00Z</scan_start><scan_end>2026-10-28T11:30:00Z</scan_end>'
          f'<errors><count>0</count></errors></report></report></get_reports_response>')
FAMILIES = ('Denial of Service', 'Brute force attacks', 'Web application abuses', 'General')


def config_answer(selected):
    families = ''.join(f'<family><name>{name}</name><nvt_count>{5 if name in selected else 0}</nvt_count><max_nvt_count>5</max_nvt_count>'
                       f'<growing>{1 if name in selected else 0}</growing></family>' for name in FAMILIES)
    return (f'<get_configs_response status="200" status_text="OK"><config id="cfg-1"><name>{openvas.CONFIG_NAME}</name>'
            f'<nvt_count>{5 * len(selected)}<growing>1</growing></nvt_count><families>{families}</families>'
            f'<preferences><preference><nvt oid=""><name/></nvt><name>safe_checks</name><value>yes</value></preference></preferences>'
            f'</config></get_configs_response>')


class ScriptedGvmd:
    """A gvmd on the far side of a GMP connection: records every command python-gvm sends and answers it from a script keyed by the command's
    tag (a string, or a callable taking the parsed command). Unscripted commands get a plain status 200 answer."""

    def __init__(self, **script):
        self.sent = []
        self.script = {
            'get_version': '<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>',
            'authenticate': '<authenticate_response status="200" status_text="OK"><role>Admin</role></authenticate_response>',
            'get_feeds': '<get_feeds_response status="200" status_text="OK"><feed><type>NVT</type></feed></get_feeds_response>',
            'get_nvt_families': ('<get_nvt_families_response status="200" status_text="OK"><families>'
                                 + ''.join(f'<family><name>{n}</name></family>' for n in FAMILIES) + '</families></get_nvt_families_response>'),
            'get_configs': self._configs,
            'get_scanners': (f'<get_scanners_response status="200" status_text="OK"><scanner id="{openvas.OPENVAS_SCANNER[0]}">'
                             f'<name>{openvas.OPENVAS_SCANNER[1]}</name></scanner></get_scanners_response>'),
            'get_port_lists': (f'<get_port_lists_response status="200" status_text="OK"><port_list id="{openvas.PORT_LIST[0]}">'
                               f'<name>{openvas.PORT_LIST[1]}</name></port_list></get_port_lists_response>'),
            'create_target': '<create_target_response status="201" status_text="OK, resource created" id="target-1"/>',
            'create_task': '<create_task_response status="201" status_text="OK, resource created" id="task-1"/>',
            'start_task': '<start_task_response status="202" status_text="OK, request submitted"><report_id>rep1</report_id></start_task_response>',
            'get_tasks': ('<get_tasks_response status="200" status_text="OK"><task id="task-1"><status>Done</status><progress>-1</progress>'
                          '<last_report><report id="rep1"/></last_report></task></get_tasks_response>'),
            'get_results': '<get_results_response status="200" status_text="OK"><results/></get_results_response>',
            'get_reports': REPORT,
        }
        self.script.update(script)
        self.modified = False

    def _configs(self, command):
        if command.get('config_id'):  # one config, read back
            return config_answer(('Web application abuses', 'General') if self.modified else FAMILIES)
        return (f'<get_configs_response status="200" status_text="OK"><config id="cfg-1"><name>{openvas.CONFIG_NAME}</name></config>'
                f'<config id="{openvas.FULL_AND_FAST[0]}"><name>{openvas.FULL_AND_FAST[1]}</name></config></get_configs_response>')

    def connection(self):
        return _Connection(self)

    def answer(self, data):
        command = ET.fromstring(data)
        self.sent.append(command)
        if command.tag == 'modify_config':
            self.modified = True
        reply = self.script.get(command.tag, f'<{command.tag}_response status="200" status_text="OK"/>')
        return (reply(command) if callable(reply) else reply).encode()

    def commands(self, tag):
        return [c for c in self.sent if c.tag == tag]


class _Connection:
    def __init__(self, gvmd):
        self.gvmd, self.pending = gvmd, []

    def connect(self):
        pass

    def disconnect(self):
        pass

    def finish_send(self):
        pass

    def send(self, data):
        self.pending.append(self.gvmd.answer(data))

    def read(self):
        return self.pending.pop(0)


class GmpTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        env = mock.patch.dict('os.environ', {'CVENGINE_OPENVAS_CREDENTIALS_FILE': os.path.join(self.dir.name, 'creds.json'),
                                             'CVENGINE_OPENVAS_SOCKET': os.path.join(self.dir.name, 'gvmd.sock')})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('CVENGINE_OPENVAS_KEEP_TASKS', None)
        own = mock.patch('client.scope.own_addresses', return_value=frozenset())
        own.start()
        self.addCleanup(own.stop)
        openvas.save_credentials('cvengine-sentinel', 'saved-password')
        open(openvas._ready_marker(), 'w').close()


class RunXmlTests(GmpTestCase):
    def run_scan(self, gvmd, **kwargs):
        return openvas.run_openvas({HOST: 'www.example.test'}, connection_factory=gvmd.connection, **kwargs)

    def test_the_target_considers_the_host_alive_and_names_exactly_one_plain_address(self):
        gvmd = ScriptedGvmd()
        self.run_scan(gvmd, excluded_families=[])
        target = gvmd.commands('create_target')[0]
        self.assertEqual(target.findtext('alive_tests'), 'Consider Alive')
        self.assertEqual(target.findtext('hosts'), HOST)
        self.assertTrue(target.findtext('name').startswith(openvas.NAME_PREFIX))

    def test_family_selection_xml_keeps_growing_all_vts_families_and_leaves_out_the_excluded_ones(self):
        gvmd = ScriptedGvmd()
        self.run_scan(gvmd, excluded_families=['web APPLICATION abuses'])  # matched without regard to case
        selection = gvmd.commands('modify_config')[0].find('family_selection')
        self.assertEqual(selection.findtext('growing'), '0')  # new families are not added on their own
        families = {f.findtext('name'): (f.findtext('all'), f.findtext('growing')) for f in selection.findall('family')}
        self.assertEqual(families, {'General': ('1', '1')})  # minus the local minimum and the server's own exclusion

    def test_the_report_is_read_with_details_and_every_host_listed(self):
        gvmd = ScriptedGvmd()
        self.run_scan(gvmd)
        report = gvmd.commands('get_reports')[0]
        self.assertEqual(report.get('report_id'), 'rep1')
        self.assertEqual(report.get('details'), '1')
        self.assertIn('result_hosts_only=0', report.get('filter'))
        self.assertIn('levels=chmlg', report.get('filter'))

    def test_list_calls_ask_for_every_row(self):
        gvmd = ScriptedGvmd()
        self.run_scan(gvmd)
        for tag in ('get_scanners', 'get_port_lists'):
            self.assertEqual(gvmd.commands(tag)[0].get('filter'), 'rows=-1', tag)
        lists = [c for c in gvmd.commands('get_configs') if not c.get('config_id')]
        self.assertEqual([c.get('filter') for c in lists], ['rows=-1'])  # and only once

    def test_an_empty_report_is_an_error_with_the_report_id_and_gvmds_own_errors(self):
        empty = ('<get_reports_response status="200" status_text="OK"><report id="rep1"><report id="rep1"><hosts><count>0</count></hosts>'
                 '<result_count><full>0</full></result_count><errors><count>1</count><error><host>' + HOST + '</host>'
                 '<description>Host unreachable</description></error></errors></report></report></get_reports_response>')
        gvmd = ScriptedGvmd(get_reports=empty)
        with self.assertRaises(openvas.OpenvasError) as raised:
            self.run_scan(gvmd)
        message = str(raised.exception)
        self.assertIn('scanned no host', message)
        self.assertIn('rep1', message)
        self.assertIn('Host unreachable', message)
        self.assertIn('0 host(s)', message)
        self.assertEqual(len(gvmd.commands('delete_task')), 1)
        self.assertEqual(gvmd.commands('delete_task')[0].get('ultimate'), '1')
        self.assertEqual(len(gvmd.commands('delete_target')), 1)

    def test_a_host_the_report_lists_counts_as_scanned_even_with_no_results(self):
        result = self.run_scan(ScriptedGvmd())
        self.assertEqual(result['scanned_addresses'], [HOST])
        self.assertEqual(result['results'], [])
        self.assertIs(result['partial'], False)


if __name__ == '__main__':
    unittest.main()
