"""The pure Java runtime readers (cvengine_scanner.java): version and vendor normalisation, JDWP reply bytes, the status pages' JSON, headers
and JVM banners. Every reader is fed what a host could send, good and bad."""
import json
import struct
import unittest

from cvengine_scanner import java


def jdwp_string(text):
    raw = text.encode('utf-8')
    return struct.pack('>I', len(raw)) + raw


def version_reply(description, vm_version, vm_name, packet_id=1, flags=0x80, error=0, major=17, minor=0):
    body = jdwp_string(description) + struct.pack('>ii', major, minor) + jdwp_string(vm_version) + jdwp_string(vm_name)
    return struct.pack('>IIBH', 11 + len(body), packet_id, flags, error) + body


DESCRIPTION = ('Java Debug Wire Protocol (Reference Implementation) version 17.0\nJVM Debug Interface version 17.0\n'
               'JVM version 17.0.9 (OpenJDK 64-Bit Server VM, mixed mode, sharing)')


class VersionTests(unittest.TestCase):
    def test_versions_normalise_to_one_spelling(self):
        cases = {
            '1.8.0_392': ('8u392', 8, False), '1.8.0_392-b08': ('8u392', 8, False), '8u392': ('8u392', 8, False), '8u392-b08': ('8u392', 8, False),
            '1.7.0_80': ('7u80', 7, False), '17.0.9+9': ('17.0.9', 17, False), '17.0.9': ('17.0.9', 17, False),
            '21.0.2+13-LTS': ('21.0.2', 21, False), '11.0.20.1+1': ('11.0.20.1', 11, False), '17.0.9.0': ('17.0.9', 17, False),
            '17.0.9+9-Ubuntu-0ubuntu122.04': ('17.0.9', 17, False), '21+35': ('21.0.0', 21, False), '17': ('17', 17, True), '1.8': ('8', 8, True),
            '1.8.0': ('8', 8, True), '17.0': ('17.0.0', 17, False), 'openjdk version 21.0.1': ('21.0.1', 21, False),
        }
        for raw, (version, major, line_only) in cases.items():
            with self.subTest(raw=raw):
                got = java.normalize_version(raw)
                self.assertEqual((got['version'], got['major'], got['line_only']), (version, major, line_only))
        self.assertEqual(java.normalize_version('21.0.2+13-LTS')['build'], '13-LTS')
        self.assertEqual(java.normalize_version('17.0.9+9-Ubuntu-0ubuntu122.04')['build'], '9-Ubuntu-0ubuntu122.04')

    def test_what_is_not_a_java_version_is_none(self):
        for raw in ('', 'abc', '2.4.57', '8.0.1', '5', '150.1', None, 17, '*****'):
            with self.subTest(raw=raw):
                self.assertIsNone(java.normalize_version(raw))

    def test_dotted_puts_java_8_updates_and_bounds_in_one_order(self):
        self.assertEqual(java.dotted('8u392'), '8.0.392')
        self.assertEqual(java.dotted('1.8.0_391'), '8.0.391')
        self.assertEqual(java.dotted('Oracle Java SE:8u381'), '8.0.381')
        self.assertEqual(java.dotted('17.0.9+9'), '17.0.9')
        self.assertEqual(java.dotted('0'), '0')
        self.assertEqual(java.dotted('*'), '*')

    def test_vendor_strings(self):
        cases = {('Eclipse Adoptium',): 'Eclipse Temurin', ('Temurin-17.0.9+9',): 'Eclipse Temurin', ('AdoptOpenJDK',): 'Eclipse Temurin',
                 ('Azul Systems, Inc.',): 'Azul', ('Zulu17.46+19-CA',): 'Azul', ('Amazon.com Inc.',): 'Amazon Corretto',
                 ('Corretto-17.0.9.8.1',): 'Amazon Corretto', ('Red Hat, Inc.',): 'Red Hat', ('Microsoft',): 'Microsoft',
                 ('IBM Corporation',): 'IBM Semeru', ('International Business Machines Corporation',): 'IBM Semeru', ('Oracle Corporation',): 'Oracle',
                 ('Java HotSpot(TM) 64-Bit Server VM',): 'Oracle', ('BellSoft',): 'BellSoft Liberica', ('Private Build',): 'Ubuntu',
                 ('Debian',): 'Debian', ('', None): 'unknown', ('Acme',): 'unknown'}
        for texts, vendor in cases.items():
            with self.subTest(texts=texts):
                self.assertEqual(java.normalize_vendor(*texts), vendor)

    def test_a_distribution_build_suffix_names_the_vendor(self):
        got = java.reading('17.0.9+9-Ubuntu-0ubuntu122.04', 'actuator', ('Oracle Corporation',))
        self.assertEqual(got['vendor'], 'Ubuntu')
        self.assertEqual(java.reading('17.0.9+9-LTS', 'actuator', ('Red Hat, Inc.',))['vendor'], 'Red Hat')


class JdwpTests(unittest.TestCase):
    def test_the_command_is_virtual_machine_version_and_nothing_else(self):
        self.assertEqual(java.HANDSHAKE, b'JDWP-Handshake')
        self.assertEqual(len(java.HANDSHAKE), 14)
        packet = java.version_command(1)
        self.assertEqual(packet, b'\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x01')  # length 11, id 1, flags 0, command set 1, command 1
        # the same bytes nmap's jdwp-version sends after the handshake
        self.assertEqual(java.HANDSHAKE + packet, b'JDWP-Handshake\0\0\0\x0b\0\0\0\x01\0\x01\x01')

    def test_a_version_reply_is_read(self):
        got = java.parse_version_reply(version_reply(DESCRIPTION, '17.0.9', 'OpenJDK 64-Bit Server VM'))
        self.assertEqual((got['vm_version'], got['vm_name'], got['jdwp_major']), ('17.0.9', 'OpenJDK 64-Bit Server VM', 17))
        reading = java.from_jdwp(got, port=5005)
        self.assertEqual((reading['version'], reading['major'], reading['source'], reading['confidence'], reading['port']),
                         ('17.0.9', 17, 'jdwp', 'exact', 5005))
        old = java.from_jdwp(java.parse_version_reply(version_reply('JVM version 1.8.0_392 (Java HotSpot(TM) 64-Bit Server VM)', '1.8.0_392',
                                                                    'Java HotSpot(TM) 64-Bit Server VM')))
        self.assertEqual((old['version'], old['vendor']), ('8u392', 'Oracle'))

    def test_anything_else_is_not_a_reply(self):
        good = version_reply(DESCRIPTION, '17.0.9', 'OpenJDK 64-Bit Server VM')
        for bad in (b'', b'JDWP-Handshake', good[:20], version_reply(DESCRIPTION, '17.0.9', 'x', flags=0),
                    version_reply(DESCRIPTION, '17.0.9', 'x', error=100), version_reply(DESCRIPTION, '17.0.9', 'x', packet_id=2),
                    struct.pack('>IIBH', 11 + 4, 1, 0x80, 0) + struct.pack('>I', 9999), 'text'):
            with self.subTest(bad=bad[:16]):
                self.assertIsNone(java.parse_version_reply(bad))

    def test_the_handshake_echo(self):
        self.assertTrue(java.is_handshake(b'JDWP-Handshake'))
        self.assertFalse(java.is_handshake(b'HTTP/1.1 400 Bad'))
        self.assertFalse(java.is_handshake(b''))

    def test_a_port_nmap_identified(self):
        got = java.from_nmap_port('jdwp', 'Java Debug Wire Protocol (Reference Implementation) version 17.0', '17.0.9', port=5005)
        self.assertEqual((got['version'], got['source'], got['port']), ('17.0.9', 'jdwp', 5005))
        self.assertIsNone(java.from_nmap_port('http', 'nginx', '1.24.0'))


class ActuatorTests(unittest.TestCase):
    def test_one_property(self):
        body = json.dumps({'property': {'source': 'systemProperties', 'value': '17.0.9'}, 'activeProfiles': [],
                           'propertySources': [{'name': 'systemProperties', 'property': {'value': '17.0.9'}}]})
        got = java.from_actuator_env(body, '/actuator/env/java.version')
        self.assertEqual((got['version'], got['source'], got['confidence']), ('17.0.9', 'actuator', 'exact'))

    def test_the_whole_environment_reads_only_the_java_keys(self):
        body = json.dumps({'activeProfiles': ['prod'], 'propertySources': [
            {'name': 'server.ports', 'properties': {'local.server.port': {'value': 8080}}},
            {'name': 'systemProperties', 'properties': {'java.version': {'value': '21.0.2'}, 'java.vendor': {'value': 'Eclipse Adoptium'},
                                                        'java.runtime.version': {'value': '21.0.2+13-LTS'}, 'db.password': {'value': 'hunter2'}}},
            {'name': 'systemEnvironment', 'properties': {'AWS_SECRET_ACCESS_KEY': {'value': 'abc'}}}]})
        got = java.from_actuator_env(body)
        self.assertEqual((got['version'], got['vendor'], got['build']), ('21.0.2', 'Eclipse Temurin', '13-LTS'))
        self.assertNotIn('hunter2', json.dumps(got))
        self.assertNotIn('abc', got['evidence'])

    def test_boot_one(self):
        got = java.from_actuator_env(json.dumps({'profiles': [], 'systemProperties': {'java.version': '1.8.0_392', 'java.vendor': 'Oracle Corporation',
                                                                                     'secret': 'x'}}), '/env')
        self.assertEqual((got['version'], got['vendor']), ('8u392', 'Oracle'))
        one = java.from_actuator_env(json.dumps({'java.version': '1.8.0_151'}), '/env/java.version')
        self.assertEqual(one['version'], '8u151')

    def test_a_masked_value_or_another_page_is_nothing(self):
        self.assertIsNone(java.from_actuator_env(json.dumps({'propertySources': [{'name': 's', 'properties': {'java.version': {'value': '******'}}}]})))
        self.assertIsNone(java.from_actuator_env('<html>login</html>'))
        self.assertIsNone(java.from_actuator_env('[]'))
        self.assertIsNone(java.from_actuator_env('{"status":"UP"}'))

    def test_info(self):
        body = json.dumps({'app': {'name': 'x'}, 'java': {'version': '17.0.9', 'vendor': {'name': 'Eclipse Adoptium', 'version': 'Temurin-17.0.9+9'},
                                                          'runtime': {'name': 'OpenJDK Runtime Environment', 'version': '17.0.9+9'},
                                                          'jvm': {'name': 'OpenJDK 64-Bit Server VM', 'vendor': 'Eclipse Adoptium', 'version': '17.0.9+9'}}})
        got = java.from_actuator_info(body)
        self.assertEqual((got['version'], got['vendor'], got['runtime']), ('17.0.9', 'Eclipse Temurin', 'OpenJDK Runtime Environment'))
        self.assertIsNone(java.from_actuator_info(json.dumps({'app': {'name': 'x'}})))

    def test_metric(self):
        body = json.dumps({'name': 'jvm.info', 'measurements': [{'statistic': 'VALUE', 'value': 1.0}],
                           'availableTags': [{'tag': 'vendor', 'values': ['Amazon.com Inc.']}, {'tag': 'runtime', 'values': ['OpenJDK Runtime Environment']},
                                             {'tag': 'version', 'values': ['17.0.9+8-LTS']}]})
        got = java.from_actuator_metric(body)
        self.assertEqual((got['version'], got['vendor']), ('17.0.9', 'Amazon Corretto'))
        self.assertIsNone(java.from_actuator_metric(json.dumps({'name': 'jvm.memory.used'})))


class JolokiaTests(unittest.TestCase):
    def test_version_and_reads(self):
        self.assertTrue(java.is_jolokia(json.dumps({'request': {'type': 'version'}, 'value': {'agent': '1.7.2', 'protocol': '7.2'}, 'status': 200})))
        self.assertFalse(java.is_jolokia('<html>'))
        self.assertFalse(java.is_jolokia(json.dumps({'value': 'x'})))
        got = java.from_jolokia(json.dumps({'value': '21.0.1+12-LTS', 'status': 200}), json.dumps({'value': 'Azul Systems, Inc.', 'status': 200}))
        self.assertEqual((got['version'], got['vendor'], got['source']), ('21.0.1', 'Azul', 'jolokia'))

    def test_a_java_8_hotspot_vm_version(self):
        got = java.from_jolokia(json.dumps({'value': '25.392-b08', 'status': 200}), json.dumps({'value': 'Oracle Corporation', 'status': 200}))
        self.assertEqual((got['version'], got['major']), ('8u392', 8))

    def test_an_error_is_nothing(self):
        self.assertIsNone(java.from_jolokia(json.dumps({'error': 'forbidden', 'status': 403})))


class StatusPageTests(unittest.TestCase):
    def test_solr(self):
        body = json.dumps({'responseHeader': {'status': 0}, 'mode': 'std', 'lucene': {'solr-spec-version': '9.4.0'},
                           'jvm': {'version': '17.0.9 17.0.9+9', 'name': 'Eclipse Adoptium OpenJDK 64-Bit Server VM',
                                   'spec': {'vendor': 'Oracle Corporation', 'version': '17'}, 'jre': {'vendor': 'Eclipse Adoptium', 'version': '17.0.9'},
                                   'vm': {'vendor': 'Eclipse Adoptium', 'name': 'OpenJDK 64-Bit Server VM', 'version': '17.0.9+9'}}})
        got = java.from_solr(body)
        self.assertEqual((got['version'], got['vendor'], got['source']), ('17.0.9', 'Eclipse Temurin', 'status_page'))

    def test_geoserver(self):
        body = json.dumps({'statuss': {'status': [
            {'module': 'gs-main', 'name': 'GeoServer Main', 'version': '2.24.1', 'message': 'not read'},
            {'module': 'jvm', 'name': 'Rendering Engine', 'component': 'Java2d', 'version': '11.0.21'},
            {'module': 'system-properties', 'name': 'System Properties', 'component': 'OpenJDK Runtime Environment', 'version': '11.0.21+9'}]}})
        got = java.from_geoserver(body)
        self.assertEqual((got['version'], got['major']), ('11.0.21', 11))
        self.assertIsNone(java.from_geoserver(json.dumps({'statuss': {'status': [{'module': 'gs-main', 'version': '2.24.1'}]}})))

    def test_druid(self):
        body = json.dumps({'druid.zk.service.host': 'zk', 'druid.metadata.storage.connector.password': 'secret', 'java.version': '17.0.8',
                           'java.vendor': 'Amazon.com Inc.', 'java.runtime.version': '17.0.8+7-LTS'})
        got = java.from_druid(body)
        self.assertEqual((got['version'], got['vendor']), ('17.0.8', 'Amazon Corretto'))
        self.assertNotIn('secret', json.dumps(got))
        self.assertIsNone(java.from_druid(json.dumps({'version': '28.0.0', 'modules': []})))

    def test_elasticsearch_and_opensearch(self):
        body = json.dumps({'_nodes': {'total': 2}, 'cluster_name': 'c', 'nodes': {
            'a': {'jvm': {'version': '21.0.1', 'vm_name': 'OpenJDK 64-Bit Server VM', 'vm_vendor': 'Oracle Corporation', 'vm_version': '21.0.1+12-29',
                          'using_bundled_jdk': True}},
            'b': {'jvm': {'version': '21.0.1', 'vm_name': 'OpenJDK 64-Bit Server VM', 'vm_vendor': 'Oracle Corporation', 'vm_version': '21.0.1+12-29'}},
            'c': {'jvm': {'version': '17.0.9', 'vm_name': 'OpenJDK 64-Bit Server VM', 'vm_vendor': 'Eclipse Adoptium', 'vm_version': '17.0.9+9'}}}})
        got = java.from_elasticsearch(body)
        self.assertEqual([(r['version'], r['vendor']) for r in got], [('21.0.1', 'Oracle'), ('17.0.9', 'Eclipse Temurin')])
        self.assertIn('using_bundled_jdk=True', got[0]['evidence'])
        self.assertEqual(java.from_elasticsearch('{"error":"security_exception"}'), [])


class HeaderAndBannerTests(unittest.TestCase):
    def test_x_powered_by_variants(self):
        cases = {
            'Servlet/4.0 JSP/2.3 (Payara Server 5.2022.5 #badassfish Java/Azul Systems, Inc./17)': ('17', 'Azul', True),
            'Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition 4.1 Java/Oracle Corporation/1.8)': ('8', 'Oracle', True),
            'Servlet/4.0 JSP/2.3 (Payara Server 5.201 #badassfish Java/Oracle Corporation/1.8.0_252)': ('8u252', 'Oracle', False),
            'Java/1.8.0_181': ('8u181', 'unknown', False),
        }
        for value, (version, vendor, line_only) in cases.items():
            with self.subTest(value=value):
                got = java.from_headers({'X-Powered-By': value})
                self.assertEqual((got[0]['version'], got[0]['vendor'], got[0]['line_only'], got[0]['source']), (version, vendor, line_only, 'header'))
        for value in ('PHP/8.2.1', 'Servlet/3.0; JBossAS-6', 'Express', 'JSF/2.0', 'ASP.NET'):
            with self.subTest(value=value):
                self.assertEqual(java.from_headers({'X-Powered-By': value}), [])
        self.assertEqual(java.from_headers({'Server': 'Apache-Coyote/1.1'}), [])

    def test_jvm_banners_in_a_page(self):
        cases = {
            'at java.base/... Java HotSpot(TM) 64-Bit Server VM (17.0.9+11-LTS-201, mixed mode, sharing)': ('17.0.9', 'Oracle'),
            'OpenJDK Runtime Environment (build 17.0.9+9-Ubuntu-0ubuntu122.04)': ('17.0.9', 'Ubuntu'),
            'OpenJDK Runtime Environment Temurin-21.0.2+13 (build 21.0.2+13-LTS)': ('21.0.2', 'Eclipse Temurin'),
            'OpenJDK 64-Bit Server VM (build 11.0.21+9, mixed mode)': ('11.0.21', 'OpenJDK'),
            '<tr><td>java.version</td></tr> java.version=1.8.0_392': ('8u392', 'unknown'),
            '{"java.version": "21.0.1"}': ('21.0.1', 'unknown'),
        }
        for body, (version, vendor) in cases.items():
            with self.subTest(body=body[:40]):
                got = java.from_body(body)
                self.assertEqual((got[0]['version'], got[0]['vendor'], got[0]['source']), (version, vendor, 'error_page'))
        self.assertEqual(java.from_body('<h1>Apache Tomcat/9.0.83</h1> Java 17 is great'), [])

    def test_evidence_is_clipped_untrusted_text(self):
        got = java.from_headers({'X-Powered-By': 'Java/17.0.9 ' + '\x00\x1b[31m' + 'x' * 600})
        self.assertLessEqual(len(got[0]['evidence']), java.EVIDENCE_LEN)
        self.assertNotIn('\x1b', got[0]['evidence'])


if __name__ == '__main__':
    unittest.main()
