"""The service-feature reads of web services and SLP (``probes.service_reads``), and how the http_probe and hygiene_check batches carry them."""
import socket
from unittest import TestCase, mock

from cvengine_scanner import features
from cvengine_scanner.probes import hygiene, http, service_reads as sr, transport, version_probes as probes
from cvengine_scanner.probes.policy import ScopePolicy

POLICY = ScopePolicy({'domains': ['rt.test']}, internal=False)


def answer(status=200, headers=None, body='', title='', content_type='text/html', url='https://vpn.rt.test/'):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return {'status': status, 'headers': headers, 'raw_headers': headers, 'body': body, 'title': title, 'content_type': content_type,
            'server': headers.get('server', ''), 'powered_by': headers.get('x-powered-by', ''), 'final_url': url, 'url': url, 'location': '',
            'challenge': '', 'bytes': len(body)}


def values(items):
    return {(i['feature'], i['value']) for i in items}


# --- fixtures: what the appliances answer (shortened from real pages)
FORTINET_LOGIN = ('<html><head><title></title><script src="/sslvpn/js/login.js"></script></head><body><form action="/remote/logincheck" '
                  'method="post" name="f"><input name="username"><input type="password" name="credential"></form>'
                  '<a onclick="launchFortiClient()">FortiClient</a></body></html>')
GLOBALPROTECT_LOGIN = ('<html><head><title>GlobalProtect Portal</title><link rel="stylesheet" href="/global-protect/portal/css/login.css">'
                       '</head><body><form method="post" action="/global-protect/login.esp"></form></body></html>')
GLOBALPROTECT_PRELOGIN = ('<?xml version="1.0" encoding="UTF-8" ?><prelogin-response><status>Success</status><ccusername></ccusername>'
                          '<autosubmit>false</autosubmit><msg></msg><authentication-message>Enter login credentials</authentication-message>'
                          '<username-label>Username</username-label></prelogin-response>')
CISCO_LOGON = ('<html><head><title>SSL VPN Service</title><script src="/+CSCOU+/common.js"></script></head><body>'
               '<form action="/+webvpn+/index.html" method="post" name="webvpnlogin"></form></body></html>')
CITRIX_GATEWAY = ('<html><head><title>NetScaler Gateway</title><link href="/vpn/js/rdx/core/css/rdx.css?v=0123" rel="stylesheet">'
                  '</head><body></body></html>')
CITRIX_AAA = '<html><head><title>NetScaler AAA</title><script src="/logon/LogonPoint/init.js"></script></head><body></body></html>'
IVANTI_WELCOME = ('<html><head><title>Ivanti Connect Secure</title></head><body><form name="frmLogin" action="login.cgi" method="POST">'
                  '<input type="hidden" name="realm"></form><img src="/dana-na/imgs/space.gif"></body></html>')
SPA_SHELL = '<html><head><title>Acme</title></head><body><div id="app"></div><script src="/static/app.js"></script></body></html>'


class FrontPageTests(TestCase):
    def test_alt_svc_names_http3(self):
        self.assertEqual(sr.alt_svc_h3('h3=":443"; ma=86400, h3-29=":443"; ma=86400'), (True, [443]))
        self.assertEqual(sr.alt_svc_h3('h3-29=":8443"'), (True, [8443]))
        self.assertEqual(sr.alt_svc_h3('h2=":443"; ma=60'), (False, []))
        self.assertEqual(sr.alt_svc_h3('clear'), (False, []))
        self.assertEqual(sr.alt_svc_h3(''), (False, []))

    def test_an_https_answer_reads_http3_either_way(self):
        got = sr.page_readings('www.rt.test', 443, 'https', answer(headers={'Alt-Svc': 'h3=":443"; ma=86400', 'Server': 'nginx'}))
        self.assertEqual(values(got), {('http3', 'yes')})
        self.assertIn('udp 443', got[0]['detail'])
        got = sr.page_readings('www.rt.test', 443, 'https', answer(headers={'Server': 'nginx'}))
        self.assertEqual(values(got), {('http3', 'no')})
        self.assertIn('not advertised is not read', got[0]['detail'])

    def test_an_edge_answer_says_so_in_the_detail(self):
        got = sr.page_readings('www.rt.test', 443, 'https', answer(headers={'Alt-Svc': 'h3=":443"', 'Server': 'cloudflare', 'CF-RAY': 'x'}))
        self.assertIn('Cloudflare', got[0]['detail'])

    def test_cleartext_http_and_challenges_read_nothing(self):
        self.assertEqual(sr.page_readings('www.rt.test', 80, 'http', answer(headers={'Alt-Svc': 'h3=":443"'})), [])
        self.assertEqual(sr.page_readings('www.rt.test', 443, 'https', {**answer(503), 'challenge': 'Cloudflare'}), [])
        self.assertEqual(sr.page_readings('www.rt.test', 443, 'https', None), [])

    def test_php_on_iis_is_php_on_windows(self):
        got = sr.php_windows_reading('www.rt.test', 443, 'Microsoft-IIS/10.0', 'PHP/8.1.10, ASP.NET')
        self.assertEqual((got['value'], got['feature']), ('yes', 'php_windows'))
        self.assertIn('CGI mode and the code page are not read remotely', got['detail'])

    def test_a_xampp_banner_is_windows_and_says_so(self):
        got = sr.php_windows_reading('www.rt.test', 80, 'Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12', '')
        self.assertEqual(got['value'], 'yes')
        self.assertIn('XAMPP', got['detail'])

    def test_a_distribution_is_not_windows(self):
        self.assertEqual(sr.php_windows_reading('h.rt.test', 80, 'Apache/2.4.41 (Ubuntu)', 'PHP/7.4.3')['value'], 'no')
        self.assertEqual(sr.php_windows_reading('h.rt.test', 80, 'nginx', 'PHP/8.2.7-1~deb12u1')['value'], 'no')
        self.assertEqual(sr.php_windows_reading('h.rt.test', 80, 'Apache/2.4.6 (CentOS) PHP/5.4.16', '')['value'], 'no')

    def test_no_php_or_no_operating_system_reads_nothing(self):
        self.assertIsNone(sr.php_windows_reading('h.rt.test', 80, 'Microsoft-IIS/10.0', 'ASP.NET'))
        self.assertIsNone(sr.php_windows_reading('h.rt.test', 80, 'nginx', 'PHP/8.3.1'))
        self.assertIsNone(sr.php_windows_reading('h.rt.test', 80, 'Apache/2.4.58 (Win64) (Unix)', 'PHP/8.3.1'))  # both named: unknown


IIS6_DAV = {'Server': 'Microsoft-IIS/6.0', 'MS-Author-Via': 'DAV', 'DAV': '1, 2', 'DASL': '<DAV:sql>',
            'Public': 'OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH',
            'Allow': 'OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK'}


class OptionsTests(TestCase):
    def test_a_dav_header_is_webdav(self):
        got = sr.methods_readings('h.rt.test', 80, answer(200, headers=IIS6_DAV))
        self.assertEqual(values(got), {('webdav', 'yes'), ('http_methods', 'put,delete,trace,propfind')})

    def test_apache_mod_dav_class_header(self):
        got = sr.methods_readings('h.rt.test', 80, answer(200, headers={'DAV': '1,2, <http://apache.org/dav/propset/fs/1>',
                                                                       'Allow': 'OPTIONS,GET,HEAD,POST,DELETE,TRACE,PROPFIND,PROPPATCH,COPY,MOVE,LOCK,UNLOCK'}))
        self.assertIn(('webdav', 'yes'), values(got))

    def test_an_ordinary_allow_list_is_no_webdav(self):
        got = sr.methods_readings('h.rt.test', 443, answer(200, headers={'Allow': 'GET, HEAD, POST, OPTIONS'}))
        self.assertEqual(values(got), {('webdav', 'no'), ('http_methods', 'none')})
        self.assertIn('below / is not read', next(i for i in got if i['feature'] == 'webdav')['detail'])

    def test_trace_and_put_are_listed(self):
        got = sr.methods_readings('h.rt.test', 443, answer(204, headers={'Allow': 'GET, HEAD, PUT, TRACE, OPTIONS'}))
        self.assertIn(('http_methods', 'put,trace'), values(got))

    def test_a_refused_options_is_no_webdav(self):
        self.assertEqual(values(sr.methods_readings('h.rt.test', 443, answer(405))), {('webdav', 'no')})
        self.assertEqual(values(sr.methods_readings('h.rt.test', 443, answer(501))), {('webdav', 'no')})

    def test_dav_methods_without_a_dav_header_are_not_believed(self):
        got = sr.methods_readings('h.rt.test', 443, answer(200, headers={'Allow': 'GET, PROPFIND, MKCOL, OPTIONS'}))
        self.assertEqual(values(got), {('http_methods', 'propfind')})

    def test_a_server_that_answers_every_method_with_its_page_is_not_read(self):
        page = answer(200, body=SPA_SHELL, title='Acme', headers={'Allow': 'GET, PUT, DELETE, PROPFIND', 'DAV': '1'})
        self.assertEqual(sr.methods_readings('h.rt.test', 443, dict(page), page), [])

    def test_an_echo_of_every_method_lists_nothing(self):
        got = sr.methods_readings('h.rt.test', 443, answer(200, headers={'Allow': ', '.join(f'M{i}X' for i in range(60))}))
        self.assertEqual(values(got), set())

    def test_challenges_and_other_statuses_read_nothing(self):
        self.assertEqual(sr.methods_readings('h.rt.test', 443, {**answer(403), 'challenge': 'Cloudflare'}), [])
        self.assertEqual(sr.methods_readings('h.rt.test', 443, answer(401)), [])
        self.assertEqual(sr.methods_readings('h.rt.test', 443, None), [])


def portal_get(table, catch_all=None):
    """A ``get(url)`` that answers by path from ``table`` (control paths included: ``catch_all`` when given, else 404)."""
    asked = []

    def get(url):
        path = '/' + url.split('://', 1)[1].split('/', 1)[1]
        asked.append(path)
        if path in table:
            return table[path]
        return catch_all if catch_all is not None else answer(404, body='<h1>Not Found</h1>')
    get.asked = asked
    return get


class PortalTests(TestCase):
    def read(self, feature, table, catch_all=None):
        get = portal_get(table, catch_all)
        states = sr.read_portal(feature, 'https://vpn.rt.test', get, sleep=lambda s: None)
        return sr.portal_reading('vpn.rt.test', 443, feature, states), get.asked

    def test_each_vendor_portal_is_read_present(self):
        cases = {'vpn_fortinet': {'/remote/login': answer(body=FORTINET_LOGIN)},
                 'vpn_globalprotect': {'/global-protect/login.esp': answer(body=GLOBALPROTECT_LOGIN, title='GlobalProtect Portal')},
                 'vpn_cisco': {'/+CSCOE+/logon.html': answer(body=CISCO_LOGON, title='SSL VPN Service')},
                 'vpn_citrix': {'/vpn/index.html': answer(body=CITRIX_GATEWAY, title='NetScaler Gateway')},
                 'vpn_ivanti': {'/dana-na/auth/url_default/welcome.cgi': answer(body=IVANTI_WELCOME, title='Ivanti Connect Secure')}}
        for feature, table in cases.items():
            with self.subTest(feature):
                item, asked = self.read(feature, table)
                self.assertEqual(item['value'], 'yes')
                self.assertEqual(len(asked), 2)  # the page and one path that cannot exist beside it, nothing else
                self.assertTrue(asked[1].split('/')[-1].startswith('cvengine-'))

    def test_a_globalprotect_gateway_without_a_portal(self):
        item, asked = self.read('vpn_globalprotect', {'/ssl-vpn/prelogin.esp': answer(body=GLOBALPROTECT_PRELOGIN, content_type='application/xml')})
        self.assertEqual(item['value'], 'yes')
        self.assertIn('gateway', item['detail'])
        self.assertNotIn('/ssl-vpn/hipreport.esp', asked)  # the CVE-2024-3400 path is never asked

    def test_a_netscaler_aaa_server(self):
        item, _asked = self.read('vpn_citrix', {'/logon/LogonPoint/index.html': answer(body=CITRIX_AAA, title='NetScaler AAA')})
        self.assertEqual(item['value'], 'yes')
        self.assertIn('AAA', item['detail'])

    def test_not_found_everywhere_is_no(self):
        item, asked = self.read('vpn_citrix', {})
        self.assertEqual(item['value'], 'no')
        self.assertEqual(asked, ['/vpn/index.html', '/logon/LogonPoint/index.html'])  # a 404 needs no control

    def test_a_catch_all_login_page_is_not_present(self):
        login = answer(body=FORTINET_LOGIN)
        item, _asked = self.read('vpn_fortinet', {'/remote/login': login}, catch_all=dict(login))
        self.assertIsNone(item)

    def test_a_page_served_for_any_path_is_not_the_portal(self):
        shell = answer(body=SPA_SHELL, title='Acme')
        item, _asked = self.read('vpn_fortinet', {}, catch_all=shell)
        self.assertEqual(item['value'], 'no')  # /remote/login is the site's catch-all page: not served on its own

    def test_a_marker_that_extends_the_path_is_kept(self):
        item, _asked = self.read('vpn_fortinet', {'/remote/login': answer(body='<form action="/remote/logincheck" method="post"></form>')})
        self.assertEqual(item['value'], 'yes')

    def test_a_not_found_page_naming_the_path_is_not_the_portal(self):
        page = answer(200, body='<p>The page /logon/LogonPoint/index.html was not found on this server.</p>')
        item, _asked = self.read('vpn_citrix', {'/vpn/index.html': answer(404), '/logon/LogonPoint/index.html': page})
        self.assertIsNone(item)

    def test_an_edge_challenge_is_unknown(self):
        item, _asked = self.read('vpn_cisco', {'/+CSCOE+/logon.html': {**answer(403), 'challenge': 'Cloudflare'}})
        self.assertIsNone(item)


class BatchTests(TestCase):
    """The http_probe kind carries the readings in ``service_features``; extra requests only where an entry names them."""

    def run_batch(self, entries, table, options=None):
        calls = []

        def fake(url, _policy=None, method='GET', **kwargs):
            path = '/' + url.split('://', 1)[1].split('/', 1)[1]
            calls.append((method, path))
            if method == 'OPTIONS':
                return options or answer(200, headers={'Allow': 'GET, HEAD, OPTIONS'}, url=url)
            return {**table.get(path, answer(404, url=url)), 'url': url}
        target = {'probes': entries, 'scope': {'hosts': ['vpn.rt.test'], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False,
                                               'addresses': [], 'blocked': []}}
        with mock.patch.object(probes, 'REQUEST_GAP', 0):
            return probes.run_batch(target, probe=fake, sleep=lambda s: None), calls

    def entry(self, probe='headers-root', **extra):
        return {'id': f'vpn.rt.test|{probe}|https://vpn.rt.test', 'host': 'vpn.rt.test', 'probe': probe, 'base': 'https://vpn.rt.test',
                'allowed': ['vpn.rt.test'], **extra}

    def test_headers_root_reads_http3_and_php_without_a_request_of_its_own(self):
        front = answer(headers={'Alt-Svc': 'h3=":443"', 'Server': 'Microsoft-IIS/10.0', 'X-Powered-By': 'PHP/8.1.10'}, body='<html></html>')
        got, calls = self.run_batch([self.entry()], {'/': front})
        self.assertEqual(values(got['service_features']), {('http3', 'yes'), ('php_windows', 'yes')})
        self.assertEqual(calls, [('GET', '/')])
        self.assertEqual(features.clean_features(got['service_features']), got['service_features'])

    def test_the_reads_an_entry_names_run_once_per_base(self):
        front = answer(body='<html></html>')
        entries = [self.entry(features=['webdav', 'vpn_fortinet', 'not-a-read']), self.entry('robots-txt', features=['webdav'])]
        got, calls = self.run_batch(entries, {'/': front, '/remote/login': answer(body=FORTINET_LOGIN)})
        self.assertEqual([c for c in calls if c[0] == 'OPTIONS'], [('OPTIONS', '/')])
        self.assertIn(('GET', '/remote/login'), calls)
        self.assertEqual(values(got['service_features']), {('http3', 'no'), ('webdav', 'no'), ('http_methods', 'none'), ('vpn_fortinet', 'yes')})
        self.assertTrue(all(i['host'] == 'vpn.rt.test' and i['port'] == 443 for i in got['service_features']))

    def test_no_read_is_made_unless_asked(self):
        got, calls = self.run_batch([self.entry('robots-txt')], {})
        self.assertEqual(calls, [('GET', '/robots.txt')])
        self.assertEqual(got['service_features'], [])


class ProbeUrlTests(TestCase):
    def test_options_is_allowed_and_a_write_method_is_not(self):
        with self.assertRaises(ValueError):
            http.probe_url('https://www.rt.test/', POLICY, method='PUT')
        with self.assertRaises(ValueError):
            http.probe_url('https://www.rt.test/', POLICY, method='PROPFIND')
        with mock.patch.object(transport, 'resolve', side_effect=ValueError('stop here')):
            with self.assertRaisesRegex(ValueError, 'stop here'):  # past the method check, to the vetted resolution
                http.probe_url('https://www.rt.test/', POLICY, method='OPTIONS')


def slp_reply(xid, function=2, error=0, urls=1):
    url = b'service:VMwareInfrastructure://esx.rt.test'
    body = error.to_bytes(2, 'big') + urls.to_bytes(2, 'big') + (b'\x00' + (65535).to_bytes(2, 'big') + len(url).to_bytes(2, 'big') + url + b'\x00') * urls
    tag = b'en'
    length = 14 + len(tag) + len(body)
    return bytes([2, function]) + length.to_bytes(3, 'big') + b'\x00\x00' + b'\x00\x00\x00' + xid.to_bytes(2, 'big') + len(tag).to_bytes(2, 'big') + tag + body


class FakeSocket:
    def __init__(self, reply):
        self.reply, self.sent, self.closed = reply, b'', False

    def sendall(self, data):
        self.sent += data
        if callable(self.reply):
            self.reply = self.reply(data)

    def settimeout(self, _t):
        pass

    def recv(self, n):
        out, self.reply = self.reply[:n], self.reply[n:]
        return out

    def close(self):
        self.closed = True


ADDRESSES = ((socket.AF_INET, ('203.0.113.5', 427)),)


class SlpTests(TestCase):
    def test_the_request_is_one_small_service_request(self):
        data = sr.slp_request(0x1234)
        self.assertEqual((data[0], data[1]), (2, 1))  # SLPv2, SrvRqst: never a registration (3)
        self.assertEqual(int.from_bytes(data[2:5], 'big'), len(data))
        self.assertEqual(int.from_bytes(data[10:12], 'big'), 0x1234)
        self.assertIn(b'service:VMwareInfrastructure', data)
        self.assertIn(b'DEFAULT', data)
        self.assertLess(len(data), 100)

    def test_a_reply_is_parsed(self):
        self.assertEqual(sr.parse_slp_reply(slp_reply(7), 7), {'function': 'SrvRply', 'error': 0, 'urls': 1})
        self.assertEqual(sr.parse_slp_reply(slp_reply(7, error=4, urls=0), 7), {'function': 'SrvRply', 'error': 4, 'urls': 0})
        self.assertIsNone(sr.parse_slp_reply(slp_reply(7), 8))  # another transaction
        self.assertIsNone(sr.parse_slp_reply(b'SSH-2.0-OpenSSH_9.6\r\n', None))
        self.assertIsNone(sr.parse_slp_reply(slp_reply(7)[:12], 7))

    def read(self, connect):
        with mock.patch.object(transport, 'resolve', return_value=ADDRESSES):
            return sr.read_slp('esx.rt.test', 427, POLICY, connect=connect)

    def test_an_answer_is_yes(self):
        sock = FakeSocket(lambda sent: slp_reply(int.from_bytes(sent[10:12], 'big')))
        item = self.read(lambda *a: sock)
        self.assertEqual((item['feature'], item['value'], item['port']), ('slp', 'yes', 427))
        self.assertIn('SrvRply', item['detail'])
        self.assertTrue(sock.closed)

    def test_a_refused_connection_is_no(self):
        def refuse(*_a):
            raise ConnectionRefusedError()
        item = self.read(refuse)
        self.assertEqual(item['value'], 'no')
        self.assertIn('UDP 427 is not read', item['detail'])

    def test_a_refusal_through_the_probe_proxy_says_nothing(self):
        def refuse(*_a):
            raise ConnectionRefusedError()
        with mock.patch.object(transport, '_proxy_for', return_value=object()):
            self.assertIsNone(self.read(refuse))

    def test_a_timeout_or_another_service_is_unknown(self):
        def slow(*_a):
            raise socket.timeout()
        self.assertIsNone(self.read(slow))
        self.assertIsNone(self.read(lambda *a: FakeSocket(b'SSH-2.0-OpenSSH_9.6\r\n')))

    def test_the_policy_refuses_before_any_connection(self):
        connect = mock.Mock()
        with self.assertRaises(ValueError):
            sr.read_slp('esx.elsewhere.test', 427, POLICY, connect=connect)
        connect.assert_not_called()

    def test_the_hygiene_batch_carries_the_slp_readings(self):
        asked = []

        def read(host, port, policy):
            asked.append((host, port))
            if host == 'out.example':
                raise ValueError('refused')
            return sr._item(host, port, 'slp', 'yes', 'SLPv2 SrvRply')
        target = {'tls': [], 'mail': [], 'slp': [{'host': 'esx.rt.test', 'port': 427}, {'host': 'out.example', 'port': 427}],
                  'scope': {'domains': ['rt.test']}}
        got = hygiene.run_batch(target, slp=read)
        self.assertEqual(sorted(asked), [('esx.rt.test', 427), ('out.example', 427)])
        self.assertEqual(values(got['service_features']), {('slp', 'yes')})
        self.assertIn('out.example', got['refused'])
        with self.assertRaises(ValueError):
            hygiene.run_batch({'tls': [], 'mail': [], 'slp': [{'host': 'x.rt.test'}], 'scope': {}})
