"""Ported from cvENGINE's web/tests/test_bucket_scan.py (its tests that need no database), run against the library copy."""
import json
import os
import ssl
from datetime import timedelta
from unittest import mock
from urllib.parse import urlsplit
from unittest import TestCase as SimpleTestCase
from cvengine_scanner.probes import buckets as bp
from cvengine_scanner.probes.policy import ScopePolicy
POLICY = ScopePolicy({'domains': ['amazonaws.com', 'storage.googleapis.com', 'blob.core.windows.net']}, internal=False)
Response = bp.Response
S3_LIST = '''<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>ex-static</Name><Prefix></Prefix><Marker></Marker><MaxKeys>20</MaxKeys><IsTruncated>true</IsTruncated>
<Contents><Key>css/site.css</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag><Size>12</Size><StorageClass>STANDARD</StorageClass></Contents>
<Contents><Key>img/a&amp;b.png</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag><Size>9</Size><StorageClass>STANDARD</StorageClass></Contents>
</ListBucketResult>'''
S3_EMPTY = '<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>ex-empty</Name><Prefix></Prefix><Marker></Marker><MaxKeys>20</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>'
S3_DENIED = '<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>4442587FB7D0A2F9</RequestId><HostId>7tDt0ksZ1y</HostId></Error>'
S3_NOSUCH = '<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>ex-gone</BucketName><RequestId>0D4C1A12D5E5A6B1</RequestId><HostId>q8Wb</HostId></Error>'
S3_REDIRECT = ('<?xml version="1.0" encoding="UTF-8"?><Error><Code>PermanentRedirect</Code><Message>The bucket you are attempting to access must be addressed using '
               'the specified endpoint. Please send all future requests to this endpoint.</Message><Endpoint>ex-eu.s3.eu-west-1.amazonaws.com</Endpoint><Bucket>ex-eu</Bucket></Error>')
GCS_LIST = json.dumps({'kind': 'storage#objects', 'nextPageToken': 'CgtmaWxlMDEudHh0', 'items': [{'name': 'public/readme.txt'}, {'name': 'public/logo.png'}]})
GCS_EMPTY = json.dumps({'kind': 'storage#objects'})
GCS_MISSING = json.dumps({'error': {'code': 404, 'message': 'The specified bucket does not exist.', 'errors': [{'message': 'The specified bucket does not exist.', 'domain': 'global', 'reason': 'notFound'}]}})
GCS_DENIED = json.dumps({'error': {'code': 401, 'message': "Anonymous caller does not have storage.objects.list access to the Google Cloud Storage bucket. Permission 'storage.objects.list' denied on resource (or it may not exist).", 'errors': [{'reason': 'required'}]}})
AZ_LIST = '''<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://exstore.blob.core.windows.net/" ContainerName="media"><MaxResults>20</MaxResults>
<Blobs><Blob><Name>banner.jpg</Name><Properties><Last-Modified>Mon, 05 Jan 2026 10:00:00 GMT</Last-Modified><Content-Length>1024</Content-Length></Properties></Blob><BlobPrefix><Name>old/</Name></BlobPrefix></Blobs><NextMarker /></EnumerationResults>'''
AZ_NOCONTAINER = '<?xml version="1.0" encoding="utf-8"?><Error><Code>ContainerNotFound</Code><Message>The specified container does not exist.</Message></Error>'
AZ_NOPUBLIC = '<?xml version="1.0" encoding="utf-8"?><Error><Code>PublicAccessNotPermitted</Code><Message>Public access is not permitted on this storage account.</Message></Error>'
def xml(status, body, **headers):
    return Response(status, {k.replace('_', '-'): v for k, v in headers.items()}, body.encode())
S3 = 'https://ex-static.s3.amazonaws.com/?max-keys=20'
S3_HEAD = 'HEAD https://ex-static.s3.amazonaws.com/css/site.css'
class Net:
    """A fake storage platform: it answers a request by its URL and remembers every one. A URL it has no answer for gets what the
    platform says for a bucket that is not there."""

    def __init__(self, **routes):
        self.routes, self.calls = {}, []
        for url, answer in routes.items():
            self.routes[url.replace('|', '/')] = answer

    def __call__(self, method, url):
        self.calls.append((method, url))
        got = self.routes.get(f'{method} {url}') or self.routes.get(url)
        if isinstance(got, Exception):
            raise got
        if got is not None:
            return got
        if method == 'HEAD':
            return Response(404)
        if urlsplit(url).hostname == 'storage.googleapis.com':
            return xml(404, GCS_MISSING)
        return xml(404, S3_NOSUCH)

    @property
    def urls(self):
        return [u for _m, u in self.calls]


class ParseTests(SimpleTestCase):




    def test_the_documented_s3_listing_and_errors(self):
        keys, more = bp.parse_s3_listing(S3_LIST.encode())
        self.assertEqual((keys, more), (['css/site.css', 'img/a&b.png'], True))
        self.assertEqual(bp.parse_s3_listing(S3_EMPTY.encode()), ([], False))
        self.assertIsNone(bp.parse_s3_listing(S3_DENIED.encode()))

    def test_a_listing_that_declares_entities_is_read_as_text_never_expanded(self):
        body = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "AAAAAAAAAAAAAAAAAAAA">]><ListBucketResult><Contents><Key>&a;</Key></Contents></ListBucketResult>').encode()
        self.assertEqual(bp.parse_s3_listing(body)[0], ['&a;'])

    def test_a_listing_is_cut_to_the_first_page(self):
        body = '<ListBucketResult>' + ''.join(f'<Contents><Key>k{i}</Key></Contents>' for i in range(50)) + '</ListBucketResult>'
        keys, more = bp.parse_s3_listing(body.encode())
        self.assertEqual((len(keys), more), (bp.MAX_KEYS, True))

    def test_gcs_and_azure_documents(self):
        self.assertEqual(bp.parse_gcs_listing(GCS_LIST.encode()), (['public/readme.txt', 'public/logo.png'], True))
        self.assertEqual(bp.parse_gcs_listing(GCS_EMPTY.encode()), ([], False))
        self.assertIsNone(bp.parse_gcs_listing(GCS_MISSING.encode()))
        self.assertEqual(bp.gcs_error(GCS_MISSING.encode())[0], 404)
        self.assertEqual(bp.parse_azure_listing(AZ_LIST.encode()), (['banner.jpg'], False))  # a BlobPrefix is a folder, not an object
        self.assertIsNone(bp.parse_azure_listing(AZ_NOCONTAINER.encode()))

class RedactionTests(SimpleTestCase):
    def test_secret_looking_segments_are_replaced(self):
        for name in ('exports/AKIAIOSFODNN7EXAMPLE/dump.csv', 'logs/token=abcDEF123/x.log', 'cfg/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig/x',
                     'uploads/ghp_abcdefghijklmnopqrstuvwxyz0123456789/a', 'k/Qx9Zr2LmN8pT4vB7cD1fG6hJ3kS5wY/a.json', 'a/AIzaSyA-1234567890abcdefghijklmnopqrstu/b'):
            self.assertIn(bp.REDACTED, bp.redact_name(name), name)
        self.assertEqual(bp.redact_name('exports/AKIAIOSFODNN7EXAMPLE/dump.csv'), 'exports/[redacted]/dump.csv')

    def test_ordinary_names_survive(self):
        for name in ('css/site.css', 'images/2026/01/photo-final.jpg', 'a3f5c9e1b7d24680a3f5c9e1b7d24680.bin', '123e4567-e89b-12d3-a456-426614174000.pdf',
                     'reports/quarterly-report-2026-q1.pdf'):
            self.assertEqual(bp.redact_name(name), name)

    def test_control_characters_and_length_are_bounded(self):
        self.assertEqual(bp.redact_name('a\nb'), 'a?b')
        self.assertEqual(len(bp.redact_name('x' * 900)), bp.MAX_NAME)

    def test_sensitive_looking_names(self):
        for name in ('backup/2026-01.tar.gz', 'db/users.sql', 'prod.env', 'keys/server.pem', 'terraform.tfstate', 'dumps/customers.csv', 'id_rsa'):
            self.assertTrue(bp.is_sensitive_name(name), name)
        for name in ('css/site.css', 'img/logo.png', 'docs/handbook.pdf'):
            self.assertFalse(bp.is_sensitive_name(name), name)

    def test_the_object_that_is_asked_for_is_never_a_folder_or_sensitive(self):
        self.assertEqual(bp.pick_object(['backup/', 'backup/db.sql', 'img/a.png']), 'img/a.png')
        self.assertIsNone(bp.pick_object(['db.sql', 'keys/id_rsa']))
class ProbeTests(SimpleTestCase):
    def test_a_public_s3_listing_is_read_once_and_one_object_is_asked_for_with_head(self):
        net = Net(**{S3: xml(200, S3_LIST), S3_HEAD: Response(200)})
        verdict = bp.check('s3', 'ex-static', fetch=net)
        self.assertEqual((verdict.state, verdict.objects, verdict.object_read), ('public', ['css/site.css', 'img/a&b.png'], True))
        self.assertEqual(net.calls, [('GET', S3), ('HEAD', 'https://ex-static.s3.amazonaws.com/css/site.css')])  # the listing and one HEAD: nothing else

    def test_a_refused_object_is_recorded_as_refused(self):
        verdict = bp.check('s3', 'ex-static', fetch=Net(**{S3: xml(200, S3_LIST), S3_HEAD: Response(403)}))
        self.assertEqual((verdict.state, verdict.object_read), ('public', False))

    def test_a_listing_of_only_sensitive_names_tests_no_object(self):
        body = '<ListBucketResult><Contents><Key>db/users.sql</Key></Contents><Contents><Key>keys/id_rsa</Key></Contents></ListBucketResult>'
        net = Net(**{S3: xml(200, body)})
        verdict = bp.check('s3', 'ex-static', fetch=net)
        self.assertEqual((verdict.state, verdict.object_read), ('public', None))
        self.assertEqual([m for m, _u in net.calls], ['GET'])

    def test_a_private_bucket_and_a_missing_one(self):
        self.assertEqual(bp.check('s3', 'ex-static', fetch=Net(**{S3: xml(403, S3_DENIED)})).state, 'private')
        verdict = bp.check('s3', 'ex-static', fetch=Net(**{S3: xml(404, S3_NOSUCH)}))
        self.assertEqual((verdict.state, verdict.code), ('missing', 'NoSuchBucket'))

    def test_a_bucket_in_another_region_is_followed_once_by_the_region_the_platform_names(self):
        net = Net(**{'https://ex-eu.s3.amazonaws.com/?max-keys=20': xml(301, S3_REDIRECT, x_amz_bucket_region='eu-west-1'),
                     'https://ex-eu.s3.eu-west-1.amazonaws.com/?max-keys=20': xml(403, S3_DENIED)})
        verdict = bp.check('s3', 'ex-eu', fetch=net)
        self.assertEqual((verdict.state, verdict.region, len(net.calls)), ('private', 'eu-west-1', 2))

    def test_a_redirect_to_something_that_is_not_a_region_is_not_followed(self):
        net = Net(**{'https://ex-eu.s3.amazonaws.com/?max-keys=20': xml(301, S3_REDIRECT, x_amz_bucket_region='evil.test/x')})
        self.assertEqual((bp.check('s3', 'ex-eu', fetch=net).state, len(net.calls)), ('unknown', 1))

    def test_a_dotted_bucket_uses_path_style(self):
        net = Net()
        bp.check('s3', 'www.example.test', fetch=net)
        self.assertEqual(net.urls, ['https://s3.amazonaws.com/www.example.test/?max-keys=20'])

    def test_gcs_listing_private_and_missing(self):
        url = 'https://storage.googleapis.com/storage/v1/b/ex-assets/o?maxResults=20&fields=kind,nextPageToken,items(name)'
        net = Net(**{url: xml(200, GCS_LIST), 'HEAD https://storage.googleapis.com/ex-assets/public/readme.txt': Response(200)})
        verdict = bp.check('gcs', 'ex-assets', fetch=net)
        self.assertEqual((verdict.state, verdict.truncated, verdict.object_read), ('public', True, True))
        self.assertEqual(bp.check('gcs', 'ex-assets', fetch=Net(**{url: xml(401, GCS_DENIED)})).state, 'private')
        self.assertEqual(bp.check('gcs', 'ex-assets', fetch=Net(**{url: xml(404, GCS_MISSING)})).state, 'missing')

    def test_an_empty_public_gcs_bucket_is_still_a_public_listing(self):
        url = 'https://storage.googleapis.com/storage/v1/b/ex-assets/o?maxResults=20&fields=kind,nextPageToken,items(name)'
        verdict = bp.check('gcs', 'ex-assets', fetch=Net(**{url: xml(200, GCS_EMPTY)}))
        self.assertEqual((verdict.state, verdict.objects, verdict.object_read), ('public', [], None))

    def test_azure_account_by_dns_and_container_by_listing(self):
        url = 'https://exstore.blob.core.windows.net/media?restype=container&comp=list&maxresults=20'
        net = Net(**{url: xml(200, AZ_LIST), 'HEAD https://exstore.blob.core.windows.net/media/banner.jpg': Response(200)})
        verdict = bp.check('azure', 'exstore', 'media', fetch=net, dns=lambda host: True)
        self.assertEqual((verdict.state, verdict.objects, verdict.object_read), ('public', ['banner.jpg'], True))
        self.assertEqual(bp.check('azure', 'exstore', 'media', fetch=Net(**{url: xml(409, AZ_NOPUBLIC)}), dns=lambda host: True).state, 'private')
        self.assertEqual(bp.check('azure', 'exstore', 'media', fetch=Net(**{url: xml(404, AZ_NOCONTAINER)}), dns=lambda host: True).state, 'private')

    def test_an_azure_account_without_an_address_is_missing_and_no_http_request_is_made(self):
        net = Net()
        verdict = bp.check('azure', 'exstore', 'media', fetch=net, dns=lambda host: False)
        self.assertEqual((verdict.state, verdict.code, net.calls), ('missing', 'NXDOMAIN', []))

    def test_an_azure_account_with_no_container_to_ask_about_is_not_listed(self):
        net = Net()
        verdict = bp.check('azure', 'exstore', '', fetch=net, dns=lambda host: True)
        self.assertEqual((verdict.state, net.calls), ('private', []))

    def test_no_dns_answer_is_unknown_not_missing(self):
        self.assertEqual(bp.check('azure', 'exstore', '', fetch=Net(), dns=lambda host: None).state, 'unknown')

    def test_a_network_failure_or_a_refused_address_is_unknown(self):
        self.assertEqual(bp.check('s3', 'ex-static', fetch=Net(**{S3: OSError('reset')})).state, 'unknown')
        self.assertEqual(bp.check('s3', 'ex-static', fetch=Net(**{S3: ValueError('probe destination is prohibited')})).state, 'unknown')
        self.assertEqual(bp.check('s3', 'ex-static', fetch=Net(**{S3: xml(503, '<Error><Code>SlowDown</Code></Error>')})).state, 'unknown')
class FetchTests(SimpleTestCase):
    """The one function that touches the network: what it refuses before anything is sent."""

    def refused(self, method, url):
        with mock.patch('cvengine_scanner.probes.transport.resolve') as resolve, mock.patch('cvengine_scanner.probes.transport.HTTPConnection') as connection:
            with self.assertRaises(ValueError):
                bp.http_fetch(method, url, POLICY)
        resolve.assert_not_called()
        connection.assert_not_called()

    def test_only_get_and_head(self):
        for method in ('POST', 'PUT', 'DELETE', 'OPTIONS'):
            self.refused(method, 'https://ex-static.s3.amazonaws.com/')

    def test_only_https_on_443_to_a_documented_storage_endpoint(self):
        for url in ('http://ex-static.s3.amazonaws.com/', 'https://ex-static.s3.amazonaws.com:8443/', 'https://www.example.test/', 'https://example.test/s3.amazonaws.com',
                    'https://ex-static.s3.amazonaws.com.evil.test/', 'https://203.0.113.5/', 'https://user:pw@ex-static.s3.amazonaws.com/',
                    'https://evil.test@ex-static.s3.amazonaws.com.evil.test/', 'https://ec2-203-0-113-5.compute-1.amazonaws.com/', 'https://x.cloudfront.net/'):
            self.refused('GET', url)

    def test_the_endpoint_list(self):
        for host in ('s3.amazonaws.com', 'ex-static.s3.amazonaws.com', 's3.eu-west-1.amazonaws.com', 'ex-static.s3.eu-west-1.amazonaws.com', 'storage.googleapis.com',
                     'exstore.blob.core.windows.net'):
            self.assertTrue(bp.endpoint_allowed(host), host)
        for host in ('ex.static.s3.amazonaws.com', 'exstore.z13.web.core.windows.net', 'ex-static.storage.googleapis.com', 'example.test', ''):
            self.assertFalse(bp.endpoint_allowed(host), host)

    def test_a_storage_name_that_resolves_to_a_prohibited_address_is_never_connected_to(self):
        with mock.patch('cvengine_scanner.probes.transport.resolve', side_effect=ValueError('probe destination is prohibited')), \
                mock.patch('cvengine_scanner.probes.transport.HTTPConnection') as connection:
            with self.assertRaises(ValueError):
                bp.http_fetch('GET', 'https://ex-static.s3.amazonaws.com/', POLICY)
        connection.assert_not_called()

    def test_a_request_goes_to_the_vetted_address_on_443_with_certificate_checks_and_no_credentials(self):
        addresses = ((2, ('203.0.113.9', 443)),)
        response = mock.Mock(status=200)
        response.getheader.side_effect = lambda name: {'x-amz-bucket-region': 'us-east-1'}.get(name)
        response.read.return_value = b'<ListBucketResult/>'
        with mock.patch('cvengine_scanner.probes.transport.resolve', return_value=addresses) as resolve, \
                mock.patch('cvengine_scanner.probes.transport.HTTPConnection') as connection:
            connection.return_value.getresponse.return_value = response
            pacer = mock.Mock()
            got = bp.http_fetch('GET', 'https://ex-static.s3.amazonaws.com/?max-keys=20', POLICY, pacer)
        resolve.assert_called_once_with('ex-static.s3.amazonaws.com', 443, POLICY)
        args, kwargs = connection.call_args
        self.assertEqual(args[:3], ('ex-static.s3.amazonaws.com', 443, addresses))
        self.assertIs(args[4], POLICY)  # every address is judged by the task's policy again when it connects
        self.assertEqual(kwargs['context'].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(kwargs['context'].check_hostname)
        method, path = connection.return_value.request.call_args[0]
        self.assertEqual((method, path), ('GET', '/?max-keys=20'))
        sent = {k.lower() for k in connection.return_value.request.call_args[1]['headers']}
        self.assertFalse(sent & {'authorization', 'cookie', 'x-amz-security-token', 'x-ms-version'})
        pacer.wait.assert_called_once()  # every request waits for its turn at the task's rate
        self.assertEqual((got.status, got.headers['x-amz-bucket-region'], got.body), (200, 'us-east-1', b'<ListBucketResult/>'))
        connection.return_value.close.assert_called_once()

    def fetch_encoded(self, body, encoding):
        from cvengine_scanner.tests.probes.test_transport import FakeResponse
        response = FakeResponse(body, encoding)
        response.status = 200
        with mock.patch('cvengine_scanner.probes.transport.resolve', return_value=((2, ('203.0.113.9', 443)),)), \
                mock.patch('cvengine_scanner.probes.transport.HTTPConnection') as connection:
            connection.return_value.getresponse.return_value = response
            return bp.http_fetch('GET', 'https://ex-static.s3.amazonaws.com/?max-keys=20', POLICY)

    def test_a_listing_a_server_sends_gzipped_despite_identity_is_read(self):
        import gzip
        listing = b'<ListBucketResult><Name>ex-static</Name><Contents><Key>a.txt</Key></Contents></ListBucketResult>'
        got = self.fetch_encoded(gzip.compress(listing), 'gzip')
        self.assertEqual((got.status, got.body), (200, listing))

    def test_a_compressed_body_is_cut_at_the_cap_after_decoding_and_a_bad_one_is_a_network_error(self):
        import gzip
        got = self.fetch_encoded(gzip.compress(b'A' * 20_000_000, compresslevel=9), 'gzip')
        self.assertEqual(len(got.body), bp.MAX_BODY)
        for body, encoding in ((b'garbage', 'gzip'), (b'<x/>', 'br')):
            with self.assertRaises(OSError):
                self.fetch_encoded(body, encoding)

    def test_a_head_reads_no_body(self):
        response = mock.Mock(status=200)
        response.getheader.return_value = ''
        with mock.patch('cvengine_scanner.probes.transport.resolve', return_value=((2, ('203.0.113.9', 443)),)), \
                mock.patch('cvengine_scanner.probes.transport.HTTPConnection') as connection:
            connection.return_value.getresponse.return_value = response
            bp.http_fetch('HEAD', 'https://ex-static.s3.amazonaws.com/a.png', POLICY)
        response.read.assert_not_called()


class BatchTests(SimpleTestCase):
    """The bucket_check kind (``run_batch``): the task's buckets under its scope policy, paced at its rate."""

    SCOPE = {'hosts': [], 'domains': ['amazonaws.com', 'storage.googleapis.com', 'blob.core.windows.net'], 'excluded': [], 'excluded_trees': [],
             'private': False, 'addresses': [], 'blocked': []}

    def test_a_public_listing_comes_back_whole_with_what_was_touched(self):
        net = Net(**{S3: xml(200, S3_LIST), S3_HEAD: Response(403, {}, b'')})
        pauses = []
        got = bp.run_batch({'scope': self.SCOPE, 'rate': 2, 'buckets': [{'id': 'b1', 'provider': 's3', 'name': 'ex-static'}]}, fetch=net, sleep=pauses.append)
        verdict = got['buckets'][0]['verdict']
        self.assertEqual((verdict['state'], verdict['objects'], verdict['truncated'], verdict['object_read']), ('public', ['css/site.css', 'img/a&b.png'], True, False))
        self.assertEqual(got['touched'], ['ex-static.s3.amazonaws.com'])
        self.assertEqual(len(pauses), 1)  # two requests, the second waits for its turn at 2 per second
        self.assertTrue(0.4 < pauses[0] <= 0.5, pauses)

    def test_an_endpoint_the_policy_does_not_name_is_never_asked(self):
        net = Net(**{S3: xml(200, S3_LIST)})
        scope = {**self.SCOPE, 'domains': ['storage.googleapis.com']}
        got = bp.run_batch({'scope': scope, 'buckets': [{'id': 'b1', 'provider': 's3', 'name': 'ex-static'}]}, fetch=net, sleep=lambda s: None)
        self.assertEqual(got['buckets'][0]['verdict']['state'], 'unknown')  # no answer, never "missing"
        self.assertEqual(net.calls, [])
        self.assertEqual(got['refused'], ['ex-static.s3.amazonaws.com'])

    def test_an_azure_account_outside_the_policy_is_not_even_looked_up(self):
        dns = mock.Mock(return_value=False)
        scope = {**self.SCOPE, 'domains': ['amazonaws.com']}
        got = bp.run_batch({'scope': scope, 'buckets': [{'id': 'a1', 'provider': 'azure', 'name': 'exstore', 'container': 'media'}]},
                           fetch=Net(), dns=dns, sleep=lambda s: None)
        dns.assert_not_called()
        self.assertEqual(got['buckets'][0]['verdict']['state'], 'unknown')

    def test_a_malformed_task_is_refused_whole(self):
        for bad in ({'id': 'b', 'provider': 'ftp', 'name': 'x'}, {'id': '', 'provider': 's3', 'name': 'x'}, {'id': 'b', 'provider': 's3', 'name': 'a b'}, 'x'):
            with self.assertRaises(ValueError):
                bp.run_batch({'scope': self.SCOPE, 'buckets': [bad]}, fetch=Net())
        with self.assertRaises(ValueError):
            bp.run_batch({'scope': self.SCOPE, 'buckets': [{'id': 'b', 'provider': 's3', 'name': 'x'}] * (bp.MAX_BUCKETS + 1)}, fetch=Net())

    def test_the_rate_is_clamped(self):
        self.assertEqual((bp.clamp_rate(100), bp.clamp_rate(0), bp.clamp_rate('x')), (5.0, 0.1, bp.DEFAULT_RPS))
