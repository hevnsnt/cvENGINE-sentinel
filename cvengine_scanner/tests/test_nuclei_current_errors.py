"""A host nuclei could not reach is not recorded as scanned clean, with the error text of the pinned nuclei (1.4.0 tool review).

nuclei 3.11.1 logs a request to an address nothing answers on (a host that is down, a filtered or closed port) as ``port closed or filtered`` with
``kind: network-permanent-error``, where older releases said ``connection refused`` or ``i/o timeout``. The reader of the error log knew only the old words, so
a dead host came back as a run with no findings and no unreachable target, and was recorded as scanned clean. The rows below are copied from a run against
a lab address nothing answers on."""
import unittest

from cvengine_scanner.parsers import parse_nuclei_errors, unreached_targets

LAB_ROWS = '\n'.join([
    '{"template":"/home/sentinel/nuclei-templates/http/technologies/lowcoder-detect.yaml","type":"http","input":"http://10.77.40.99","address":"10.77.40.99:80",'
    '"error":"port closed or filtered","kind":"network-permanent-error","attrs":{}}',
    '{"template":"/home/sentinel/nuclei-templates/http/technologies/graphql-detect.yaml","type":"http","input":"http://10.77.40.99/graphiql.min.js",'
    '"address":"10.77.40.99:80","error":"port closed or filtered","kind":"network-permanent-error","attrs":{}}'])


class CurrentNucleiErrors(unittest.TestCase):
    def test_a_host_whose_every_request_failed_as_port_closed_or_filtered_is_unreached(self):
        errors = parse_nuclei_errors(LAB_ROWS)
        self.assertEqual(unreached_targets(['http://10.77.40.99'], errors, set()), ['http://10.77.40.99'])

    def test_a_host_that_answered_is_still_reached(self):
        errors = parse_nuclei_errors(LAB_ROWS)
        self.assertEqual(unreached_targets(['http://10.77.40.99'], errors, {'10.77.40.99'}), [])

    def test_a_failure_that_says_something_answered_does_not_make_the_host_unreached(self):
        rows = LAB_ROWS + '\n{"input":"http://10.77.40.99","error":"unexpected EOF reading the body","kind":"unknown-error"}'
        self.assertEqual(unreached_targets(['http://10.77.40.99'], parse_nuclei_errors(rows), set()), [])

    def test_the_older_wording_still_counts(self):
        rows = '{"input":"http://10.77.40.99","error":"dial tcp 10.77.40.99:80: connect: connection refused"}'
        self.assertEqual(unreached_targets(['http://10.77.40.99'], parse_nuclei_errors(rows), set()), ['http://10.77.40.99'])


if __name__ == '__main__':
    unittest.main()
