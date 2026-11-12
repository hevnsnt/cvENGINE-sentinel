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


NEUTRAL_ROWS = '\n'.join([
    '{"template":"/t/a.yaml","type":"network","input":"10.77.40.99","address":"10.77.40.99:","error":"cause=\\"no port provided in network protocol request\\"","kind":"unknown-error"}',
    '{"template":"/t/b.yaml","type":"http","input":"10.77.40.99","address":"10.77.40.99:","error":"cause=\\"interactsh client not initialized\\"","kind":"unknown-error"}'])


class TemplateProblemsSayNothingAboutTheHost(unittest.TestCase):
    """Run with -ni (no interactsh), every host gets one ``interactsh client not initialized`` row from each template that wants it, and one ``no port provided``
    row from a network template with no port; a pass with the targeted or deep tags always has them. They say nothing of whether the host answered, but they are
    not connection errors, so a dead host that had them was read as reached: the pass came back with no findings and nothing unreachable, and the host was
    recorded as scanned clean (seen on a lab address nothing answers on, with the tags grafana, jira and tomcat)."""

    def test_a_dead_host_is_unreached_although_templates_logged_their_own_problems(self):
        errors = parse_nuclei_errors(LAB_ROWS.replace('10.77.40.99:80', '10.77.40.99:80') + '\n' + NEUTRAL_ROWS)
        self.assertEqual(unreached_targets(['10.77.40.99'], errors, set()), ['10.77.40.99'])

    def test_template_problems_alone_do_not_make_a_host_unreached(self):
        self.assertEqual(unreached_targets(['10.77.40.99'], parse_nuclei_errors(NEUTRAL_ROWS), set()), [])

    def test_a_real_answer_failure_beside_them_still_means_the_host_answered(self):
        rows = LAB_ROWS + '\n' + NEUTRAL_ROWS + '\n{"input":"10.77.40.99","error":"unexpected EOF reading the body","kind":"unknown-error"}'
        self.assertEqual(unreached_targets(['10.77.40.99'], parse_nuclei_errors(rows), set()), [])


if __name__ == '__main__':
    unittest.main()
