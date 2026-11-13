"""The shared scan policy (``cvengine_scanner.flags``): the nuclei exclusion floor and flag builder, the UDP sweep's flags, the reviewed NSE
scripts and the probe ports. Ported from the cvENGINE server's tests (tests.test_resources, tests.test_authcheck, tests.test_egress_proxy,
tests.test_udp_scan, tests.test_hard_naabu, tests.test_probes, tests.test_discovery)."""
import unittest

from cvengine_scanner import flags


class NucleiFlagTests(unittest.TestCase):
    def test_every_nuclei_run_excludes_the_dos_templates(self):
        for argv in (flags.NUCLEI_FLAGS, flags.NUCLEI_BASE_FLAGS, flags.nuclei_flags(), flags.nuclei_flags(['rce'], 'light'),
                     flags.nuclei_flags(tech=True), flags.nuclei_flags(['wordpress'], secret_file='/tmp/x/secrets.json')):
            with self.subTest(argv=argv):
                self.assertEqual(argv[argv.index('-etags') + 1], 'dos,default-login,bruteforce')  # credential checks are off unless a person turns them on (TL-2)

    def test_the_sentinel_run_keeps_the_raw_request_and_response(self):
        # what a Sentinel ran before the builders moved here, less -omit-raw: a finding keeps its request and response (clipped, credentials redacted by
        # parse_nuclei_jsonl) as the evidence a person can repeat (review M2). Every other flag is as it was.
        self.assertEqual(flags.NUCLEI_FLAGS, ['-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150', '-c', '40', '-timeout', '10', '-retries', '1',
                                              '-etags', 'dos,default-login,bruteforce'])
        self.assertNotIn('-omit-raw', flags.NUCLEI_FLAGS)

    def test_the_server_run_is_unchanged(self):
        self.assertEqual(flags.NUCLEI_BASE_FLAGS, ['-severity', 'info,low,medium,high,critical', '-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150',
                                                   '-c', '40', '-timeout', '10', '-retries', '1', '-etags', 'dos,default-login,bruteforce'])

    def test_credential_checks_come_back_only_when_asked_for(self):
        for build in (flags.nuclei_flags, flags.nuclei_web_flags):
            on, off = build(allow_credential_checks=True), build()
            self.assertEqual(on[on.index('-etags') + 1], 'dos')
            self.assertEqual(off[off.index('-etags') + 1], 'dos,default-login,bruteforce')
        self.assertEqual(flags.nuclei_flags(['rce'], 'light', allow_credential_checks=True).count('-etags'), 1)

    def test_the_light_profile_lowers_rate_and_concurrency(self):
        normal, light = flags.nuclei_flags(), flags.nuclei_flags(profile='light')
        self.assertEqual(normal[normal.index('-rl') + 1], '150')
        self.assertEqual(light[light.index('-rl') + 1], '50')
        self.assertEqual(light[light.index('-c') + 1], '10')
        self.assertIn('-bs', light)
        self.assertEqual(flags.nuclei_flags(['rce', 'apache'], 'light')[-2:], ['-tags', 'apache,rce'])

    def test_severities_and_the_tech_pass(self):
        argv = flags.nuclei_flags(severities=['high', 'critical'])
        self.assertEqual(argv[argv.index('-severity') + 1], 'high,critical')
        tech = flags.nuclei_flags(['ignored'], tech=True)
        self.assertEqual(tech[tech.index('-severity') + 1], 'info')
        self.assertEqual(tech[-2:], ['-tags', 'tech'])

    def test_a_signed_in_run_adds_only_the_file_path_and_no_redirects(self):
        plain = flags.nuclei_flags(['wordpress'])
        signed = flags.nuclei_flags(['wordpress'], secret_file='/tmp/x/secrets.json')
        self.assertEqual(signed, plain + ['-sf', '/tmp/x/secrets.json', '-dr'])

    def test_the_templates_and_the_proxy_arguments(self):
        self.assertNotIn('-proxy', flags.nuclei_flags())
        self.assertEqual(flags.nuclei_flags(proxy_args=['-proxy', 'http://192.0.2.1:3128'])[-2:], ['-proxy', 'http://192.0.2.1:3128'])
        with_templates = flags.nuclei_flags(templates_dir='/t')
        self.assertEqual(with_templates[with_templates.index('-t') + 1], '/t')

    def test_host_of_reads_a_url_a_host_port_or_a_bare_host(self):
        self.assertEqual(flags.host_of({'host': 'https://Www.Example.test:8443/x'}), 'www.example.test')
        self.assertEqual(flags.host_of({'host': 'www.example.test:8443'}), 'www.example.test')
        self.assertEqual(flags.host_of({'host': 'www.example.test'}), 'www.example.test')
        self.assertEqual(flags.host_of({'host': '', 'ip': '[2001:db8::1]'}), '2001:db8::1')
        self.assertEqual(flags.host_of({'host': 'http://[::1'}), '')  # a URL that does not parse names no host
        self.assertEqual(flags.host_of({'host': 5}), '')


class NmapFlagTests(unittest.TestCase):
    def test_only_reviewed_scripts_survive_and_the_udp_ones_are_reviewed(self):
        self.assertTrue(set(flags.UDP_NSE_SCRIPTS) <= flags.NSE_SCRIPT_SET)
        self.assertNotIn('ntp-monlist', flags.NSE_SCRIPT_SET)  # nmap files it under intrusive, and the target records it
        self.assertNotIn('snmp-brute', flags.NSE_SCRIPT_SET)
        self.assertEqual(flags.reviewed_scripts({'snmp-sysdescr': 'x', 'ntp-monlist': 'y', 'ike-version': 'z'}), {'snmp-sysdescr': 'x'})
        self.assertEqual(flags.reviewed_scripts(None), {})

    def test_the_udp_sweep_is_slow_and_low(self):
        argv = flags.udp_nmap_flags()
        self.assertEqual(argv[:2], ['-sU', '-sV'])
        self.assertEqual(argv[argv.index('--version-intensity') + 1], '3')
        self.assertEqual(argv[argv.index('--max-retries') + 1], '1')
        self.assertEqual(argv[argv.index('--max-rate') + 1], '20')
        self.assertIn('-Pn', argv)
        self.assertIn('-n', argv)
        self.assertNotIn('-T4', argv)
        self.assertTrue(set(argv[argv.index('--script') + 1].split(',')) <= flags.NSE_SCRIPT_SET)
        self.assertEqual(argv[argv.index('-p') + 1], 'U:' + ','.join(str(p) for p in flags.UDP_PORTS))
        custom = flags.udp_nmap_flags([123, 161], 5)
        self.assertEqual((custom[custom.index('-p') + 1], custom[custom.index('--max-rate') + 1]), ('U:123,161', '5'))

    def test_the_fingerprint_pass_runs_the_reviewed_scripts(self):
        self.assertEqual(flags.NMAP_FAST_FLAGS[flags.NMAP_FAST_FLAGS.index('--script') + 1], ','.join(flags.NSE_SCRIPTS))
        self.assertEqual(flags.NMAP_FAST_FLAGS[flags.NMAP_FAST_FLAGS.index('--top-ports') + 1], str(flags.TOP_PORTS))
        self.assertEqual(len(flags.EXTRA_PORTS), len(set(flags.EXTRA_PORTS)))
        self.assertTrue({6379, 27017, 2375, 10250} <= set(flags.EXTRA_PORTS))

    def test_the_port_argument_is_compact(self):
        self.assertEqual(flags.port_argument([8080, 22, 80, 81, 82, 443, 22]), '22,80-82,443,8080')
        self.assertEqual(flags.port_argument([5]), '5')
        self.assertEqual(flags.port_argument([*flags.CLOSED_PROBE_PORTS, 22]), '1,3,22')

    def test_the_version_probe_runs_only_reviewed_scripts_for_the_service(self):
        for service, expected in (('http', 'http-server-header'), ('ssl/http', 'http-server-header'), ('https', 'http-server-header'),
                                  ('ssh', 'ssh2-enum-algos'), ('ftp', 'ftp-anon'), ('mystery', 'banner'), ('', 'banner')):
            with self.subTest(service=service):
                argv = flags.probe_nmap_flags(443, service)
                scripts = argv[argv.index('--script') + 1].split(',')
                self.assertIn(expected, scripts)
                self.assertTrue(set(scripts) <= flags.NSE_SCRIPT_SET)
                self.assertEqual(argv[argv.index('-p') + 1], '443')
        with self.assertRaises(ValueError):
            flags.probe_nmap_flags('443; rm -rf /')

    def test_a_desktop_vm_kernel_is_named(self):
        for release in ('6.10.14-linuxkit', '5.15.153.1-microsoft-standard-WSL2', '6.7.11-orbstack-00143', '4.9.93-boot2docker', '4.9.87-moby'):
            self.assertTrue(any(marker in release.lower() for marker in flags.KERNEL_MARKERS), release)
        self.assertFalse(any(marker in '6.8.0-45-generic' for marker in flags.KERNEL_MARKERS))



class TaskLimitTests(unittest.TestCase):
    """Review H5 and M7: the time a nmap or naabu task may take, and how many hosts one naabu task carries, come from one function that the
    Sentinel and the server both use, so neither gives up a task the other is still running."""

    def test_nmap_keeps_the_limit_the_sentinel_has_always_used(self):
        self.assertEqual([flags.task_seconds('nmap', n) for n in (1, 10, 64)], [600, 900, 3600])

    def test_a_naabu_run_of_one_host_gets_the_full_sweep_budget(self):
        self.assertEqual(flags.task_seconds('naabu', 1), 900)
        self.assertEqual(flags.task_seconds('naabu', 12), 1800)

    def test_the_host_count_of_a_naabu_task_fits_its_time_limit(self):
        per_task = flags.hosts_per_task('naabu')
        self.assertGreaterEqual(per_task, 6)  # 138 s measured for one loopback host: the old 900 s held about six
        self.assertLessEqual(flags.task_seconds('naabu', per_task), flags.NAABU_MAX_SECONDS)
        self.assertLess(per_task, flags.MAX_TARGETS)  # a task of the largest chunk does not fit: the server splits it

    def test_a_time_the_task_names_is_used_inside_the_kinds_range_only(self):
        self.assertEqual(flags.task_seconds('naabu', 5, requested=1800), 1800)
        self.assertEqual(flags.task_seconds('naabu', 5, requested=10 ** 6), flags.NAABU_MAX_SECONDS)
        self.assertEqual(flags.task_seconds('naabu', 5, requested=3), 900)
        self.assertEqual(flags.task_seconds('nmap', 5, requested=True), 600)  # a boolean is not a time
        self.assertEqual(flags.task_seconds('nmap', 5, requested='1800'), 600)

    def test_an_unknown_kind_has_no_limit_here(self):
        with self.assertRaises(KeyError):
            flags.task_seconds('bbot_discovery', 1)


class NmapPassFlagsTests(unittest.TestCase):
    """Review M1: the fingerprint pass scans the ports naabu found plus the extended and closed probe ports, with the reviewed scripts and
    intensity 7 (NMAP_FAST_FLAGS), and keeps the host timeout that makes a timed-out host visible (H3)."""

    def test_the_task_ports_are_the_ones_scanned_with_the_extra_and_closed_probe_ports(self):
        argv = flags.nmap_pass_flags([22, 80, 8000, 8001])
        self.assertNotIn('--top-ports', argv)
        covered = set()
        for part in argv[argv.index('-p') + 1].split(','):
            low, _, high = part.partition('-')
            covered.update(range(int(low), int(high or low) + 1))
        self.assertTrue({22, 80, 8000, 8001, 6379, 27017, *flags.CLOSED_PROBE_PORTS} <= covered)

    def test_a_task_that_names_no_ports_scans_the_top_thousand(self):
        argv = flags.nmap_pass_flags(None)
        self.assertEqual(argv[argv.index('--top-ports') + 1], '1000')
        self.assertNotIn('-p', argv)

    def test_the_pass_keeps_the_reviewed_scripts_and_the_host_timeout(self):
        argv = flags.nmap_pass_flags([22])
        self.assertEqual(argv[argv.index('--version-intensity') + 1], '7')
        self.assertEqual(argv[argv.index('--script') + 1], ','.join(flags.NSE_SCRIPTS))
        self.assertEqual(argv[argv.index('--host-timeout') + 1], '8m')
        self.assertIn('-n', argv)

    def test_a_port_that_is_not_a_port_is_refused(self):
        for bad in ([0], [65536], ['22'], [True], [22, 'x'], list(range(1, flags.MAX_NMAP_PORTS + 2))):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                flags.nmap_pass_flags(bad)


if __name__ == '__main__':
    unittest.main()


class NucleiTaskLimitTests(unittest.TestCase):
    """A nuclei run ends before the server stops waiting for it (agentapi.sentinel_dispatch: COMPLETION_CEILING + PER_TARGET_SECONDS x (targets - 1)), so its
    findings arrive. The server's numbers are copied here on purpose: a change on one side must fail this until the other side matches."""
    SERVER = {'nuclei_light': (900, 20), 'nuclei_targeted': (1800, 30), 'nuclei_deep': (3600, 60)}

    def test_every_nuclei_run_ends_at_least_a_minute_before_the_server_gives_up(self):
        from cvengine_scanner.flags import task_seconds
        for kind, (base, per) in self.SERVER.items():
            for count in (1, 2, 5, 9, 21, 64, 200):
                with self.subTest(kind=kind, targets=count):
                    self.assertLessEqual(task_seconds(kind, count), base + per * (count - 1) - 60)

    def test_the_limits_cover_the_longest_runs_seen_in_production(self):
        """The longest completed runs on the VPS (11/8 to 11/10) fit: a limit is a ceiling on a stuck run, never on a normal one."""
        from cvengine_scanner.flags import task_seconds
        for kind, count, longest in (('nuclei_light', 63, 926), ('nuclei_targeted', 9, 1714), ('nuclei_deep', 21, 3008), ('nuclei_deep', 1, 1335)):
            with self.subTest(kind=kind, targets=count):
                self.assertGreater(task_seconds(kind, count), longest)


class NucleiServiceBudgetTests(unittest.TestCase):
    """What one host:port of a non-web service may receive from one task, and which templates it may receive."""

    def test_the_pace_of_a_service_run_is_a_pause_between_template_runs(self):
        spend = flags.nuclei_service_budget(None)
        self.assertEqual(spend, {'pause_ms': 500, 'seconds': 300, 'web_rate': 25})
        self.assertGreaterEqual(spend['pause_ms'], 500)  # at most two template runs a second on one host:port: nuclei's own -rl does not pace tcp, javascript or ssl

    def test_the_ssh_class_has_a_pause_of_its_own(self):
        self.assertEqual(flags.nuclei_service_pause_ms('ssh'), 5500)
        self.assertEqual(flags.nuclei_service_pause_ms('ssh', {'pause_ms': 9000}), 9000)
        self.assertEqual(flags.nuclei_service_pause_ms('smtp'), flags.NUCLEI_SERVICE_BUDGET['pause_ms'])
        self.assertGreaterEqual(flags.NUCLEI_SERVICE_CLASS_PAUSE_MS['ssh'], 5000)  # one failed authentication costs 5 s of OpenSSH source penalty

    def test_a_task_makes_the_budget_gentler_and_never_harsher(self):
        self.assertEqual(flags.nuclei_service_budget({'pause_ms': 2000, 'seconds': 30, 'web_rate': 5}), {'pause_ms': 2000, 'seconds': 30, 'web_rate': 5})
        self.assertEqual(flags.nuclei_service_budget({'pause_ms': 1, 'seconds': 10 ** 6, 'web_rate': 10 ** 6}), flags.NUCLEI_SERVICE_BUDGET)
        self.assertEqual(flags.nuclei_service_budget({'pause_ms': 10 ** 9, 'seconds': 0, 'web_rate': 0}),
                         {'pause_ms': flags.NUCLEI_SERVICE_PAUSE_MAX, **flags.NUCLEI_SERVICE_FLOOR})
        self.assertEqual(flags.nuclei_service_budget({'pause_ms': True, 'seconds': '9', 'web_rate': 1.5}), flags.NUCLEI_SERVICE_BUDGET)
        self.assertEqual(flags.nuclei_service_budget('x'), flags.NUCLEI_SERVICE_BUDGET)

    def test_a_service_run_is_one_template_at_a_time_with_no_credential_template(self):
        selection = flags.nuclei_service_selection('smtp')
        argv = flags.nuclei_service_flags(selection, None)
        at = lambda name: argv[argv.index(name) + 1]  # noqa: E731
        self.assertEqual([at(f) for f in ('-rl', '-c', '-bs', '-pc', '-jsc', '-retries', '-mhe', '-pt')], ['1', '1', '1', '1', '1', '0', '10', 'tcp,javascript'])
        self.assertIn('-nh', argv)
        self.assertEqual(set(at('-etags').split(',')), {'dos', 'default-login', 'bruteforce', 'fuzz', 'intrusive'})  # the exclusion floor, and no credential attempts
        self.assertNotIn('http', at('-pt').split(','))
        self.assertEqual(flags.nuclei_service_flags(flags.nuclei_service_selection('tls'))[flags.nuclei_service_flags(flags.nuclei_service_selection('tls')).index('-pt') + 1], 'ssl')

    def test_the_web_flags_leave_out_the_raw_socket_templates_and_bound_each_host(self):
        argv = flags.nuclei_web_flags()
        self.assertEqual(argv[argv.index('-ept') + 1], 'tcp,javascript')
        self.assertNotIn('-pt', argv)
        self.assertIn('-per-host-rate-limit', argv)
        self.assertEqual(argv[argv.index('-rl') + 1], '25')  # one host never receives the whole global rate (150 a second)
        self.assertEqual([a for a in argv if a not in ('-per-host-rate-limit',) and a != '25'], [a for a in flags.NUCLEI_FLAGS if a != '150'] + ['-ept', 'tcp,javascript'])

    def test_the_global_rate_is_shared_among_the_hosts_of_a_web_pass(self):
        rate = lambda hosts, budget=None: int(flags.nuclei_web_flags(hosts, budget)[flags.nuclei_web_flags(hosts, budget).index('-rl') + 1])  # noqa: E731
        self.assertEqual([rate(1), rate(2), rate(6), rate(10), rate(64)], [25, 25, 25, 15, 2])
        self.assertLessEqual(64 * rate(64), 150)  # a chunk of 64 hosts together stays at the global rate
        self.assertEqual(rate(1, {'web_rate': 5}), 5)
        self.assertEqual(rate(1, {'web_rate': 500}), 25)

    def test_every_service_name_and_port_points_at_a_class_that_exists(self):
        for table in (flags.NUCLEI_SERVICE_NAMES, flags.NUCLEI_SERVICE_PORTS):
            self.assertLessEqual(set(table.values()), {*flags.NUCLEI_SERVICES, flags.NUCLEI_WEB})
        for tags, types in flags.NUCLEI_SERVICES.values():
            self.assertTrue(types and set(types) <= {'tcp', 'javascript', 'ssl'})  # never an http template type
        self.assertTrue(set(flags.NUCLEI_DEFAULT_PORTS) <= set(flags.NUCLEI_SERVICE_PORTS))
        self.assertEqual({flags.NUCLEI_SERVICE_PORTS[p] for p in flags.NUCLEI_DEFAULT_PORTS}, {'web'})

    def test_the_class_of_a_port_comes_from_the_label_then_the_port_number_and_never_defaults_to_web(self):
        self.assertEqual(flags.nuclei_service_class(22, 'web'), 'web')
        self.assertEqual(flags.nuclei_service_class(8080, 'ssh'), 'ssh')
        self.assertEqual(flags.nuclei_service_class(22), 'ssh')
        self.assertEqual(flags.nuclei_service_class(8080), 'web')
        self.assertEqual(flags.nuclei_service_class(5000), 'unknown')  # in no table: not web
        self.assertEqual(flags.nuclei_service_class(22, 'unknown'), 'unknown')
        self.assertEqual(flags.nuclei_service_class(22, 'from-a-newer-server'), 'unknown')

    def test_the_templates_of_a_class_are_narrowed_to_the_tags_the_task_asked_for(self):
        sel = flags.nuclei_service_selection
        self.assertEqual(sel('ssh')['tags'], ['openssh', 'ssh'])
        self.assertEqual(sel('ssh', ['apache', 'ssh'])['tags'], ['ssh'])
        self.assertIsNone(sel('ssh', ['tech']))
        self.assertEqual(sel('tls', ['tls'])['tags'], ['tls'])
        self.assertEqual(sel('tls')['tags'], [])
        self.assertEqual(sel('ssh')['etags'], list(flags.NUCLEI_SERVICE_EXCLUDED_TAGS))

    def test_the_unknown_class_takes_the_network_templates_that_no_class_owns_and_never_http(self):
        selection = flags.nuclei_service_selection('unknown')
        self.assertEqual(selection['types'], ['tcp', 'javascript', 'ssl'])
        self.assertTrue({'ssh', 'ftp', 'smtp', 'postgresql', 'redis', 'smb'} <= set(selection['etags']))  # a class's templates are left to its own ports
        self.assertTrue(set(flags.NUCLEI_SERVICE_EXCLUDED_TAGS) <= set(selection['etags']))
        self.assertEqual(flags.nuclei_service_selection('unknown', ['rce'])['tags'], ['rce'])
        self.assertNotIn('http', selection['types'])
        self.assertNotIn('-tags', flags.nuclei_service_listing_flags(selection))

    def test_labels_are_keyed_the_same_way_whatever_the_spelling(self):
        key = flags.nuclei_label_key
        self.assertEqual(key('WWW.Example.COM.:0443'), ('www.example.com', 443))
        self.assertEqual(key('[2001:DB8:0::1]:22'), ('2001:db8::1', 22))
        self.assertEqual(key('192.0.2.1:22'), ('192.0.2.1', 22))
        self.assertEqual(key('b\u00fccher.example:22'), ('xn--bcher-kva.example', 22))
        for not_a_port in ('example.com', 'https://example.com:22', '2001:db8::1', 'example.com:x', ':22', 5):
            self.assertIsNone(key(not_a_port))
