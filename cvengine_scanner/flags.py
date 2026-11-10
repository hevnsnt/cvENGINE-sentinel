"""The scan policy both sides of the wire share: the command-line flags every tool runs with (and the builders that put them together), the
reviewed NSE scripts, the UDP port list, the extra and closed probe ports, the nuclei exclusion floor (``-etags dos``), ``host_of`` and the
limits that mirror the cvENGINE server's own. The Sentinel's runners (``client.tools``) build their argv from these, and the server builds its
local runs, its targets and reads results with the same values, so a flag changed here changes it for both.

Nothing in here runs a tool or reads the environment: it is data and pure functions. A setting the server reads from its environment (the UDP
port list, the packet rate) is passed in by the caller.
"""
import re
from urllib.parse import urlparse

MAX_TARGETS = 64  # matches agentapi.sentinel_broker.MAX_ADDRESSES: a task never names more than this many

NAABU_FLAGS = ['-p', '-', '-rate', '1000', '-retries', '2', '-c', '25', '-warm-up-time', '2', '-json', '-silent', '-nc']
# --- nuclei ------------------------------------------------------------------------------------------------------------
NUCLEI_SEVERITIES = 'info,low,medium,high,critical'  # what a run reports when the task names no severities ('unknown' is left out)
# The exclusion floor for every nuclei run, local or on a Sentinel: denial-of-service templates never run, whatever tags were asked for.
NUCLEI_EXCLUDED_TAGS = ('dos',)
NUCLEI_EXCLUDE_FLAGS = ['-etags', ','.join(NUCLEI_EXCLUDED_TAGS)]
_NUCLEI_RUN = ['-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150', '-c', '40', '-timeout', '10', '-retries', '1']
# A Sentinel's run. The raw request and response are kept (no -omit-raw): parse_nuclei_jsonl keeps them, clipped and with credentials redacted,
# as the evidence of a finding (review M2). The severity filter is the task's own (client.tools adds -severity only when the task names one).
NUCLEI_FLAGS = [*_NUCLEI_RUN, *NUCLEI_EXCLUDE_FLAGS]
# The server's local run: the default severities up front, raw pairs kept (it stores the matching request and response).
NUCLEI_BASE_FLAGS = ['-severity', NUCLEI_SEVERITIES, *_NUCLEI_RUN, *NUCLEI_EXCLUDE_FLAGS]
# A lighter run for when the normal one was stopped for lack of memory: fewer hosts in parallel, a gentler rate.
NUCLEI_LIGHT_FLAGS = {'-rl': '50', '-c': '10'}
NUCLEI_TECH_FLAGS = ['-tags', 'tech']
NUCLEI_DEFAULT_PORTS = (80, 443)  # the ports a bare host or address is probed on by the web templates


def nuclei_flags(tags=None, profile='normal', severities=None, tech=False, templates_dir=None, secret_file=None, proxy_args=()):
    """The nuclei flags of the server's local run (``cveFeed.nuclei_scan``), optionally narrowed to ``tags`` (an iterable of tag names the caller
    already checked against its allowlist, ``cveFeed.nuclei_templates``). ``profile='light'`` lowers concurrency and rate for a memory-constrained
    retry. ``severities`` narrows the severity list, and ``tech`` is the light technology-fingerprint pass (the http/technologies templates, info
    severity). ``secret_file`` (the path of a nuclei secrets file) makes it an authenticated run: nuclei reads the headers from that file, so no
    value is ever on the command line, and ``-dr`` stops it following redirects, which could carry a header to another host. ``proxy_args`` is the
    egress proxy's argument list (empty for a direct run). ``-etags dos`` is always there."""
    flags = list(NUCLEI_BASE_FLAGS)
    if templates_dir:
        flags += ['-t', templates_dir]
    if severities or tech:
        flags[flags.index('-severity') + 1] = ','.join(severities) if severities else 'info'
    if profile == 'light':
        for flag, value in NUCLEI_LIGHT_FLAGS.items():
            flags[flags.index(flag) + 1] = value
        flags += ['-bs', '10']
    if tech:
        flags += NUCLEI_TECH_FLAGS
    elif tags:
        flags += ['-tags', ','.join(sorted(tags))]
    if secret_file:
        flags += ['-sf', secret_file, '-dr']
    return flags + list(proxy_args)


# The OS guess only holds when nmap's probes cross the network unchanged. Docker Desktop, WSL2, OrbStack and boot2docker run containers in a VM
# behind a proxy that answers probes itself, so the guess describes the gateway: neither side stores it. The server reads its own kernel release
# against this list (cveFeed.os_detection), a Sentinel its own (client.tools.os_guess_reliable).
KERNEL_MARKERS = ('linuxkit', 'moby', 'microsoft', 'wsl2', 'orbstack', 'boot2docker')

# --- nmap: the reviewed NSE scripts, the fingerprint pass, the extra and closed probe ports ------------------------------
# NSE scripts that read what a service says about itself and its host. All are in nmap's safe or discovery categories and none exploits
# anything: banner (the raw greeting), ssh-hostkey and ssh2-enum-algos (SSH server identity), ssl-cert (certificate subject, issuer, validity),
# http-headers, http-title, http-server-header (the Server header when -sV could not read it) and http-generator (the generator meta tag of the
# front page: one GET), ftp-anon (whether anonymous login is accepted, and the top level listing it shows), rdp-ntlm-info (the OS build, host and
# domain names RDP's NTLM challenge reveals, without logging in), rdp-enum-encryption (which RDP security layers the server accepts, so a server
# that does not insist on NLA is visible), smb-os-discovery and nbstat (OS, host and domain names over SMB and NetBIOS). mysql-info,
# mongodb-info, redis-info, memcached-info and couchdb-stats read each database's own pre-authentication greeting for its version and build
# details; ms-sql-ntlm-info reads the same NTLM challenge rdp-ntlm-info does, over SQL Server's own protocol; ms-sql-info asks the SQL Server
# Browser service, once per host, which instances exist and their exact version. None of these sends a credential or reads a
# credential-protected value. Scripts only run on ports whose service matches.
NSE_SCRIPTS = ('banner', 'ssh-hostkey', 'ssh2-enum-algos', 'ssl-cert', 'http-headers', 'http-title', 'http-server-header', 'http-generator',
               'ftp-anon',
               'rdp-ntlm-info', 'rdp-enum-encryption', 'smb-os-discovery', 'nbstat', 'mysql-info', 'ms-sql-info',
               'ms-sql-ntlm-info', 'mongodb-info', 'redis-info', 'memcached-info', 'couchdb-stats')
NSE_FLAGS = ['--script', ','.join(NSE_SCRIPTS), '--script-timeout', '30s']
# The UDP sweep adds five scripts, each reviewed as read-only: snmp-sysdescr (one SNMP GET of sysDescr and the uptime with the default community
# "public": a reply is proof that community works), snmp-info (the SNMPv3 engine ID, the probe -sV sends), ntp-info (the time and the "readvar"
# variables: version, system, processor), upnp-info (one SSDP M-SEARCH: the server string and device description) and ipmi-version (one Get
# Channel Authentication Capabilities request: the IPMI version and the authentication types offered, no login). ntp-monlist is deliberately
# absent: nmap files it under "intrusive" and says the target records the request. Together with nbstat (UDP 137) they only run on UDP ports
# whose service matches.
UDP_NSE_SCRIPTS = ('snmp-sysdescr', 'snmp-info', 'ntp-info', 'upnp-info', 'ipmi-version')
# nmap's own documentation says a version scan "automatically executes the scripts in the version category" (rpcinfo, hnap-info, vmware-version,
# skypev2-version, and more) whenever -sV runs, regardless of --script; these "cannot be selected explicitly". Their output is still written to
# -oX. None of them has been reviewed the way NSE_SCRIPTS has, so ``reviewed_scripts`` drops anything -sV smuggled in before it is stored.
NSE_SCRIPT_SET = frozenset(NSE_SCRIPTS) | frozenset(UDP_NSE_SCRIPTS)


def reviewed_scripts(scripts):
    """``scripts`` (``{script id: output}``) with every id outside NSE_SCRIPT_SET dropped."""
    return {sid: text for sid, text in (scripts or {}).items() if sid in NSE_SCRIPT_SET}


# The fingerprint pass (the nmap kind): service detection at intensity 7, the OS guess, the reviewed scripts. The ports come last: the
# task's own list (nmap_pass_flags), or the top thousand when it names none.
TOP_PORTS = 1000
NMAP_HOST_TIMEOUT = '8m'  # nmap gives up on a host after this; the host is then flagged timed_out, never read as clean (review H3)
_FAST_SCAN_FLAGS = ['-sV', '--version-intensity', '7', '-O', '--osscan-limit', '-Pn', '-T4', '--max-retries', '2', '--min-hostgroup', '32',
                    '--defeat-rst-ratelimit', *NSE_FLAGS]
NMAP_FAST_FLAGS = [*_FAST_SCAN_FLAGS, '--top-ports', str(TOP_PORTS)]  # the top thousand, as the server's own fingerprint pass runs it
NMAP_FULL_PORT_FLAGS = ['-p-', '--open', '-T4', '-Pn']
# nmap's --top-ports ranks ports by how often they are open across the internet, not by how dangerous an open one is, so the thousand it picks
# leave out most of the services an exposure check cares about (Redis is 2742th, MongoDB 2169th, the Docker API 3217th, kubelet is not ranked
# at all). The fingerprint pass scans the top thousand plus these, about 3% more probes.
EXTRA_PORTS = (
    2181, 2375, 2376, 2379, 2380,     # Zookeeper, Docker API (plain and TLS), etcd
    3100, 4369, 5601, 5672, 5984,     # Loki, Erlang epmd, Kibana, AMQP, CouchDB
    6379, 6380, 6443, 7474, 8086,     # Redis, Kubernetes API, Neo4j, InfluxDB
    8161, 8200, 8500, 8834, 8983,     # ActiveMQ console, Vault, Consul, Nessus, Solr
    9042, 9092, 9100, 9200, 9300,     # Cassandra, Kafka, node exporter, Elasticsearch HTTP and transport
    9443, 10250, 10255, 11211, 15672,  # alternate HTTPS, kubelet, kubelet read-only, Memcached, RabbitMQ console
    16686, 27017, 27018, 50070, 61616, 1883, 8883,  # Jaeger, MongoDB, Hadoop, ActiveMQ, MQTT (plain and TLS)
)
# nmap's OS detection (-O --osscan-limit) needs one open and one CLOSED TCP port, and a pass over naabu's open ports alone has no closed one, so
# the host was never OS-fingerprinted. These unassigned ports are nearly always answered with a reset when the host answers at all: one is
# enough, two tolerate a firewall that drops one of them.
CLOSED_PROBE_PORTS = (1, 3)


def port_argument(ports):
    """A compact nmap ``-p`` argument ("22,80,8000-8010") for a set of ports."""
    ports = sorted(set(ports))
    parts, start, prev = [], None, None
    for port in ports + [None]:
        if start is None:
            start = prev = port
        elif port is not None and port == prev + 1:
            prev = port
        else:
            parts.append(str(start) if start == prev else f'{start}-{prev}')
            start = prev = port
    return ','.join(parts)


MAX_NMAP_PORTS = 4096  # the most ports one fingerprint task names (the contract's bound on the nmap target's ports)


def nmap_pass_flags(ports=None):
    """The flags of the fingerprint pass (the address goes after them). With ``ports`` (what naabu found, from the server) the pass scans
    those plus EXTRA_PORTS and CLOSED_PROBE_PORTS: the extended set the pipeline is meant to fingerprint, and the closed port OS detection
    needs. Without ``ports`` it scans nmap's top thousand, as NMAP_FAST_FLAGS does. ``-n`` (no reverse DNS, the targets are addresses),
    ``--open`` and the host timeout are always there."""
    if ports is None:
        port_flags = ['--top-ports', str(TOP_PORTS)]
    else:
        if not isinstance(ports, (list, tuple, set, frozenset)) or len(ports) > MAX_NMAP_PORTS:
            raise ValueError(f'a fingerprint task names at most {MAX_NMAP_PORTS} ports')
        if any(isinstance(p, bool) or not isinstance(p, int) or not 0 < p < 65536 for p in ports):
            raise ValueError('a port must be a whole number from 1 to 65535')
        port_flags = ['-p', port_argument({*ports, *EXTRA_PORTS, *CLOSED_PROBE_PORTS})]
    return [*_FAST_SCAN_FLAGS, '-n', '--open', '--host-timeout', NMAP_HOST_TIMEOUT, *port_flags]


# The time one task of a kind may take, by how many hosts it names: ``(smallest, seconds per host, largest)``. nmap's numbers are the ones
# the Sentinel has always used. naabu's come from a measured full sweep: 65,535 SYN probes at 1000 per second took 138 s on one loopback
# host (proofs/scan3-lab/naabu-live.txt), so one host gets 150 s and a task of more than 24 hosts is split (review H5). The Sentinel and the
# server both read a task's limit here, so neither gives up a task the other is still running (review M7).
TASK_LIMITS = {'nmap': (600, 90, 3600), 'naabu': (900, 150, 3600)}
NAABU_MAX_SECONDS = TASK_LIMITS['naabu'][2]


def task_seconds(kind, count, requested=None):
    """Seconds one ``kind`` task over ``count`` hosts may take. ``requested``, the task's own time limit when the server sends one, is used
    inside the kind's range only: a boolean, a float or text is no time at all, and anything out of range is held to the nearest end."""
    smallest, per_host, largest = TASK_LIMITS[kind]
    if isinstance(requested, int) and not isinstance(requested, bool):
        return min(largest, max(smallest, requested))
    return min(largest, max(smallest, per_host * max(1, int(count))))


def hosts_per_task(kind):
    """How many hosts one ``kind`` task can cover inside its largest time limit: the most a server should put in one chunk for it."""
    _smallest, per_host, largest = TASK_LIMITS[kind]
    return max(1, largest // per_host)


# The version probe's nmap run on one port (the server's cveFeed.probes): the safe scripts for the service it answered with, all of them in
# NSE_SCRIPTS.
PROBE_NMAP_SCRIPTS = {'http': 'http-server-header,http-headers,http-generator,http-title,ssl-cert,banner', 'ssh': 'ssh2-enum-algos,ssh-hostkey,banner',
                      'mysql': 'mysql-info', 'redis': 'redis-info', 'memcached': 'memcached-info', 'mongodb': 'mongodb-info',
                      'ms-sql': 'ms-sql-info', 'smtp': 'banner', 'ftp': 'banner,ftp-anon', 'imap': 'banner', 'pop3': 'banner'}


def probe_nmap_flags(port, service=''):
    """The flags of the version probe's nmap run on one ``port`` (the address goes last, after these): a full version scan of that port and the
    reviewed scripts for ``service`` (``banner`` when it is none of the known ones), XML to standard output."""
    name = re.sub(r'^(ssl/|tcp)', '', str(service or '').lower())
    key = next((k for k in PROBE_NMAP_SCRIPTS if name.startswith(k)), 'http' if name.startswith('http') or name == 'https' else '')
    scripts = PROBE_NMAP_SCRIPTS.get(key, 'banner')
    return ['-sV', '--version-all', '-Pn', '-p', str(int(port)), '--script', scripts, '--script-timeout', '20s', '--host-timeout', '90s',
            '-oX', '-']

DISCOVER_FLAGS = ['-sn', '-T4', '-PE', '-PP', '-PS21,22,23,25,80,135,443,445,3389,8080', '-PA80,443', '-PU53,161', '--max-retries', '2',
                  '--host-timeout', '30s']
MAX_DISCOVER_ADDRESSES = 512  # a /23: the server sweeps in /24 chunks, so anything larger is not a task this server would send
MAX_DISCOVER_HOSTS = 512

MAX_OPEN_PER_IP = 500  # an address with more "open" ports than this is a tarpit or a firewall that accepts everything

def host_of(line):
    """Hostname or IP a nuclei result line names (``host`` may be a URL or host:port); mirrors
    ``cveFeed.nuclei_scan.host_of`` so a Sentinel-reported finding names the same host a local run would."""
    raw = next((v for v in (line.get('host'), line.get('ip')) if isinstance(v, str) and v), '').strip()
    try:
        if '://' in raw:
            return (urlparse(raw).hostname or '').lower()
    except ValueError:
        return ''
    if raw.count(':') == 1:
        return raw.rsplit(':', 1)[0].strip('[]').lower()
    return raw.strip('[]').lower()

# Same options cveFeed.testssl_scan.BASE_ARGS uses: protocols, cipher categories, server defaults and certificate,
# vulnerabilities, forward secrecy. --nodns none: the task already names a vetted ip, never resolved again here.
TESTSSL_FLAGS = ['--quiet', '--warnings', 'off', '--color', '0', '--nodns', 'none', '--connect-timeout', '15',
                 '--openssl-timeout', '15', '--overwrite', '-p', '-s', '-S', '-U', '-f']

# --- nmap -sU: the UDP exposure sweep --------------------------------------------------------------------------------------
# The curated list: what matters for exposure, not what is common (each is described in the server's docs/PIPELINE.md).
UDP_PORTS = (53, 67, 68, 69, 123, 137, 161, 500, 514, 623, 1194, 1812, 1813, 1900, 4500, 5060, 5353, 11211)
UDP_VERSION_INTENSITY = '3'  # nmap's default is 7; 3 still tries the probes registered for NTP, SNMP, SSDP and DNS
UDP_SCRIPT_TIMEOUT = '30s'
UDP_MAX_RATE = 20  # packets per second


def udp_nmap_flags(ports=UDP_PORTS, max_rate=UDP_MAX_RATE):
    """The flags of one UDP sweep (the address goes after them): UDP scan, service detection at a low intensity (it probes only the ports that
    did not say closed), no host discovery and no DNS, one retry, a low packet rate, and only the reviewed scripts (UDP_NSE_SCRIPTS plus
    nbstat). The server passes its own ``CVENGINE_UDPSCAN_PORTS`` and ``CVENGINE_UDPSCAN_MAX_RATE``; a Sentinel runs the defaults."""
    scripts = ','.join(('nbstat', *UDP_NSE_SCRIPTS))
    return ['-sU', '-sV', '--version-intensity', UDP_VERSION_INTENSITY, '-Pn', '-n', '--max-retries', '1', '--max-rate', str(max_rate),
            '--script', scripts, '--script-timeout', UDP_SCRIPT_TIMEOUT, '-p', 'U:' + ','.join(str(p) for p in ports)]

# Same options cveFeed.wpscan_scan.wpscan_args builds for a passive pass: mixed detection, no TLS verification (the
# target is whatever the server named, already vetted there), a bounded max-scan-duration so a slow site still
# reports what it found before the process would be killed.
WPSCAN_ARGS = ['--format', 'json', '--no-banner', '--random-user-agent', '--throttle', '100', '--request-timeout', '30',
               '--connect-timeout', '15', '--detection-mode', 'mixed', '--plugins-detection', 'passive',
               '--themes-detection', 'passive', '--disable-tls-checks', '--enumerate', 'vp,vt,cb,dbe,u1-5']

# The thorough pass (kind ``wpscan_thorough``): the same base options, but plugin and theme detection in mixed mode asks the site for every plugin
# and theme slug WPScan knows (about 170,000 requests, hours per site), and the timthumb check. A fixed list for this kind: nothing in a task
# changes it, only the time limit does (``thorough_timeout``).
WPSCAN_THOROUGH_ARGS = ['--format', 'json', '--no-banner', '--random-user-agent', '--throttle', '100', '--request-timeout', '30',
                        '--connect-timeout', '15', '--detection-mode', 'mixed', '--plugins-detection', 'mixed',
                        '--themes-detection', 'mixed', '--disable-tls-checks', '--enumerate', 'ap,at,tt']
WPSCAN_THOROUGH_DEFAULT_SECONDS = 12 * 3600  # the server's default; the contract's range for a task's timeout_seconds is 600 to 86400
WPSCAN_THOROUGH_MIN_SECONDS = 600
WPSCAN_THOROUGH_MAX_SECONDS = 24 * 3600


def thorough_timeout(value):
    """The seconds one thorough run may take: the task's ``timeout_seconds`` when it is a whole number, held to the contract's range (a boolean, a
    float, text or nothing is the default). The run ends its own scan 30 seconds before this and reports what it read."""
    if isinstance(value, bool) or not isinstance(value, int):
        return WPSCAN_THOROUGH_DEFAULT_SECONDS
    return min(WPSCAN_THOROUGH_MAX_SECONDS, max(WPSCAN_THOROUGH_MIN_SECONDS, value))


# wafw00f, the options cveFeed.waf_scan.run_wafw00f builds: -a tries every fingerprint instead of stopping at the first, -r does not follow
# redirects, and the report is JSON in a file the runner names with -o. No version or confidence comes out of it, so none is reported.
WAFW00F_TIMEOUT = 60  # seconds one site's check may take before it is killed
WAFW00F_REQUEST_TIMEOUT = 15  # wafw00f's own per-request timeout (-T), cut to the run's timeout when that is shorter
WAF_NAME_LEN = 100  # a product or manufacturer name is cut to this: the ``waf`` result's bound in sentinel_contract.json
MAX_WAF_PRODUCTS = 20  # the most products one site's result names (the contract's list bound)
GENERIC_WAF_NAMES = frozenset({'generic', 'unknown', 'none', ''})  # something blocks, or nothing does: no product is named


def wafw00f_flags(timeout):
    """The flags of one wafw00f run that may take ``timeout`` seconds, ``-T`` (a request's timeout) never longer than that."""
    return ['-a', '-r', '-T', str(min(timeout, WAFW00F_REQUEST_TIMEOUT)), '--no-colors', '-f', 'json']


# nmap_full: every TCP port of one address, open ports only (cveFeed.nmap_scan.FULL_PORT_FLAGS and HOST_TIMEOUT_FULL). -n: the target is an address.
NMAP_FULL_FLAGS = [*NMAP_FULL_PORT_FLAGS, '-n', '--host-timeout', '10m']
# nmap_verify: service detection on the named ports of one address; the intensity and the NSE scripts come from the task, each checked here.
NMAP_VERIFY_FLAGS = ['-sV', '-Pn', '-n']
# The NSE scripts an nmap_verify task may name are NSE_SCRIPTS above, the server's reviewed list: a name not on it is refused, whatever the server
# sent, so a task can never run an intrusive or a brute-force script.
NSE_SCRIPT_TIMEOUT = '20s'
MAX_VERIFY_PORTS = 64

# path_probe: whether the path a scan leaves from answers a malformed segment (cveFeed.path_probe). nmap sends both segments, since only nmap holds
# the raw-socket capability in the Sentinel image: a plain SYN (-sS) and nmap's T7 probe, FIN+PSH+URG (-sF --scanflags FINPSHURG). --reason says
# whether a reset came back. One closed port per address, no retries.
PATH_PROBE_PLAIN = ['-sS', '-Pn', '-n', '--reason', '--max-retries', '0', '--host-timeout', '15s']
PATH_PROBE_ODD = ['-sF', '--scanflags', 'FINPSHURG', '-Pn', '-n', '--reason', '--max-retries', '0', '--host-timeout', '15s']
MAX_PATH_TARGETS = 8  # cveFeed.path_probe.MAX_TARGETS

# nuclei_validate: an AI-written or approved template, checked or run exactly as cveFeed.templategen does on the server.
NUCLEI_VALIDATE_FLAGS = ['-validate', '-duc', '-silent']
NUCLEI_FIXTURE_FLAGS = ['-jsonl', '-silent', '-duc', '-ni', '-rl', '2', '-timeout', '2', '-retries', '0']
NUCLEI_TEMPLATE_FLAGS = ['-jsonl', '-silent', '-duc', '-ni', '-rl', '10', '-timeout', '10', '-retries', '0']
MAX_TEMPLATE_BYTES = 200_000  # cveFeed.validation.MAX_INSTALLED_TEMPLATE_BYTES: the contract's bound on the template text
