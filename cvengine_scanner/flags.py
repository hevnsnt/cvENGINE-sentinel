"""The scan policy both sides of the wire share: the command-line flags every tool runs with, the UDP port list, ``host_of`` and the
limits that mirror the cvENGINE server's own. The Sentinel's runners (``client.tools``) build their argv from these, and the server builds its
own targets and reads results with the same values, so a flag changed here changes it for both.

Nothing in here runs a tool or reads the environment: it is data and one pure function.
"""
from urllib.parse import urlparse

MAX_TARGETS = 64  # matches agentapi.sentinel_broker.MAX_ADDRESSES: a task never names more than this many

# -n: no reverse DNS. parse_nmap_xml never reads host names, and the targets are already resolved addresses.
NMAP_FLAGS = ['-Pn', '-n', '-sV', '--version-intensity', '5', '-O', '--osscan-limit', '-T4', '--open',
              '--top-ports', '1000', '--host-timeout', '8m', '--max-retries', '2']
NAABU_FLAGS = ['-p', '-', '-rate', '1000', '-retries', '2', '-c', '25', '-warm-up-time', '2', '-json', '-silent', '-nc']
# -omit-raw: no raw request/response pairs in the output (parse_nuclei_jsonl never reads them, and they are most of its size).
# -etags dos: the exclusion floor for every nuclei kind. Denial-of-service templates never run, whatever tags the server asks for.
NUCLEI_FLAGS = ['-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150', '-c', '40', '-timeout', '10', '-retries', '1', '-omit-raw',
                '-etags', 'dos']

# The OS guess only holds when nmap's probes cross the network unchanged. Docker Desktop and OrbStack run containers in a VM behind a proxy that
# answers probes itself, so the guess describes the gateway: the server must not store it (mirrors cveFeed.os_detection.KERNEL_MARKERS).
KERNEL_MARKERS = ('linuxkit', 'microsoft', 'wsl2', 'orbstack')

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

UDP_PORTS = (53, 67, 68, 69, 123, 137, 161, 500, 514, 623, 1194, 1812, 1813, 1900, 4500, 5060, 5353, 11211)
UDP_NSE_SCRIPTS = ('snmp-sysdescr', 'snmp-info', 'ntp-info', 'upnp-info', 'ipmi-version')

# Same options cveFeed.wpscan_scan.wpscan_args builds for a passive pass: mixed detection, no TLS verification (the
# target is whatever the server named, already vetted there), a bounded max-scan-duration so a slow site still
# reports what it found before the process would be killed.
WPSCAN_ARGS = ['--format', 'json', '--no-banner', '--random-user-agent', '--throttle', '100', '--request-timeout', '30',
               '--connect-timeout', '15', '--detection-mode', 'mixed', '--plugins-detection', 'passive',
               '--themes-detection', 'passive', '--disable-tls-checks', '--enumerate', 'vp,vt,cb,dbe,u1-5']

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
