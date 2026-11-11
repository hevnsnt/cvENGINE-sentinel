"""Everything the daemon reads from its environment, in one place, each with a sane default."""
import ipaddress
import logging
import os
import platform
import socket
from urllib.parse import urlsplit

from cvengine_scanner import contract

CAPABILITIES = ['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep', 'testssl', 'nmap_udp', 'wpscan', 'openvas', 'waf', 'bbot_discovery',
                'http_probe', 'dns_resolve',
                # contract 3: asked for only from a server whose contract has them (server_knows). path_probe and nuclei_validate go to the
                # install's built-in scanner while it has one; with none, a contract-4 server offers them to the project's own Sentinels
                # (external_since), and this one runs an AI-written check only after the checks in client/daemon.py and tools._verified_template.
                'nmap_full', 'nmap_verify', 'node2shell', 'rdp_shot', 'db_probe', 'path_probe', 'nuclei_validate',
                'secrets_scan', 'alive_check', 'bucket_check', 'vhost_probe', 'subdir_probe', 'route_probe', 'supplier_check', 'hygiene_check', 'dangling_dns_check', 'identity_check', 'web_screenshot', 'wpscan_thorough', 'page_read', 'ssh_probe',
                'route_probe_signed']  # route_probe_signed: the built-in scanner's alone (runnable_kinds drops it elsewhere); it reads a stored sign-in
CONTRACT_VERSION = contract.version()  # the result contract this Sentinel speaks: the packaged sentinel_contract.json's, declared at registration and every heartbeat
KIND_SINCE = contract.load()['kind_since']  # the contract version that introduced each kind (waf: 2, bbot_discovery, http_probe, dns_resolve, secrets_scan, alive_check, bucket_check, vhost_probe, subdir_probe, route_probe, supplier_check, hygiene_check, dangling_dns_check, identity_check, page_read and ssh_probe: 3)
PRE_CONTRACT_SERVER = 1  # what a server speaks when its replies name no contract: cvENGINE 1.3 and older, whose kinds are the version 1 kinds
INTERNAL_CAPABILITY = 'network:internal'  # mirrors agentapi.sentinel_broker.INTERNAL_CAPABILITY
INTERNAL_KINDS = ['discover']  # scan kinds only an internal Sentinel declares: the server sweeps a declared private range only through one
HEARTBEAT_SECONDS = 60  # matches agentapi.agent_broker.HEARTBEAT_SECONDS; see that constant if it ever changes
DEFAULT_TOKEN_PATH = '/var/lib/cvengine-sentinel/token.json'
KNOWN_KINDS = CAPABILITIES + INTERNAL_KINDS
DEFAULT_POLL_WAIT = 15  # seconds the long poll (sentinel/tasks/next) may block per call
SHUTDOWN_GRACE_SECONDS = 20  # how long a SIGTERM waits for in-flight tasks to finish before releasing them
BUILTIN_NAME = 'CVEngine Scanner'  # what the install's own scanner is called; the server forces the same name at its enrollment
# What the built-in scanner can do beyond the kinds, reported in ``info.features``: ``secret_read`` (signed-in nuclei through the server's single-use read
# of a stored credential, client/signed_in.py) and ``vantage`` (it applies the server's egress proxy and private-target settings, ``vantage()``). The
# server offers that work, and stops warning about the vantage point, only to a built-in scanner that says so.
BUILTIN_FEATURES = ('secret_read', 'vantage')
# What every other Sentinel reports in ``info.features``: ``bbot_keys`` says this client reads a bbot discovery task's API keys through the single-use
# secret read, keeps them only in a private file for the run, and masks them in everything it reports. A server sends keys only to a Sentinel that says so
# (and the owner has not switched it off); an old Sentinel does not say it and never gets them. Optional: a server that does not know it ignores it.
EXTERNAL_FEATURES = ('bbot_keys',)

logger = logging.getLogger('sentinel.config')


def _env(name, default=None):
    value = os.environ.get(name)
    return value if value not in (None, '') else default


# Settings the server may manage (agentapi.sentinel_settings.SETTINGS): for most, the most recent change, here or in cvENGINE, wins. ``local_settings`` is
# what this machine's own configuration says and is what gets reported; ``_overrides`` holds what the server told this Sentinel to run with. Two are this
# machine's policy, which the server can tighten but never loosen: a kind disabled here stays disabled, and a local self-update setting is a ceiling.
SELF_UPDATE = ('off', 'manual', 'automatic')  # in rising order: the effective value is the lower of this machine's and the server's
_overrides = {}  # replaced whole, never mutated, so a reader on another thread sees either the old settings or the new ones
_server_contract = PRE_CONTRACT_SERVER  # the contract the server last said it speaks; until a reply says, the oldest, so nothing it may not know is asked for


def set_server_contract(reply):
    """Note the contract the server speaks from a registration or heartbeat answer (``contract: {version, min_supported}``). A reply that is an
    object without it comes from a server older than the contract (cvENGINE 1.3), which speaks version 1. Returns the version now in force."""
    global _server_contract
    if isinstance(reply, dict):
        info = reply.get('contract')
        version = info.get('version') if isinstance(info, dict) else None
        if isinstance(version, int) and not isinstance(version, bool) and version >= 1:
            _server_contract = version
        elif 'contract' not in reply:
            _server_contract = PRE_CONTRACT_SERVER
    return _server_contract


def server_contract():
    return _server_contract


def server_knows(kind):
    """Whether the server's contract has ``kind``. A server answers a poll that names a kind it does not know with a 400 (cvENGINE 1.3 for
    ``waf``), so such a kind is never asked for, declared or reported. A kind the packaged contract does not list counts as the newest."""
    return KIND_SINCE.get(kind, CONTRACT_VERSION) <= _server_contract
_warned_disabled = set()  # unknown CVENGINE_SENTINEL_DISABLE entries already logged, so each is reported once, not at every poll


def clean_settings(raw):
    """The settings in ``raw`` (from the server) that are well formed, clipped to what this client accepts. They are data, never commands:
    anything else is dropped."""
    out = {}
    if not isinstance(raw, dict):
        return out
    name = raw.get('name')
    if isinstance(name, str) and name.strip():
        out['name'] = ''.join(c for c in name if c.isprintable()).strip()[:100] or None
        if out['name'] is None:
            del out['name']
    if raw.get('network') in ('external', 'internal'):
        out['network'] = raw['network']
    if raw.get('profile') in ('full', 'light'):
        out['profile'] = raw['profile']
    kinds = raw.get('disabled_kinds')
    if isinstance(kinds, list):
        out['disabled_kinds'] = sorted({k for k in kinds if isinstance(k, str) and k in KNOWN_KINDS})
    value = raw.get('max_concurrent')
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_AUTO_CONCURRENT:
        out['max_concurrent'] = value
    if raw.get('self_update') in SELF_UPDATE:
        out['self_update'] = raw['self_update']
    vantage = clean_vantage(raw.get('vantage'))
    if vantage:
        out['vantage'] = vantage
    return out


PROXY_SCHEMES = ('http', 'https', 'socks5', 'socks5h')  # what Settings > Proxy accepts on the server (cveFeed.egress_proxy.SCHEMES)
MAX_PROXIES = 20
# The private space a built-in scanner may be told to scan, as the server's own scans may: the tailnet when the Tailscale sidecar is on, or every private
# range with CVENGINE_ALLOW_PRIVATE_TARGETS. Nothing outside these is ever accepted (loopback, link-local and the rest stay refused by the scope floor).
PRIVATE_SPACE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7'))


def _proxy_url(value):
    """A proxy URL from Settings > Proxy as the server sent it, or None. The URL may carry a login: it is kept as is and never logged."""
    if not isinstance(value, str) or not value or len(value) > 400 or any(not c.isprintable() or c.isspace() for c in value):
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in PROXY_SCHEMES or not parts.hostname or parts.path not in ('', '/') or parts.query or parts.fragment or port == 0:
        return None
    return value


def _private_range(value):
    try:
        net = ipaddress.ip_network(str(value), strict=True)
    except ValueError:
        return None
    return str(net) if any(net.version == p.version and net.subnet_of(p) for p in PRIVATE_SPACE) else None


def clean_vantage(raw):
    """Where the server's own scans leave from, as it tells its built-in scanner (``vantage`` in the settings reply): ``proxies`` (Settings > Proxy, in
    use), ``bypass`` (destinations that never go through a proxy: host names, ``.suffix`` domains, addresses and networks), ``proxy_private`` (private
    addresses go through the proxy too) and ``private_ranges`` (private networks it may scan). Dropped when malformed; honoured only by a built-in scanner."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    listed = raw.get('proxies') if isinstance(raw.get('proxies'), list) else []
    proxies = [url for url in (_proxy_url(v) for v in listed[:MAX_PROXIES]) if url]
    if proxies:
        out['proxies'] = proxies
        bypass = raw.get('bypass')
        if isinstance(bypass, list):
            out['bypass'] = [b.strip().lower() for b in bypass[:200] if isinstance(b, str) and b.strip() and len(b) <= 260 and b.isprintable()]
        out['proxy_private'] = raw.get('proxy_private') is True
    ranges = raw.get('private_ranges')
    if isinstance(ranges, list):
        clean = [r for r in (_private_range(v) for v in ranges[:20]) if r]
        if clean:
            out['private_ranges'] = clean
    return out


def builtin():
    """CVENGINE_SENTINEL_BUILTIN=1: this is cvENGINE's own built-in scanner, the compose service next to the server. It is named ``BUILTIN_NAME``,
    never updates itself (the server's updater swaps its image), runs no OpenVAS, reports ``info.builtin``, re-enrols by itself from
    ``CVENGINE_SENTINEL_BLOB_FILE`` when the server stops accepting its token, and applies the server's vantage settings. Never set on any other Sentinel:
    those settings would then reach a machine the server does not run on."""
    return (_env('CVENGINE_SENTINEL_BUILTIN') or '').strip().lower() in ('1', 'true', 'yes', 'on')


def vantage():
    """The vantage settings the server sent (``clean_vantage``), or ``{}``: only a built-in scanner applies them. An external Sentinel scans from
    its own network, with its own floor, and a server can neither send it through a proxy nor unlock private space for it."""
    return dict(_overrides.get('vantage') or {}) if builtin() else {}


def private_ranges():
    """The private networks this Sentinel may scan although it is not internal: those the server's vantage settings name (a built-in scanner only)."""
    return [ipaddress.ip_network(r) for r in vantage().get('private_ranges', [])]


_deny_cache = {'text': None, 'value': ((), [])}


def deny_ranges():
    """``(networks, bad)``: this machine's own deny list, ``CVENGINE_SENTINEL_DENY_RANGES`` (comma separated CIDRs; a bare address is one host). It protects addresses
    even when the server is old and sends no list of its own. Read at every call so an operator's change needs no restart of anything but the container's
    environment; ``bad`` names entries that are not a network (they make every task refused, never silently ignored)."""
    text = os.environ.get('CVENGINE_SENTINEL_DENY_RANGES', '')
    if _deny_cache['text'] != text:
        from cvengine_scanner import scope as _floor
        _deny_cache['value'] = _floor.parse_denied_ranges(text)
        _deny_cache['text'] = text
        if _deny_cache['value'][1]:
            logger.error('CVENGINE_SENTINEL_DENY_RANGES holds entries that are not networks (%s): every task is refused until it is fixed', ', '.join(_deny_cache['value'][1]))
    return _deny_cache['value']


def set_overrides(values):
    """Replace what the server told this Sentinel to run with. An empty dict means nothing: every setting is this machine's own again. The new dict
    is built first and swapped in with one assignment, so the poll thread never reads a half-replaced one (local values with the server's missing)."""
    global _overrides
    _overrides = clean_settings(values)


def overrides():
    return dict(_overrides)


def _local_name():
    if builtin():
        return BUILTIN_NAME
    return _env('CVENGINE_SENTINEL_NAME') or socket.gethostname() or 'sentinel'


def sentinel_name():
    if builtin():
        return BUILTIN_NAME  # the install's own scanner keeps its one name, whatever a setting says
    return _overrides.get('name') or _local_name()


def local_settings():
    """What this machine's own configuration says for each setting, ignoring anything the server set: reported to the server at every registration,
    so it can tell a change made here from one made in cvENGINE. ``name`` and ``profile`` are reported only when this machine states one: an unnamed
    Sentinel's fallback name is the host name, which in Docker is the container id and changes at every recreate, so reporting it would undo a rename
    made in cvENGINE."""
    # a disabled kind the server does not know is left out: cvENGINE 1.3 refuses the whole registration (400) for a disabled_kinds entry it has no such kind for
    out = {'network': 'internal' if _local_internal() else 'external', 'disabled_kinds': sorted(k for k in _local_disabled() if server_knows(k)),
           'max_concurrent': _local_max_concurrent()}
    if _env('CVENGINE_SENTINEL_NAME') or builtin():
        out['name'] = _local_name()
    profile = (_env('CVENGINE_SENTINEL_PROFILE') or '').strip().lower()
    if profile in ('full', 'light'):
        out['profile'] = profile
    if _local_self_update():  # like the profile, reported only when this machine states one: otherwise cvENGINE's default applies
        out['self_update'] = _local_self_update()
    return out


def _local_self_update():
    """CVENGINE_SENTINEL_UPDATE: ``off``, ``manual`` or ``automatic`` for this machine, or ``None`` (unset or not one of those). Always ``off`` for the
    built-in scanner: cvENGINE's updater swaps its pinned image, and an image never rebuilds itself."""
    if builtin():
        return 'off'
    value = (_env('CVENGINE_SENTINEL_UPDATE') or '').strip().lower()
    return value if value in SELF_UPDATE else None


def capped_self_update(server):
    """``server`` (a self-update value from cvENGINE, or ``None``) under this machine's own ceiling: the lower of the two in ``SELF_UPDATE`` order, so a
    local ``off`` can never be raised and a local ``manual`` never becomes ``automatic``. Either one alone applies as is; ``None`` when neither is set."""
    local = _local_self_update()
    server = server if server in SELF_UPDATE else None
    if local and server:
        return min(local, server, key=SELF_UPDATE.index)
    return local or server


def self_update():
    """The effective self-update setting: the server's, capped by this machine's own (``capped_self_update``), else ``None`` (the updater then follows
    what cvENGINE says in the heartbeat reply)."""
    return capped_self_update(_overrides.get('self_update'))


def _local_internal():
    """Whether this Sentinel was told it sits inside a private network (CVENGINE_SENTINEL_NETWORK=internal). Only then does it
    declare ``network:internal``, which is what lets the server hand it work for an address of an internal range the project
    declared; every other Sentinel is never offered such work, because it could not reach it."""
    return (_env('CVENGINE_SENTINEL_NETWORK') or '').strip().lower() == 'internal'


def is_internal():
    """The effective network. This machine's own setting is a ceiling: only a Sentinel configured as internal here is ever internal, and the server
    can lower it to external (an administrator pulling an internal Sentinel back) but never raise an external one to internal, so a server that is
    buggy or compromised cannot unlock private ranges or internal sweeps by declaring the Sentinel internal."""
    return _local_internal() and _overrides.get('network') != 'external'


def _local_disabled():
    """CVENGINE_SENTINEL_DISABLE, comma separated, as known scan kinds (case and spacing ignored). An entry that names no kind is dropped and logged
    once, so a typo is visible instead of silently disabling nothing."""
    entries = {k.strip().lower() for k in (_env('CVENGINE_SENTINEL_DISABLE') or '').split(',') if k.strip()}
    unknown = entries - set(KNOWN_KINDS) - _warned_disabled
    if unknown:
        _warned_disabled.update(unknown)
        logger.warning('CVENGINE_SENTINEL_DISABLE names unknown scan kinds, ignored: %s (known: %s)', ', '.join(sorted(unknown)), ', '.join(KNOWN_KINDS))
    return entries & set(KNOWN_KINDS)


def disabled_kinds():
    """Scan kinds turned off on this Sentinel: never declared to the server and never polled for, whatever tools are installed. This machine's own
    CVENGINE_SENTINEL_DISABLE (comma separated, for example ``openvas``) is a veto the server cannot lift: the result is the union of it and the
    server's setting, so the server can only add kinds. A light profile never runs OpenVAS."""
    current = _overrides
    kinds = _local_disabled() | set(current.get('disabled_kinds') or ())
    profile = current.get('profile') or (_env('CVENGINE_SENTINEL_PROFILE') or '').strip().lower()
    return kinds | {'openvas'} if profile == 'light' or builtin() else kinds  # the built-in scanner has no GVM stack


def registered_capabilities(kinds=None):
    """What this Sentinel tells the server it can do: the scan kinds, plus ``network:internal`` (and the kinds only an internal Sentinel
    takes) when deployed inside a private network. The poll's own ``kinds`` filter takes only scan kinds (``poll_kinds``), so this is for
    registration and bootstrap alone. ``kinds`` is an explicit list for tests; the daemon passes none. Disabled kinds are left in here and
    removed by the caller (``daemon.declared_kinds``) with ``disabled_kinds``, which is read fresh each time."""
    caps = poll_kinds(kinds)
    return caps + [INTERNAL_CAPABILITY] if is_internal() and INTERNAL_CAPABILITY not in caps else caps


def poll_kinds(kinds=None):
    """The scan kinds this Sentinel asks the server for: every standard kind, plus the internal-only ones when the effective network (``is_internal``,
    the server's setting if it set one, else this machine's) is internal. Computed afresh at every call, so the daemon calls it at every poll and a
    network changed in cvENGINE takes effect at once. ``kinds`` is an explicit list for tests, taken as given; the daemon passes none."""
    if kinds:
        return list(kinds)
    return CAPABILITIES + INTERNAL_KINDS if is_internal() else list(CAPABILITIES)


CLAIM_BASE, CLAIM_PER_SLOT, CLAIM_WINDOW = 60, 30, 60  # mirrors agentapi.sentinel_broker.claim_limit: calls per window to the claim endpoint (poll and accept)


def claim_limit(max_concurrent):
    """How many claim-endpoint calls (a poll, an accept) the server allows one Sentinel of this concurrency per ``CLAIM_WINDOW`` seconds."""
    return max(CLAIM_BASE, CLAIM_PER_SLOT * max(1, int(max_concurrent)))


MAX_AUTO_CONCURRENT = 10  # mirrors agentapi.agent_broker.MAX_CONCURRENT_CAP: no point auto-detecting past what the server will ever grant


def _cgroup_cpu_limit():
    """The CPU count this process is actually allowed, from the container's own cgroup quota (v2, then v1): tighter
    than the host's physical count whenever ``docker run --cpus``/a compose ``cpus:`` limit is set, and the number
    that matters for how many scan-stage subprocesses run well here. ``None`` when neither file applies (bare metal,
    a VM, or a container with no CPU limit), so the caller falls back to the host's own CPU count."""
    try:
        with open('/sys/fs/cgroup/cpu.max', encoding='utf-8') as handle:
            quota, period = handle.read().split()
        if quota == 'max':
            return None
        quota, period = int(quota), int(period)
        return max(1, quota // period) if period else None
    except (OSError, ValueError):
        pass
    try:
        with open('/sys/fs/cgroup/cpu/cpu.cfs_quota_us', encoding='utf-8') as handle:
            quota = int(handle.read().strip())
        if quota <= 0:
            return None
        with open('/sys/fs/cgroup/cpu/cpu.cfs_period_us', encoding='utf-8') as handle:
            period = int(handle.read().strip())
        return max(1, quota // period) if period else None
    except (OSError, ValueError):
        return None


def _detected_cpus():
    """CPUs this process may actually use: a container's own cgroup quota when one is set, else the scheduler
    affinity mask (also cgroup-aware on Linux, for a cpuset limit with no quota), else the host's raw CPU count,
    else ``1`` if nothing can be read at all."""
    limited = _cgroup_cpu_limit()
    if limited is not None:
        return limited
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 1


def max_concurrent():
    """The effective concurrency: the server's setting when it set one more recently than this machine's, else this machine's own. Both are capped at
    ``MAX_AUTO_CONCURRENT``."""
    return _overrides.get('max_concurrent') or _local_max_concurrent()


def _local_max_concurrent():
    """How many nmap/naabu/nuclei runs this Sentinel executes at once. ``CVENGINE_SENTINEL_MAX_CONCURRENT`` wins when
    set; left unset, this auto-detects from the CPU this Sentinel actually has (its container's own cgroup quota when
    one is set, else the host's CPU count), capped at ``MAX_AUTO_CONCURRENT`` (never a flat ``1`` regardless of how
    much the machine could actually do, which is what a Sentinel with real capacity sitting idle usually means). An
    explicit value is held to the same cap the server's setting is clipped to."""
    raw = _env('CVENGINE_SENTINEL_MAX_CONCURRENT')
    if raw is not None:
        try:
            return max(1, min(int(raw), MAX_AUTO_CONCURRENT))
        except (TypeError, ValueError):
            return 1
    return max(1, min(_detected_cpus(), MAX_AUTO_CONCURRENT))


BUILD_VERSION_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'VERSION')


def _clean_version(value):
    value = (value or '').strip()
    return value if value and len(value) <= 64 and all(c.isalnum() or c in '.-_+' for c in value) else None


def build_version(path=None):
    """The git commit stamped into this image by the Dockerfile (``VERSION``, the first 12 characters of the checkout's HEAD at build time), or
    ``None`` when the image was built without a git checkout."""
    try:
        with open(path or BUILD_VERSION_FILE, encoding='utf-8') as handle:
            return _clean_version(handle.read(200))
    except OSError:
        return None


def version():
    """The client version: the commit this image was built from, else CVENGINE_SENTINEL_VERSION when someone set it by hand (the updater no longer
    writes it: a stale value would hide the build), else ``None`` when neither is known."""
    return build_version() or _clean_version(_env('CVENGINE_SENTINEL_VERSION'))


def token_path():
    return _env('CVENGINE_SENTINEL_TOKEN_FILE', DEFAULT_TOKEN_PATH)


def blob_file():
    """CVENGINE_SENTINEL_BLOB_FILE: a file holding the provisioning blob, in the same format as CVENGINE_SENTINEL_BLOB (the built-in scanner's, which
    the server writes into a volume the two share)."""
    return _env('CVENGINE_SENTINEL_BLOB_FILE')


MAX_BLOB_BYTES = 16384


def blob():
    """The provisioning blob: CVENGINE_SENTINEL_BLOB, else the content of CVENGINE_SENTINEL_BLOB_FILE (read afresh at every call, so a blob the server
    replaced is seen), else ``None``. Never logged: it is a live enrollment secret."""
    value = _env('CVENGINE_SENTINEL_BLOB')
    if value:
        return value
    path = blob_file()
    if not path:
        return None
    try:
        with open(path, encoding='utf-8') as handle:
            text = handle.read(MAX_BLOB_BYTES + 1)
    except (OSError, UnicodeDecodeError):
        return None
    text = text.strip()
    return text if text and len(text) <= MAX_BLOB_BYTES else None


def allow_insecure():
    """CVENGINE_SENTINEL_ALLOW_INSECURE=1: the one explicit opt-in to a plain ``http`` server URL (``httpclient.validate_server_url``)."""
    return (_env('CVENGINE_SENTINEL_ALLOW_INSECURE') or '').strip() == '1'


def os_family():
    system = platform.system().lower()
    if system == 'linux':
        return 'linux'
    if system == 'darwin':
        return 'macos'
    if system == 'windows':
        return 'windows'
    return ''
