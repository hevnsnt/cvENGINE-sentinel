"""Everything the daemon reads from its environment, in one place, each with a sane default."""
import os
import platform
import socket

CAPABILITIES = ['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep', 'testssl', 'nmap_udp', 'wpscan', 'openvas']
INTERNAL_CAPABILITY = 'network:internal'  # mirrors agentapi.sentinel_broker.INTERNAL_CAPABILITY
INTERNAL_KINDS = ['discover']  # scan kinds only an internal Sentinel declares: the server sweeps a declared private range only through one
HEARTBEAT_SECONDS = 60  # matches agentapi.agent_broker.HEARTBEAT_SECONDS; see that constant if it ever changes
DEFAULT_TOKEN_PATH = '/var/lib/cvengine-sentinel/token.json'
DEFAULT_POLL_WAIT = 15  # seconds the long poll (sentinel/tasks/next) may block per call
SHUTDOWN_GRACE_SECONDS = 20  # how long a SIGTERM waits for in-flight tasks to finish before releasing them


def _env(name, default=None):
    value = os.environ.get(name)
    return value if value not in (None, '') else default


# Settings the server may manage (agentapi.sentinel_settings.SETTINGS): the most recent change, here or in cvENGINE, wins. ``local_settings`` is what this
# machine's own configuration says and is what gets reported; ``_overrides`` holds what the server told this Sentinel to run with, and is consulted first.
SETTING_KEYS = ('name', 'network', 'profile', 'disabled_kinds', 'max_concurrent', 'self_update')
SELF_UPDATE = ('off', 'manual', 'automatic')
_overrides = {}


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
        out['disabled_kinds'] = sorted({k for k in kinds if isinstance(k, str) and k in CAPABILITIES + INTERNAL_KINDS})
    value = raw.get('max_concurrent')
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_AUTO_CONCURRENT:
        out['max_concurrent'] = value
    if raw.get('self_update') in SELF_UPDATE:
        out['self_update'] = raw['self_update']
    return out


def set_overrides(values):
    """Replace what the server told this Sentinel to run with. An empty dict means nothing: every setting is this machine's own again."""
    _overrides.clear()
    _overrides.update(clean_settings(values))


def overrides():
    return dict(_overrides)


def _local_name():
    return _env('CVENGINE_SENTINEL_NAME') or socket.gethostname() or 'sentinel'


def sentinel_name():
    return _overrides.get('name') or _local_name()


def local_settings():
    """What this machine's own configuration says for each setting, ignoring anything the server set: reported to the server at every registration,
    so it can tell a change made here from one made in cvENGINE. ``profile`` is reported only when this machine states one."""
    out = {'name': _local_name(), 'network': 'internal' if _local_internal() else 'external',
           'disabled_kinds': sorted(_local_disabled()), 'max_concurrent': _local_max_concurrent()}
    profile = (_env('CVENGINE_SENTINEL_PROFILE') or '').strip().lower()
    if profile in ('full', 'light'):
        out['profile'] = profile
    if _local_self_update():  # like the profile, reported only when this machine states one: otherwise cvENGINE's default applies
        out['self_update'] = _local_self_update()
    return out


def _local_self_update():
    """CVENGINE_SENTINEL_UPDATE: ``off``, ``manual`` or ``automatic`` for this machine, or ``None`` (unset or not one of those)."""
    value = (_env('CVENGINE_SENTINEL_UPDATE') or '').strip().lower()
    return value if value in SELF_UPDATE else None


def self_update():
    """The effective self-update setting: the server's when it set one more recently than this machine's, else this machine's own, else ``None``
    (the updater then follows what cvENGINE says in the heartbeat reply)."""
    return _overrides.get('self_update') or _local_self_update()


def _local_internal():
    """Whether this Sentinel was told it sits inside a private network (CVENGINE_SENTINEL_NETWORK=internal). Only then does it
    declare ``network:internal``, which is what lets the server hand it work for an address of an internal range the project
    declared; every other Sentinel is never offered such work, because it could not reach it."""
    return (_env('CVENGINE_SENTINEL_NETWORK') or '').strip().lower() == 'internal'


def is_internal():
    """The effective network: the server's setting when it set one more recently than this machine's, else this machine's own."""
    return _overrides['network'] == 'internal' if 'network' in _overrides else _local_internal()


def _local_disabled():
    return {k.strip() for k in (_env('CVENGINE_SENTINEL_DISABLE') or '').split(',') if k.strip()}


def disabled_kinds():
    """Scan kinds turned off on this Sentinel (CVENGINE_SENTINEL_DISABLE, comma separated, for example ``openvas``, or the server's setting): never
    declared to the server and never polled for, whatever tools are installed. A light profile never runs OpenVAS."""
    kinds = set(_overrides['disabled_kinds']) if 'disabled_kinds' in _overrides else _local_disabled()
    profile = _overrides.get('profile') or (_env('CVENGINE_SENTINEL_PROFILE') or '').strip().lower()
    return kinds | {'openvas'} if profile == 'light' else kinds


def registered_capabilities(kinds=None):
    """What this Sentinel tells the server it can do: the scan kinds, plus ``network:internal`` (and the kinds only an internal Sentinel
    takes) when deployed inside a private network. The poll's own ``kinds`` filter takes only scan kinds (``poll_kinds``), so this is for
    registration and bootstrap alone."""
    caps = poll_kinds(kinds)
    return caps + [INTERNAL_CAPABILITY] if is_internal() and INTERNAL_CAPABILITY not in caps else caps


def poll_kinds(kinds=None):
    """The scan kinds this Sentinel asks the server for: every standard kind, plus the internal-only ones when deployed inside a network."""
    if kinds:  # an explicit list is the operator's own choice and is taken as given
        return list(kinds)
    return CAPABILITIES + INTERNAL_KINDS if is_internal() else list(CAPABILITIES)


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
    """The effective concurrency: the server's setting when it set one more recently than this machine's, else this machine's own."""
    return _overrides.get('max_concurrent') or _local_max_concurrent()


def _local_max_concurrent():
    """How many nmap/naabu/nuclei runs this Sentinel executes at once. ``CVENGINE_SENTINEL_MAX_CONCURRENT`` wins when
    set; left unset, this auto-detects from the CPU this Sentinel actually has (its container's own cgroup quota when
    one is set, else the host's CPU count), capped at ``MAX_AUTO_CONCURRENT`` - never a flat ``1`` regardless of how
    much the machine could actually do, which is what a Sentinel with real capacity sitting idle usually means."""
    raw = _env('CVENGINE_SENTINEL_MAX_CONCURRENT')
    if raw is not None:
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            return 1
    return max(1, min(_detected_cpus(), MAX_AUTO_CONCURRENT))


def version():
    """The client version this image was built from (CVENGINE_SENTINEL_VERSION, the git commit the updater builds), or ``None`` when unknown."""
    value = (_env('CVENGINE_SENTINEL_VERSION') or '').strip()
    return value if value and len(value) <= 64 and all(c.isalnum() or c in '.-_+' for c in value) else None


def token_path():
    return _env('CVENGINE_SENTINEL_TOKEN_FILE', DEFAULT_TOKEN_PATH)


def blob():
    return _env('CVENGINE_SENTINEL_BLOB')


def os_family():
    system = platform.system().lower()
    if system == 'linux':
        return 'linux'
    if system == 'darwin':
        return 'macos'
    if system == 'windows':
        return 'windows'
    return ''
