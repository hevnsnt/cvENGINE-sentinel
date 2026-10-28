"""Everything the daemon reads from its environment, in one place, each with a sane default."""
import os
import platform
import socket

CAPABILITIES = ['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep']
HEARTBEAT_SECONDS = 60  # matches agentapi.agent_broker.HEARTBEAT_SECONDS; see that constant if it ever changes
DEFAULT_TOKEN_PATH = '/var/lib/cvengine-sentinel/token.json'
DEFAULT_POLL_WAIT = 15  # seconds the long poll (sentinel/tasks/next) may block per call
SHUTDOWN_GRACE_SECONDS = 20  # how long a SIGTERM waits for in-flight tasks to finish before releasing them


def _env(name, default=None):
    value = os.environ.get(name)
    return value if value not in (None, '') else default


def sentinel_name():
    return _env('CVENGINE_SENTINEL_NAME') or socket.gethostname() or 'sentinel'


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
