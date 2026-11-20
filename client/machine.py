"""What this Sentinel's machine has and how it is doing, reported in every heartbeat as ``info.machine`` so cvENGINE's auto-tuner can size this one
Sentinel's concurrency (``max_concurrent``) and its per-kind slots from its own CPU, memory and load, and back it off when the kernel kills its tools.

Numbers only: CPU counts, the load average, memory and swap in MB, the container's own memory limit and use (cgroup v2, else v1; none outside a
container) and how many runs of each task kind the kernel killed for memory in the last hour (``note_oom``, called by the daemon when a task ends with
``tools.ToolOOMError`` or a bbot run that was killed). No target, finding, path or secret is ever in it. Every read is wrapped: what cannot be read is
left out (``None``), and a report that fails as a whole is simply not sent (``daemon.info``). The field is optional and additive: a server that does not
know it ignores it, and the contract version is unchanged.

The load average is the whole host's (a container sees the host's ``/proc/loadavg``), so it is reported beside ``host_cpus`` (the host's CPU count),
which is what it compares with; ``cpus`` is what this Sentinel may use (its cgroup quota, else its affinity mask).
"""
import collections
import logging
import os
import threading
import time

logger = logging.getLogger('sentinel.machine')

MB = 1024 * 1024
OOM_WINDOW_SECONDS = 3600  # the out-of-memory kills reported are those of the last hour
MAX_KINDS = 64  # kinds kept in the kill count (there are fewer kinds than this; a bound all the same)

_lock = threading.Lock()
_kills = collections.defaultdict(collections.deque)  # kind -> monotonic times of out-of-memory kills


def _read(path):
    try:
        with open(path, encoding='ascii') as handle:
            return handle.read().strip()
    except (OSError, ValueError):
        return ''


def note_oom(kind, now=None):
    """A run of ``kind`` was killed by the system (status -9 or 137 that this daemon did not send): counted for an hour."""
    if not isinstance(kind, str) or not kind:
        return
    now = time.monotonic() if now is None else now
    with _lock:
        if kind not in _kills and len(_kills) >= MAX_KINDS:
            return
        _kills[kind].append(now)


def oom_kills(now=None):
    """``{kind: kills in the last hour}``, only the kinds that had one."""
    now = time.monotonic() if now is None else now
    out = {}
    with _lock:
        for kind, times in list(_kills.items()):
            while times and now - times[0] > OOM_WINDOW_SECONDS:
                times.popleft()
            if times:
                out[kind] = len(times)
            else:
                del _kills[kind]
    return out


def reset():
    """Forget every counted kill (tests)."""
    with _lock:
        _kills.clear()


def meminfo(read=_read):
    """``{mem_total_mb, mem_available_mb, swap_total_mb, swap_free_mb}`` from ``/proc/meminfo`` (the host's, also inside a container), each None when missing."""
    fields = {'MemTotal': 'mem_total_mb', 'MemAvailable': 'mem_available_mb', 'SwapTotal': 'swap_total_mb', 'SwapFree': 'swap_free_mb'}
    out = dict.fromkeys(fields.values())
    for line in read('/proc/meminfo').splitlines():
        name, _, rest = line.partition(':')
        parts = rest.split()
        if name in fields and parts and parts[0].isdigit():
            out[fields[name]] = int(parts[0]) // 1024
    return out


def cgroup_memory(read=_read):
    """``(limit_mb, used_mb)`` of this container's memory cgroup (v2 ``memory.max``/``memory.current``, else v1 ``memory.limit_in_bytes``/``memory.usage_in_bytes``).
    The limit is None when there is none ("max", or v1's huge number), the use None when it cannot be read."""
    for limit_path, used_path in (('/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory.current'),
                                  ('/sys/fs/cgroup/memory/memory.limit_in_bytes', '/sys/fs/cgroup/memory/memory.usage_in_bytes')):
        raw_limit, raw_used = read(limit_path), read(used_path)
        if not raw_limit and not raw_used:
            continue
        limit = int(raw_limit) // MB if raw_limit.isdigit() and 0 < int(raw_limit) < (1 << 50) else None
        used = int(raw_used) // MB if raw_used.isdigit() else None
        return limit, used
    return None, None


def cgroup_oom_kills(read=_read):
    """How many out-of-memory kills this container's memory cgroup counted since it started (v2 ``memory.events``), or None."""
    for line in read('/sys/fs/cgroup/memory.events').splitlines():
        if line.startswith('oom_kill '):
            value = line.split()[1]
            return int(value) if value.isdigit() else None
    return None


def _cpus():
    from client import config
    try:
        return int(config._detected_cpus())
    except Exception:  # noqa: BLE001
        return None


def report(read=_read, loadavg=os.getloadavg, now=None):
    """The ``info.machine`` report: ``{cpus, host_cpus, load: [1, 5, 15 minutes], mem_total_mb, mem_available_mb, swap_total_mb, swap_free_mb,
    cgroup_limit_mb, cgroup_used_mb, cgroup_oom_kills, oom_kills_1h: {kind: n}}``. What cannot be read is None (the load is left out)."""
    out = {'cpus': _cpus(), 'host_cpus': os.cpu_count()}
    try:
        out['load'] = [round(float(x), 2) for x in loadavg()[:3]]
    except (OSError, AttributeError, ValueError):
        out['load'] = None
    out.update(meminfo(read))
    out['cgroup_limit_mb'], out['cgroup_used_mb'] = cgroup_memory(read)
    out['cgroup_oom_kills'] = cgroup_oom_kills(read)
    out['oom_kills_1h'] = oom_kills(now)
    return out
