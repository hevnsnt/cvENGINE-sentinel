"""Memory admission control: which kinds of work may start now, given the memory this container really has.

A Sentinel in a container with a 2 GB limit that ran one deep nuclei run, several light ones and a Chromium at the same time was killed by the kernel
(every nuclei run loads the whole template set: about 500-730 MB each, whatever its tags or concurrency). The slot count (``max_concurrent``) says
nothing about memory, so the daemon asks this module before it polls: a kind is only asked for while the kinds already running, plus its own weight, fit
in the budget. A task that runs alone is always admitted (a budget smaller than one nuclei still has to make progress), never a second heavy one beside it.

The budget is the container's own limit (cgroup v2 ``memory.max``, v1 ``memory.limit_in_bytes``; with none, the host's memory) less a reserve for the
daemon itself and the page cache, never a number written down here. ``CVENGINE_SENTINEL_MEMORY_MB`` overrides it for a host whose limit cannot be read.

The weights are the measured peak (cgroup ``memory.peak``) of one run of the kind against a local lab server, image tools of 2026-11 (nuclei 3.11.1, Chromium 156,
nmap 7.993): nuclei 500 MB with ``GOMEMLIMIT`` set to ``NUCLEI_GOMEMLIMIT_MB`` (720-735 MB without it, whatever ``-c``), Chromium with two pages 224 MB (a page can use
more: the browser is stopped past ``shot.MAX_RSS_MB``), nmap -p- 68 MB, bbot 66 MB for a one-host lab run (a real discovery grows with its targets, so it is weighed
higher), Kingfisher about 150 MB (daemon's own measurement). Everything else is a small in-process probe or a short tool run.
"""
import logging
import os
import threading

logger = logging.getLogger('sentinel.admission')

MB = 1024 * 1024
RESERVE_FRACTION = 0.15  # of the limit: the page cache, the Python daemon, its threads
DAEMON_MB = 200  # the daemon and its probes outside any task
DEFAULT_WEIGHT_MB = 40  # an in-process probe or a short tool run
NUCLEI_GOMEMLIMIT_MB = 400  # the soft memory limit nuclei (a Go program) is started with: it collects garbage harder instead of growing

WEIGHTS_MB = {
    'nuclei_light': 520, 'nuclei_deep': 520, 'nuclei_targeted': 520, 'nuclei_validate': 200,
    'web_screenshot': 400, 'rdp_shot': 150,
    'bbot_discovery': 250,
    'secrets_scan': 150,
    'nmap_full': 100, 'nmap': 100, 'nmap_verify': 100, 'nmap_udp': 100, 'discover': 100, 'naabu': 80,
    'testssl': 60, 'wpscan': 120, 'wpscan_thorough': 120, 'waf': 60,
    'openvas': 0,  # GVM runs in its own containers, with their own limits
}
# The kinds that are heavy enough that two of them beside each other is a decision, not an accident (named in the log and in tests).
HEAVY = frozenset(k for k, w in WEIGHTS_MB.items() if w >= 300)


def weight(kind):
    return WEIGHTS_MB.get(kind, DEFAULT_WEIGHT_MB)


def _read(path):
    try:
        with open(path, encoding='ascii') as handle:
            return handle.read().strip()
    except (OSError, ValueError):
        return ''


def container_limit_bytes(read=_read):
    """The memory limit of this container in bytes, or ``None`` when there is none. ``read`` returns a file's text ('' when it has none)."""
    override = os.environ.get('CVENGINE_SENTINEL_MEMORY_MB', '').strip()
    if override.isdigit() and int(override) > 0:
        return int(override) * MB
    for path in ('/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory/memory.limit_in_bytes'):
        raw = read(path)
        if raw.isdigit() and 0 < int(raw) < (1 << 50):  # cgroup v1 says 9223372036854771712 for "none"
            return int(raw)
    return None


def host_memory_bytes(read=_read):
    for line in read('/proc/meminfo').splitlines():
        if line.startswith('MemTotal:'):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024
    return None


def budget_mb(read=_read):
    """The memory, in MB, the running tasks' weights may add up to."""
    limit = container_limit_bytes(read) or host_memory_bytes(read) or 2048 * MB
    return max(1, int(limit / MB * (1 - RESERVE_FRACTION)) - DAEMON_MB)


def scaled_nuclei(budget):
    """``(concurrency, rate)`` for one nuclei run on a Sentinel with this budget: the template set costs the same whatever they are, but the buffers of
    each parallel host and request grow with them, so a small budget gets fewer (the server's own defaults are -c 40 -rl 150 for a roomy machine)."""
    conc = max(5, min(40, int(budget) // 40))
    return conc, max(25, min(150, conc * 4))


class Admission:
    """The running tasks' weights against the budget. ``can_start(kind, running)`` takes the kinds now running; thread safety is the caller's (the daemon
    reads its in-flight list under its own lock)."""

    def __init__(self, budget=None):
        self._budget = budget
        self._lock = threading.Lock()

    @property
    def budget(self):
        if self._budget is None:
            self._budget = budget_mb()
        return self._budget

    def used(self, running):
        return sum(weight(k) for k in running)

    def can_start(self, kind, running):
        running = [k for k in running if k is not None]
        w = weight(kind)
        if w == 0 or not any(weight(k) > DEFAULT_WEIGHT_MB for k in running):
            return True  # nothing heavy runs: a task alone is always admitted, and a light one costs next to nothing
        return self.used(running) + w <= self.budget

    def admissible(self, kinds, running):
        """``kinds`` less those that would not fit beside ``running`` right now."""
        return [k for k in kinds if self.can_start(k, running)]


class ClaimPacer:
    """A sliding window of this Sentinel's own claim-endpoint calls (poll and accept both count on the server): it never spends more than ``share`` of what the
    server allows per window, so a Sentinel with many short tasks waits instead of being refused."""

    def __init__(self, limit, window=60.0, share=0.75, clock=None):
        import time
        self._clock = clock or time.monotonic
        self.limit, self.window, self.share = limit, window, share
        self._calls = []
        self._lock = threading.Lock()

    def wait_needed(self):
        """Seconds to wait before the next call, 0 when it fits."""
        now = self._clock()
        with self._lock:
            self._calls = [t for t in self._calls if now - t < self.window]
            allowed = max(1, int(self.limit * self.share))
            if len(self._calls) < allowed:
                return 0.0
            return max(0.0, self._calls[len(self._calls) - allowed] + self.window - now)

    def note(self):
        with self._lock:
            self._calls.append(self._clock())
