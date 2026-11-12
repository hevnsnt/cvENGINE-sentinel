"""The Sentinel's own watchdog: one thread, apart from every task thread, that checks the work this Sentinel is doing and the loops that keep it alive.

It exists because the Sentinel has several ways to stop being useful without crashing (see docs/WATCHDOG.md): a tool that hangs and says nothing, a memory
budget that two long nuclei runs hold for an hour while every waiter starves, tool children that outlive their task, a heartbeat or poll loop that is stuck
(a DNS lookup has no timeout), a full disk. Every rule below is small, reads /proc and the daemon's own state, and never needs the network.

W1 deadline        a task past its kind's hard deadline has its whole process group stopped and is reported as an error that says so.
W2 no progress     a task whose process group used no CPU and moved no bytes for N minutes is hung: same stop.
W3 memory          waiters that have waited long behind holders that have run long may start beside them within a bounded overcommit, only while the real
                   memory measured from /proc and the cgroup stays above a floor. Nothing is killed for it (``CVENGINE_SENTINEL_WATCHDOG_MEM_KILL=1`` adds a last-resort stop).
W4 orphans         a tool process group that outlived its task is killed, its zombie children are reaped.
W5 liveness        a stale heartbeat thread is replaced, a stuck poll loop (or a heartbeat that cannot be revived) ends the process so its supervisor restarts it.
W6 disk            below a floor no new work is taken, this Sentinel's own temporary and cache files are removed, ``low_disk`` is reported.
W7 report          the optional heartbeat field ``info.watchdog`` (a server that does not know it drops it).
W8 control         ``CVENGINE_SENTINEL_WATCHDOG=0`` switches all of it off; every threshold has its own variable; every action is one log line; a kind stopped
                   too often is withheld for a while.

The result contract is not touched: a stopped task is reported with the existing ``error`` outcome and a plain sentence, nuclei findings already produced are
reported as ``done`` (never an empty ``done``: a run that was stopped and produced nothing is an error).
"""
import collections
import logging
import os
import shutil
import signal
import tempfile
import threading
import time

from cvengine_scanner import flags

from . import admission
from . import config
from . import control

logger = logging.getLogger('sentinel.watchdog')

MB = 1024 * 1024
TICK_SECONDS = 10.0

# Seconds each kind's tool may take by its own limits (client/tools.py, flags.py, bbot, openvas), the figure the hard deadline is never lower than; the
# deadline adds GRACE_SECONDS so a tool that stops on its own limit is never the watchdog's doing.
TOOL_BUDGET_SECONDS = {
    'nuclei_light': 3600, 'nuclei_targeted': 3600, 'nuclei_deep': 3600, 'nuclei_validate': 600,
    'nmap': 3600, 'nmap_verify': 900, 'nmap_full': 1500, 'nmap_udp': 1500, 'discover': 900, 'naabu': flags.TASK_LIMITS['naabu'][2],
    'testssl': 900, 'wpscan': 900, 'waf': 300, 'web_screenshot': 1800, 'rdp_shot': 300, 'secrets_scan': 1800,
    'bbot_discovery': 21600, 'wpscan_thorough': 12 * 3600, 'openvas': 24 * 3600,
    # in-process probe batches that run past the 900 s default by their own limits (cvengine_scanner.probes: version_probes and routes BATCH_SECONDS 1200,
    # suppliers MAX_SECONDS 1500): each stops starting work at its limit and reports the rest as not run, so the watchdog must not stop it earlier
    'http_probe': 1200, 'route_probe': 1200, 'route_probe_signed': 1200, 'supplier_check': 1500,
}
DEFAULT_BUDGET_SECONDS = 900  # an in-process probe or a kind this table does not know: seconds long in practice
GRACE_SECONDS = 300
BUDGET_GRACE_SECONDS = 600  # past a time limit the task itself carries (bbot, thorough wpscan): the tool stops on it, this is the backstop
NO_PROGRESS_MINUTES = {'nuclei_light': 20, 'nuclei_targeted': 20, 'nuclei_deep': 20, 'nmap': 20, 'nmap_full': 20, 'nmap_udp': 20, 'wpscan': 20, 'bbot_discovery': 30}
DEFAULT_NO_PROGRESS_MINUTES = 15
NO_PROGRESS_OFF = frozenset({'openvas', 'wpscan_thorough'})  # no process of its own to watch (gvmd runs elsewhere), or hours between sign of life
NUCLEI_KINDS = frozenset({'nuclei_light', 'nuclei_targeted', 'nuclei_deep'})
KILL_ESCALATE_SECONDS = 5.0  # SIGTERM to the group, then SIGKILL this long after
ABANDON_SECONDS = 20.0  # a task whose thread has still not ended this long after the stop is reported by the watchdog and no longer counted
LABELS = {'nuclei_light': 'nuclei light scan', 'nuclei_targeted': 'nuclei targeted scan', 'nuclei_deep': 'nuclei deep scan', 'nmap': 'nmap scan',
          'nmap_full': 'full port scan', 'nmap_udp': 'UDP scan', 'nmap_verify': 'port verification', 'testssl': 'TLS check', 'wpscan': 'WordPress scan',
          'wpscan_thorough': 'thorough WordPress scan', 'bbot_discovery': 'discovery run', 'openvas': 'OpenVAS scan', 'web_screenshot': 'screenshot'}


def label(kind):
    return LABELS.get(kind) or str(kind).replace('_', ' ')


def env_int(name, default, low=None, high=None):
    raw = os.environ.get(name, '').strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        value = default
    if low is not None:
        value = max(low, value)
    if high is not None:
        value = min(high, value)
    return value


def enabled():
    """``CVENGINE_SENTINEL_WATCHDOG=0`` (also false, off, no) switches the whole watchdog off."""
    return os.environ.get('CVENGINE_SENTINEL_WATCHDOG', '1').strip().lower() not in ('0', 'false', 'off', 'no')


def deadline_seconds(kind, budget_s=None):
    """The hard deadline of a task of ``kind``: the tool's own budget plus a grace, raised (never lowered under the budget) by
    ``CVENGINE_SENTINEL_DEADLINE_<KIND>_MIN`` or ``CVENGINE_SENTINEL_DEADLINE_DEFAULT_MIN``. ``budget_s`` is a time limit the task itself carries."""
    base = TOOL_BUDGET_SECONDS.get(kind, DEFAULT_BUDGET_SECONDS)
    if isinstance(budget_s, int) and not isinstance(budget_s, bool) and budget_s > 0:
        base = max(base, budget_s) if kind in ('bbot_discovery', 'wpscan_thorough') else base
        floor = base + BUDGET_GRACE_SECONDS
    else:
        floor = base + GRACE_SECONDS
    for name in (f'CVENGINE_SENTINEL_DEADLINE_{str(kind).upper()}_MIN', 'CVENGINE_SENTINEL_DEADLINE_DEFAULT_MIN'):
        minutes = env_int(name, 0, 0)
        if minutes:
            return max(floor, minutes * 60, base)  # never under what the tool is itself allowed
    return floor


def no_progress_seconds(kind):
    if kind in NO_PROGRESS_OFF:
        return None
    for name in (f'CVENGINE_SENTINEL_NOPROGRESS_{str(kind).upper()}_MIN', 'CVENGINE_SENTINEL_NOPROGRESS_DEFAULT_MIN'):
        minutes = env_int(name, 0, 0)
        if minutes:
            return minutes * 60
    return NO_PROGRESS_MINUTES.get(kind, DEFAULT_NO_PROGRESS_MINUTES) * 60


# --- /proc ---------------------------------------------------------------------------------------------------------------------------------

def _read(path):
    try:
        with open(path, encoding='ascii', errors='replace') as handle:
            return handle.read().strip()
    except OSError:
        return ''


def scan_proc(root='/proc'):
    """``{pgid: {'rss_mb', 'cpu', 'io', 'pids', 'zombies': [pid], 'parents': {pid: ppid}}}`` for every process group on the host (this container), one pass
    over /proc. ``cpu`` is utime+stime in clock ticks and ``io`` rchar+wchar in bytes, both summed over the group: a tool that is working moves one of them."""
    out = {}
    try:
        names = os.listdir(root)
    except OSError:
        return out
    page = os.sysconf('SC_PAGE_SIZE') if hasattr(os, 'sysconf') else 4096
    for name in names:
        if not name.isdigit():
            continue
        stat = _read(f'{root}/{name}/stat')
        end = stat.rfind(')')
        if end < 0:
            continue
        fields = stat[end + 2:].split()  # after "pid (comm) ": state ppid pgrp session ...
        if len(fields) < 22:
            continue
        try:
            pid, state, ppid, pgrp = int(name), fields[0], int(fields[1]), int(fields[2])
            cpu = int(fields[11]) + int(fields[12])
            rss = int(fields[21]) * page
        except ValueError:
            continue
        row = out.setdefault(pgrp, {'rss_mb': 0.0, 'cpu': 0, 'io': 0, 'pids': [], 'zombies': [], 'parents': {}})
        row['pids'].append(pid)
        row['parents'][pid] = ppid
        row['cpu'] += cpu
        row['rss_mb'] += rss / MB
        if state == 'Z':
            row['zombies'].append(pid)
            continue
        io = _read(f'{root}/{name}/io')
        for line in io.splitlines():
            if line.startswith(('rchar:', 'wchar:')):
                try:
                    row['io'] += int(line.split()[1])
                except (IndexError, ValueError):
                    pass
    return out


def live_pids(row):
    return [p for p in row['pids'] if p not in set(row['zombies'])]


def pgid_of(proc):
    """The process group id a registered tool handle runs in (the tool is its own session leader), or ``None`` for a handle with no process (OpenVAS)."""
    inner = getattr(proc, 'proc', proc)
    pid = getattr(inner, 'pid', None)
    return pid if isinstance(pid, int) and not isinstance(pid, bool) and pid > 1 else None


def mem_state(read=_read):
    """``{'limit_mb', 'avail_mb'}``: this container's limit and the memory really left: the lesser of the host's MemAvailable and the limit less what the
    cgroup's working set (usage without the reclaimable page cache) holds."""
    raw_read = read

    def read(path):  # a kernel file ends in a newline: the limit would not parse, and the host's memory would be taken for it
        return raw_read(path).strip()
    avail_host = limit = None
    total = None
    for line in read('/proc/meminfo').splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            if parts[0] == 'MemAvailable:':
                avail_host = int(parts[1]) / 1024
            elif parts[0] == 'MemTotal:':
                total = int(parts[1]) / 1024
    cg_limit = admission.container_limit_bytes(read)
    limit = (cg_limit / MB) if cg_limit else total
    avail = avail_host
    current = read('/sys/fs/cgroup/memory.current').strip() or read('/sys/fs/cgroup/memory/memory.usage_in_bytes').strip()
    if cg_limit and current.isdigit():
        inactive = 0
        for line in (read('/sys/fs/cgroup/memory.stat') or read('/sys/fs/cgroup/memory/memory.stat')).splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in ('inactive_file', 'total_inactive_file') and parts[1].isdigit():
                inactive = int(parts[1])
        working = max(0, int(current) - inactive) / MB
        left = limit - working
        avail = left if avail is None else min(avail, left)
    return {'limit_mb': limit, 'avail_mb': avail}


def compute_overcommit(budget_mb, used_mb, estimates_mb, limit_mb, floor_mb, fraction):
    """The MB the memory budget may be exceeded by right now: ``fraction`` of the budget at most, and never more than the real room: what the container's
    limit leaves after the safe floor, the daemon's own memory and the running tasks' estimated real use (``estimates_mb``). A task admitted into the
    overcommit is weighed at its full weight, so the measured room it needs is there before it starts."""
    if not limit_mb:
        return 0
    real_room = limit_mb - floor_mb - admission.DAEMON_MB - sum(estimates_mb)
    free_weights = budget_mb - used_mb
    over = min(int(budget_mb * fraction), int(real_room - free_weights))
    return max(0, over)


class Watchdog:
    """See the module text. ``tick()`` is one pass of every rule (tests call it with a fake clock); ``start()`` runs it every ``TICK_SECONDS`` in a thread."""

    def __init__(self, daemon, clock=time.monotonic, wall=time.time, proc_root='/proc', mem=mem_state, disk=None, tick_seconds=None):
        self.d = daemon
        self.clock, self.wall, self.proc_root, self.mem = clock, wall, proc_root, mem
        self.disk = disk or self._disk_free_mb
        self.tick_seconds = tick_seconds or env_int('CVENGINE_SENTINEL_WATCHDOG_TICK', int(TICK_SECONDS), 2, 60)
        self.thread = None
        self.last_tick = clock()  # monotonic
        self.last_tick_wall = wall()
        self.peak = {}  # task id -> the largest real memory (MB) its process groups showed
        self.seen = {}  # task id -> {'sig', 'moved'} for the no-progress rule
        self.watch = {}  # pgid -> when its task ended (monotonic): a group still alive after the grace is an orphan
        self.actions = collections.deque(maxlen=60)  # {'at', 'code', 'kind', 'minutes'}
        self.kills = collections.defaultdict(collections.deque)  # kind -> monotonic times of watchdog stops
        self.withheld = {}  # kind -> monotonic time it is offered again
        self.overcommit_mb = 0
        self.overcommit_admitted = 0
        self.low_disk = False
        self.low_disk_mb = None
        self.reaped_zombies = 0
        self.hb_restarts = collections.deque(maxlen=5)  # monotonic times
        self._reasoned = {}
        self.cfg = self.read_config()

    @staticmethod
    def read_config():
        return {
            'mem_wait': env_int('CVENGINE_SENTINEL_WATCHDOG_MEM_WAIT_SECONDS', 180, 10),  # waiters must have waited this long ...
            'mem_hold': env_int('CVENGINE_SENTINEL_WATCHDOG_MEM_HOLD_SECONDS', 300, 10),  # ... behind holders that have run this long (their fair share)
            'over_pct': env_int('CVENGINE_SENTINEL_WATCHDOG_OVERCOMMIT_PERCENT', 25, 0, 50),
            'floor_mb': env_int('CVENGINE_SENTINEL_WATCHDOG_MEM_FLOOR_MB', 0, 0),  # 0: the larger of 300 MB and 15 percent of the limit
            'mem_kill': os.environ.get('CVENGINE_SENTINEL_WATCHDOG_MEM_KILL', '').strip().lower() in ('1', 'true', 'yes', 'on'),
            'hb_stale': env_int('CVENGINE_SENTINEL_WATCHDOG_HEARTBEAT_STALE_SECONDS', 150, 90),
            'poll_stale': env_int('CVENGINE_SENTINEL_WATCHDOG_POLL_STALE_SECONDS', 300, 120),
            'disk_floor_mb': env_int('CVENGINE_SENTINEL_WATCHDOG_DISK_FLOOR_MB', 300, 1),
            'kill_limit': env_int('CVENGINE_SENTINEL_WATCHDOG_KILLS_PER_HOUR', 3, 1),
            'withhold': env_int('CVENGINE_SENTINEL_WATCHDOG_WITHHOLD_MINUTES', 30, 1) * 60,
            'partial': os.environ.get('CVENGINE_SENTINEL_WATCHDOG_PARTIAL', '1').strip().lower() not in ('0', 'false', 'off', 'no'),
        }

    # --- thread ------------------------------------------------------------------------------------------------------------------------------

    def start(self):
        if self.alive():
            return
        self.thread = threading.Thread(target=self._loop, name='sentinel-guard', daemon=True)
        self.thread.start()

    def alive(self):
        return self.thread is not None and self.thread.is_alive()

    def _loop(self):
        logger.info('watchdog on: tick %ss; kill switch CVENGINE_SENTINEL_WATCHDOG=0', self.tick_seconds)
        while not self.d.stop_event.wait(self.tick_seconds):
            self.tick()

    def tick(self):
        now = self.clock()
        scan = scan_proc(self.proc_root)
        for name, rule in (('tasks', self._rule_tasks), ('memory', self._rule_memory), ('orphans', self._rule_orphans), ('liveness', self._rule_liveness),
                           ('disk', self._rule_disk), ('withheld', self._rule_withheld)):
            try:
                rule(now, scan)
            except Exception:  # noqa: BLE001 - one broken rule must not stop the others, or the tick
                if now - self._reasoned.get(name, -1e9) > 600:
                    self._reasoned[name] = now
                    logger.exception('watchdog rule %s failed', name)
        self.last_tick, self.last_tick_wall = now, self.wall()
        self._publish(now)
        self.d._write_control()

    # --- actions, the log and the report -----------------------------------------------------------------------------------------------------

    def act(self, code, kind=None, minutes=None, text=''):
        """One action: recorded for the heartbeat and logged as one line (the logging format adds the timestamp). Never carries a target, a finding or a secret."""
        self.actions.append({'at': int(self.wall()), 'code': code, 'kind': kind, 'minutes': minutes})
        logger.warning('watchdog %s%s: %s', code, f' {kind}' if kind else '', text)

    def _recent(self, seconds=3600):
        cut = self.wall() - seconds
        return [a for a in self.actions if a['at'] >= cut]

    def _publish(self, now):
        recent = self._recent()
        reasons = []
        for a in reversed(recent):
            reasons.append(self.sentence(a))
            if len(reasons) >= 5:
                break
        if self.low_disk:
            reasons.insert(0, f'low disk: {self.low_disk_mb} MB left, taking no new work')
        for kind, until in self.withheld.items():
            reasons.insert(0, f'{label(kind)} work withheld for {max(1, int((until - now) / 60))} more minutes after repeated stops')
        report = {'last_tick': int(self.last_tick_wall), 'actions_last_hour': len(recent), 'kills': sum(1 for a in recent if a['code'].startswith('stopped')),
                  'overcommit_active': self.overcommit_mb > 0, 'overcommit_mb': int(self.overcommit_mb), 'low_disk': self.low_disk,
                  'withheld': sorted(self.withheld), 'reasons': reasons[:5],
                  'actions': [dict(a) for a in recent[-8:]]}
        from . import daemon
        spool = getattr(daemon, '_spool_report', None)
        if spool:
            report['spool'] = dict(spool)
        daemon._watchdog_report.clear()
        daemon._watchdog_report.update(report)

    @staticmethod
    def sentence(a):
        k = label(a.get('kind') or 'task')
        m = a.get('minutes')
        return {'stopped_deadline': f'stopped a {k} that passed its time limit after {m} minutes',
                'stopped_hung': f'stopped a hung {k}: no output or CPU for {m} minutes',
                'stopped_memory': f'stopped a {k} to keep the container from running out of memory',
                'overcommit': f'let a {k} start before a long scan ended, within the memory that was really free',
                'orphans': 'ended tool processes left behind by a finished task',
                'heartbeat_restart': 'restarted the heartbeat thread, which had stopped',
                'withheld': f'stopped taking {k} work for a while after repeated stops',
                'disk_clean': 'removed its own old temporary files to free disk'}.get(a['code'], a['code'])

    # --- W1 and W2: deadline and no progress -------------------------------------------------------------------------------------------------

    def _tasks(self):
        with self.d._lock:
            return [(tid, st) for tid, st in self.d._in_flight.items() if not st['done'].is_set()]

    def _rule_tasks(self, now, scan):
        live = set()
        for tid, st in self._tasks():
            live.add(tid)
            kind = st.get('kind')
            wd = st.get('wd')
            if wd:
                self._escalate(now, tid, st, wd)
                continue
            if st.get('dropped') or st.get('finishing'):
                continue
            age = now - st.get('started', now)
            limit = deadline_seconds(kind, st.get('budget_s'))
            if age >= limit:
                minutes = int(age // 60)
                self.stop(now, tid, st, 'stopped_deadline', minutes,
                          f'timed out after {minutes} minutes: the Sentinel stopped the {label(kind)} at its time limit of {int(limit // 60)} minutes')
                continue
            idle_limit = no_progress_seconds(kind)
            pgids = {g for g in st.get('pgids', ()) if g in scan and live_pids(scan[g])}
            if idle_limit is None or not pgids:
                self.seen.pop(tid, None)
                continue
            signature = tuple(sorted((g, scan[g]['cpu'], scan[g]['io'], len(scan[g]['pids'])) for g in pgids))
            prev = self.seen.get(tid)
            if prev is None or prev['sig'] != signature:
                self.seen[tid] = {'sig': signature, 'moved': now}
                continue
            idle = now - prev['moved']
            if idle >= idle_limit:
                minutes = int(idle // 60)
                self.stop(now, tid, st, 'stopped_hung', minutes,
                          f'no output and no CPU for {minutes} minutes: the Sentinel stopped the hung {label(kind)}')
        for tid in list(self.seen):
            if tid not in live:
                del self.seen[tid]

    def stop(self, now, tid, st, code, minutes, text):
        """Stop one task: its process group gets SIGTERM now (SIGKILL ``KILL_ESCALATE_SECONDS`` later); the task's own thread then reports ``text``."""
        kind = st.get('kind')
        with self.d._lock:
            if st.get('wd') or st.get('finishing'):
                return False
            st['wd'] = {'code': code, 'text': text[:280], 'at': now, 'killed': False, 'minutes': minutes}
        self.act(code, kind, minutes, f'task {tid}: {text}')
        self._count_kill(now, kind)
        self.d._stop(st.get('proc'))
        return True

    def _count_kill(self, now, kind):
        times = self.kills[kind]
        times.append(now)
        while times and now - times[0] > 3600:
            times.popleft()
        if len(times) >= self.cfg['kill_limit'] and kind not in self.withheld:
            self.withheld[kind] = now + self.cfg['withhold']
            self.act('withheld', kind, None, f'{label(kind)} was stopped {len(times)} times in an hour: no more of it for {self.cfg["withhold"] // 60} minutes '
                     '(the server also cools a kind off after repeated failures)')

    def _escalate(self, now, tid, st, wd):
        age = now - wd['at']
        if age >= KILL_ESCALATE_SECONDS and not wd['killed']:
            wd['killed'] = True
            self.d._kill(st.get('proc'), background=True)
        if age >= ABANDON_SECONDS and not wd.get('abandoned'):
            with self.d._lock:
                if st['done'].is_set() or st.get('finishing') or st.get('dropped'):
                    return
                wd['abandoned'] = True
                st['dropped'] = True  # the task thread, if it ever returns, reports nothing: the watchdog does
                st['dropped_at'] = time.monotonic() - 30.0  # the reaper gives its slot and memory back at its next pass
            logger.error('watchdog: task %s has not ended %ds after it was stopped; reporting it and no longer counting it', tid, int(age))
            self.d._report_in_thread(tid, {'outcome': 'error', 'error': wd['text']})
            self.d._reap_dropped()

    # --- W3: memory --------------------------------------------------------------------------------------------------------------------------

    def _rule_memory(self, now, scan):
        d, cfg = self.d, self.cfg
        mem = self.mem()
        limit, avail = mem.get('limit_mb'), mem.get('avail_mb')
        with d._lock:
            rows = [(tid, st.get('kind'), now - st.get('started', now), st) for tid, st in d._in_flight.items() if not st['done'].is_set() and st.get('kind') != 'openvas']
            blocked = dict(d._blocked_since)
        floor = cfg['floor_mb'] or max(300, int((limit or 0) * 0.15))
        heavy = [(tid, kind, age, st) for tid, kind, age, st in rows if admission.weight(kind) > admission.DEFAULT_WEIGHT_MB]
        estimates = []
        for tid, kind, age, st in rows:
            w = admission.weight(kind)
            rss = sum(scan[g]['rss_mb'] for g in st.get('pgids', ()) if g in scan)
            peak = self.peak[tid] = max(self.peak.get(tid, 0.0), rss)  # the most this run has shown: a run is never estimated below what it already used
            estimates.append(peak * 1.15 if age >= 120 and peak > 0 else w)  # a run that has been going a while has grown to what it will use, plus 15 percent
        for tid in list(self.peak):
            if tid not in {r[0] for r in rows}:
                del self.peak[tid]
        waited = max((now - since for since in blocked.values()), default=0)
        fair = bool(heavy) and min(age for _t, _k, age, _s in heavy) >= cfg['mem_hold']
        new = 0
        if blocked and waited >= cfg['mem_wait'] and fair and limit and cfg['over_pct'] > 0:
            used = d.admission.used([k for _t, k, _a, _s in rows])
            new = compute_overcommit(d.admission.budget, used, estimates, limit, floor, cfg['over_pct'] / 100.0)
        if new != self.overcommit_mb:
            if new and not self.overcommit_mb:
                logger.warning('watchdog: %s waited %ds for memory behind long runs; allowing %d MB over the budget while real free memory stays above %d MB',
                               '/'.join(sorted(blocked)), int(waited), new, int(floor))
            elif self.overcommit_mb and not new:
                logger.info('watchdog: the memory overcommit ended (nobody waits, a holder ended or real free memory is near the floor)')
        self.overcommit_mb = new
        d.admission.overcommit_mb = new
        if cfg['mem_kill'] and avail is not None and heavy and avail < floor / 2:  # last resort, off by default: the kernel would choose worse
            tid, kind, _age, st = min(heavy, key=lambda row: row[2])
            if self.stop(now, tid, st, 'stopped_memory', int(_age // 60),
                         'out of memory, retry later (the Sentinel stopped it to keep the container alive)'):
                self._count_kill(now, kind)

    def note_overcommit_admit(self, kind):
        """The daemon admitted ``kind`` beyond the plain budget: one action, counted for the heartbeat."""
        self.overcommit_admitted += 1
        self.act('overcommit', kind, None, f'{label(kind)} started beside long runs inside a {self.overcommit_mb} MB overcommit')

    # --- W4: orphans and zombies -------------------------------------------------------------------------------------------------------------

    def task_ended(self, state):
        """Called when a task thread (or the reaper) lets go of ``state``: any process group it started that is still alive is watched."""
        now = self.clock()
        for pgid in state.get('pgids', ()):
            self.watch.setdefault(pgid, now)

    def _rule_orphans(self, now, scan):
        me = os.getpid()
        with self.d._lock:
            owned = {g for st in self.d._in_flight.values() if not st['done'].is_set() for g in st.get('pgids', ())}
        for pgid, since in list(self.watch.items()):
            row = scan.get(pgid)
            if pgid in owned:  # the id was reused by a task that runs now
                del self.watch[pgid]
                continue
            if not row:
                del self.watch[pgid]
                continue
            for pid in list(row['zombies']):  # only a direct child of this process whose task is over: nobody else waits for it
                if row['parents'].get(pid) == me:
                    try:
                        os.waitpid(pid, os.WNOHANG)
                        self.reaped_zombies += 1
                    except OSError:
                        pass
            alive = live_pids(row)
            if not alive:
                del self.watch[pgid]
                continue
            if now - since >= 15.0:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except OSError:
                    pass
                self.act('orphans', None, None, f'{len(alive)} tool process(es) of process group {pgid} outlived their task by {int(now - since)}s: killed')
                # the entry stays one more tick: the zombies the kill leaves are reaped then

    # --- W5: liveness ------------------------------------------------------------------------------------------------------------------------

    def _rule_liveness(self, now, scan):
        d = self.d
        if d.stop_event.is_set():
            return
        hb_age = now - d.hb_beat_at
        if hb_age > self.cfg['hb_stale']:
            recent = [t for t in self.hb_restarts if now - t < 1800]
            if recent:
                logger.error('watchdog: the heartbeat loop is stale again (%ds) after a restart: exiting so the supervisor restarts this Sentinel', int(hb_age))
                self._exit(now)
                return
            self.hb_restarts.append(now)
            self.act('heartbeat_restart', None, None, f'the heartbeat loop has not completed a pass for {int(hb_age)}s; starting a new heartbeat thread')
            d.restart_heartbeat()
        poll_age = now - d.poll_beat_at
        if poll_age > self.cfg['poll_stale']:
            logger.error('watchdog: the poll loop has not turned for %ds (a hung lookup or connection): exiting so the supervisor restarts this Sentinel', int(poll_age))
            self._exit(now)

    def _exit(self, now):
        from . import daemon
        d = self.d
        d.exit_code = d.exit_code or daemon.WEDGED
        d.stop_event.set()
        threading.Thread(target=self._hard_exit, name='sentinel-guard-exit', daemon=True).start()

    def _hard_exit(self):
        from . import daemon
        # the daemon's own shutdown gets its grace; a loop that is stuck never reaches it
        if not self.d._halted.wait(config.SHUTDOWN_GRACE_SECONDS + daemon.RELEASE_WAIT_SECONDS + 15):
            logger.error('watchdog: the daemon did not stop in time: ending the process')
            self._flush_logs()
            os._exit(daemon.WEDGED)

    @staticmethod
    def _flush_logs():
        for handler in logging.getLogger().handlers:
            try:
                handler.flush()
            except Exception:  # noqa: BLE001
                pass

    # --- W6: disk ----------------------------------------------------------------------------------------------------------------------------

    @staticmethod
    def _disk_free_mb():
        paths = {control.state_dir(), tempfile.gettempdir()}
        free = []
        for p in paths:
            try:
                free.append(shutil.disk_usage(p).free / MB)
            except OSError:
                continue
        return min(free) if free else None

    def _rule_disk(self, now, scan):
        free = self.disk()
        floor = self.cfg['disk_floor_mb']
        if free is None:
            return
        if free < floor:
            if not self.low_disk:
                self.act('low_disk', None, None, f'{int(free)} MB free (floor {floor} MB): taking no new work and cleaning its own temporary files')
            self.low_disk, self.low_disk_mb = True, int(free)
            freed = self.clean_own_files(now)
            if freed:
                self.act('disk_clean', None, None, f'removed {freed // 1024} KB of its own temporary files')
        elif self.low_disk and free >= floor * 1.5:  # a little hysteresis
            logger.info('watchdog: %d MB free again; taking work', int(free))
            self.low_disk, self.low_disk_mb = False, None
        elif self.low_disk:
            self.low_disk_mb = int(free)

    def clean_own_files(self, now, older=3 * 3600):
        """Remove this Sentinel's own temp and cache files older than ``older`` seconds: its ``cvengine-*``, ``secrets-`` work directories and ``tmp*.txt``
        target lists in the temp directory, and nuclei's cache and resume files. Never the state volume, the spool, templates or anything else."""
        freed = 0
        cut = self.wall() - older
        home = os.path.expanduser('~')
        targets = [(tempfile.gettempdir(), ('cvengine-', 'secrets-', 'tmp'), False),
                   (os.path.join(home, '.cache', 'nuclei'), ('',), True),
                   (os.path.join(home, '.config', 'nuclei'), ('resume-',), False)]
        with self.d._lock:
            busy = bool(self.d._in_flight)
        for base, prefixes, whole in targets:
            try:
                entries = os.listdir(base)
            except OSError:
                continue
            for name in entries:
                if not name.startswith(prefixes):
                    continue
                path = os.path.join(base, name)
                try:
                    st = os.lstat(path)
                    if st.st_mtime > cut or st.st_uid != os.getuid():
                        continue
                    if base == tempfile.gettempdir() and name.startswith('tmp') and not name.endswith('.txt'):
                        continue
                    if whole and busy:  # the cache of a run that may be reading it
                        continue
                    if os.path.isdir(path) and not os.path.islink(path):
                        size = sum(os.path.getsize(os.path.join(r, f)) for r, _d, fs in os.walk(path) for f in fs if os.path.exists(os.path.join(r, f)))
                        shutil.rmtree(path, ignore_errors=True)
                    else:
                        size = st.st_size
                        os.unlink(path)
                    freed += size
                except OSError:
                    continue
        return freed

    # --- W8: withheld kinds ------------------------------------------------------------------------------------------------------------------

    def _rule_withheld(self, now, scan):
        for kind, until in list(self.withheld.items()):
            if now >= until:
                del self.withheld[kind]
                logger.info('watchdog: %s work is offered again', label(kind))

    def filter_kinds(self, kinds):
        """The kinds to ask the server for, less those withheld after repeated stops, and none at all while the disk is low."""
        if self.low_disk:
            return []
        return [k for k in kinds if k not in self.withheld]
