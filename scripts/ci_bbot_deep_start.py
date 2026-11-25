"""Start a DEEP bbot discovery (the kitchen-sink preset, which is what the UI's "run deep discovery" starts) the way a bbot_discovery task does
(client.bbot.build_command with the blacklist the client writes), as whatever user runs this, three times one after another, and fails when any of
them is dead in its first 10 seconds. Each run is stopped before the next starts, as the Sentinel runs deep discoveries one at a time
(client.daemon.Daemon._deep_bbot): three at once were killed by the kernel (-9) under the 2 GB container limit. The runs still share HOME/.bbot,
as every run in a running Sentinel does, so a later run starts on the state an earlier one left there.

Why: the kitchen-sink preset adds a regex entry to bbot's blacklist, and a blacklist that also held a one-address network (``::1/128``) made bbot
die at start with ``TypeError: '<' not supported between instances of 'int' and 'str'`` (bbot/scanner/target.py, Target.add), in under a second.
The ``--dry-run`` start of ci_bbot_start.py does not run the preset the UI's deep mode uses, so it could not see it.

Run by .github/workflows/image.yml and scripts/ci_scan_smoke.sh in the built image as uid 10001 under a hostname of its own. It scans example.com
for ten seconds per run, about thirty seconds in all."""
import os
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client import bbot  # noqa: E402

TARGET = {'domain': 'example.com', 'presets': ['kitchen-sink'], 'force': True, 'mode': 'deep', 'scope': {'in_scope_domains': ['example.com']}}
STARTS, ALIVE_SECONDS = 3, 10


def _stop(proc):
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()


def main():
    with tempfile.TemporaryDirectory(prefix='cvengine-bbot-deep-') as work:
        blacklist = os.path.join(work, 'blacklist.txt')
        with open(blacklist, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(bbot.Policy(TARGET['scope']).blacklist()) + '\n')
        print('uid', os.getuid(), 'hostname', os.uname()[1], 'HOME', os.environ.get('HOME'))
        failed = 0
        for i in range(STARTS):
            out_dir = os.path.join(work, f'scans{i}')
            os.mkdir(out_dir, 0o700)
            with open(os.path.join(work, f'stderr{i}.txt'), 'w+', encoding='utf-8') as err:
                cmd = bbot.build_command(TARGET, out_dir, blacklist)
                if i == 0:
                    print('running:', ' '.join(cmd))
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err, text=True, start_new_session=True)
                try:
                    proc.wait(timeout=ALIVE_SECONDS)
                    dead = True  # it ended inside its first ten seconds: dead, whatever its status
                except subprocess.TimeoutExpired:
                    dead = False
                _stop(proc)
                if dead:
                    failed += 1
                    err.seek(0)
                    tail = err.read().splitlines()[-25:]
                    print(f'--- deep bbot start {i} died within {ALIVE_SECONDS}s (status {proc.returncode}): {bbot.crash_summary(tail) or "no exception line"}',
                          file=sys.stderr)
                    print('\n'.join(tail), file=sys.stderr)
        if failed:
            return 1
    print(f'{STARTS} deep bbot starts one after another as uid {os.getuid()}, sharing HOME/.bbot, were each alive after {ALIVE_SECONDS}s')
    return 0


if __name__ == '__main__':
    sys.exit(main())
