"""Start bbot the way a bbot_discovery task does (client.bbot.build_command, plus --dry-run: modules load and set up, no packet is sent), as whatever
user runs this. Exits non-zero when bbot cannot start, or when it tries to install anything (a running Sentinel has no root and no sudo).

Run by the Dockerfile as the run-time user, and by .github/workflows/image.yml in the built image as uid 10001 under a hostname of its own: bbot keys
its record of installed module dependencies by hostname, so the record written at build never matches in a container, and a client that did not
tell bbot to skip the installer failed here with ``PermissionError: Permission denied: 'sudo'``."""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client import bbot  # noqa: E402

TARGET = {'domain': 'example.com', 'presets': ['subdomain-enum', 'web', 'web-screenshots'], 'require_flags': ['safe'], 'force': True,
          'scope': {'in_scope_domains': ['example.com']}}


def main():
    with tempfile.TemporaryDirectory(prefix='cvengine-bbot-start-') as work:
        blacklist = os.path.join(work, 'blacklist.txt')
        with open(blacklist, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(bbot.Policy(TARGET['scope']).blacklist()) + '\n')
        cmd = bbot.build_command(TARGET, os.path.join(work, 'scans'), blacklist) + ['--dry-run']
        print('uid', os.getuid(), 'hostname', os.uname()[1], 'HOME', os.environ.get('HOME'))
        print('running:', ' '.join(cmd))
        done = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
    output = done.stdout
    print('\n'.join(output.splitlines()[-25:]))
    if done.returncode != 0:
        print(f'bbot cannot start (exit status {done.returncode}): {bbot.start_failure(output.splitlines()) or "see the output above"}', file=sys.stderr)
        return 1
    for marker in ('Installing module dependencies', 'Installing dependencies for module', "'sudo'", 'needs root privileges'):
        if marker in output:
            print(f'bbot tried to install dependencies at start ({marker!r}): the image is missing something a module needs', file=sys.stderr)
            return 1
    print('bbot starts as uid', os.getuid(), 'without installing anything')
    return 0


if __name__ == '__main__':
    sys.exit(main())
