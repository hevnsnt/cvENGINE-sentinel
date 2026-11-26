"""Gather the license texts of what the image carries into /usr/share/licenses/cvengine-sentinel, then check the ones the notices promise are there.

Run by the Dockerfile as root, near the end of the build, after every tool is installed. The Sentinel's own LICENSE, THIRD-PARTY-NOTICES.txt,
SOURCE-OFFER.txt, the nmap and node2shell texts (docker/licenses) and the Go tools' licences (the gotools stage's /out/doc) are copied in before it
runs; this adds what only exists once the tools are installed: WPScan and its gems, testssl.sh, the nuclei templates, Kingfisher's notices, every
Python package of both venvs, Chromium's files, the tools bbot installed and the Ubuntu package list. Exits 1 when a promised text is missing, so a
build that would ship without one fails.
"""
import email.message
import email.parser
import glob
import os
import shutil
import subprocess
import sys

DEST = os.environ.get('CVENGINE_LICENSES_DIR', '/usr/share/licenses/cvengine-sentinel')
NAMES = ('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT', 'MIT-LICENSE', 'AUTHORS', 'PATENTS', 'CREDITS', 'ABOUT')


def is_license(name):
    upper = os.path.basename(name).upper()
    return any(upper.startswith(n) for n in NAMES) or 'CREDITS' in upper


def copy_files(src_dir, dest_dir, depth=1):
    """Copy the license-like files of ``src_dir`` (and of its subdirectories up to ``depth`` levels) to ``dest_dir``. Returns how many."""
    found = 0
    src_dir = os.path.abspath(src_dir)
    for here, dirs, files in os.walk(src_dir):
        level = here[len(src_dir):].count(os.sep)
        if level >= depth:
            dirs[:] = []
        for name in files:
            path = os.path.join(here, name)
            if is_license(name) and os.path.isfile(path) and not os.path.islink(path):
                target = os.path.join(dest_dir, os.path.relpath(path, src_dir))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copyfile(path, target)
                found += 1
    return found


def copy_tree(src, dest):
    if os.path.isdir(src):
        shutil.copytree(src, dest, dirs_exist_ok=True)


def ruby_gems():
    try:
        paths = subprocess.run(['gem', 'env', 'gempath'], capture_output=True, text=True, timeout=60).stdout.strip().split(':')
    except (OSError, subprocess.SubprocessError):
        paths = []
    for gem_dir in sorted({g for p in paths if p for g in glob.glob(os.path.join(p, 'gems', '*'))}):
        name = os.path.basename(gem_dir)
        copy_files(gem_dir, os.path.join(DEST, 'ruby-gems', name))
        if name.startswith('wpscan-'):
            copy_files(gem_dir, os.path.join(DEST, 'wpscan'))


def python_venv(venv, label):
    rows = []
    for info in sorted(glob.glob(os.path.join(venv, 'lib', 'python*', 'site-packages', '*.dist-info'))):
        base = os.path.basename(info)[:-len('.dist-info')]
        dest = os.path.join(DEST, 'python', label, base)
        copy_files(info, dest, depth=4)  # wheel metadata 2.4 keeps them under licenses/, sometimes a level or two deeper
        meta = email.message.Message()
        try:
            with open(os.path.join(info, 'METADATA'), encoding='utf-8', errors='replace') as handle:
                meta = email.parser.Parser().parse(handle, headersonly=True)
        except OSError:
            pass
        licence = (meta.get('License-Expression') or '').strip()
        if not licence:
            raw = (meta.get('License') or '').strip()
            licence = raw.splitlines()[0] if raw else ''
        if not licence or len(licence) > 80:  # a whole license text pasted into the field: the classifiers say it shorter
            classifiers = [c.split('::')[-1].strip() for c in (meta.get_all('Classifier') or []) if c.startswith('License ::')]
            licence = '; '.join(classifiers) or (licence[:80] if licence else 'not stated')
        rows.append(f"{meta.get('Name') or base}\t{meta.get('Version') or ''}\t{licence}")
    if rows:
        os.makedirs(os.path.join(DEST, 'python', label), exist_ok=True)
        with open(os.path.join(DEST, 'python', label, 'INDEX.txt'), 'w', encoding='utf-8') as handle:
            handle.write('name\tversion\tdeclared license\n' + '\n'.join(rows) + '\n')


def chromium():
    for root in glob.glob('/opt/pw-browsers/*'):
        copy_files(root, os.path.join(DEST, 'chromium', os.path.basename(root)), depth=3)


def bbot_tools():
    tools = '/home/sentinel/.bbot/tools'
    if not os.path.isdir(tools):
        return
    os.makedirs(os.path.join(DEST, 'bbot-tools'), exist_ok=True)
    names = sorted(os.listdir(tools))
    with open(os.path.join(DEST, 'bbot-tools', 'INDEX.txt'), 'w', encoding='utf-8') as handle:
        handle.write('Installed by bbot for its modules (gowitness and trajan are built by this image, see ../gowitness and ../trajan):\n')
        handle.write(''.join(f'{n}\n' for n in names))
    for name in names:
        path = os.path.join(tools, name)
        if os.path.isdir(path):
            copy_files(path, os.path.join(DEST, 'bbot-tools', name), depth=3)


def ubuntu_packages():
    out = subprocess.run(['dpkg-query', '-W', '-f', '${Package}\t${Version}\t${source:Package}\t${source:Version}\n'],
                         capture_output=True, text=True, timeout=120, check=True).stdout
    with open(os.path.join(DEST, 'ubuntu-packages.txt'), 'w', encoding='utf-8') as handle:
        handle.write('package\tversion\tsource package\tsource version\n' + out)


# What THIRD-PARTY-NOTICES.txt promises. A directory entry needs at least one license-like file in it.
REQUIRED_FILES = ('LICENSE', 'THIRD-PARTY-NOTICES.txt', 'SOURCE-OFFER.txt', 'nmap/LICENSE', 'node2shell-scanner/LICENSE', 'wpscan/LICENSE',
                  'gowitness/go.mod', 'gowitness/go.sum', 'gowitness/MODIFICATIONS', 'python/venv/INDEX.txt', 'python/bbot-venv/INDEX.txt',
                  'ubuntu-packages.txt')
REQUIRED_DIRS = ('nuclei', 'naabu', 'sshamble', 'gowitness', 'trajan', 'go', 'testssl.sh', 'nuclei-templates', 'kingfisher', 'ruby-gems')
REQUIRED_PYTHON = (('venv', 'wafw00f-'), ('venv', 'python_gvm-'), ('bbot-venv', 'bbot-'), ('bbot-venv', 'blastdns-'), ('bbot-venv', 'blasthttp-'))


def has_license(path):
    return any(is_license(n) for _, _, files in os.walk(path) for n in files)


def check():
    missing = [f for f in REQUIRED_FILES if not os.path.isfile(os.path.join(DEST, f)) or os.path.getsize(os.path.join(DEST, f)) == 0]
    missing += [d + '/' for d in REQUIRED_DIRS if not has_license(os.path.join(DEST, d))]
    for venv, prefix in REQUIRED_PYTHON:
        if not any(has_license(p) for p in glob.glob(os.path.join(DEST, 'python', venv, prefix + '*'))):
            missing.append(f'python/{venv}/{prefix}*')
    return missing


def main():
    os.makedirs(DEST, exist_ok=True)
    ruby_gems()
    copy_files('/opt/testssl', os.path.join(DEST, 'testssl.sh'))
    copy_files('/home/sentinel/nuclei-templates', os.path.join(DEST, 'nuclei-templates'))
    copy_tree('/usr/share/doc/kingfisher', os.path.join(DEST, 'kingfisher'))
    python_venv('/opt/venv', 'venv')
    python_venv('/opt/bbot-venv', 'bbot-venv')
    chromium()
    bbot_tools()
    ubuntu_packages()
    for here, dirs, files in os.walk(DEST):
        for name in dirs:
            os.chmod(os.path.join(here, name), 0o755)
        for name in files:
            os.chmod(os.path.join(here, name), 0o644)
    missing = check()
    count = sum(len(files) for _, _, files in os.walk(DEST))
    if missing:
        print('license texts missing from the image: ' + ', '.join(missing), file=sys.stderr)
        return 1
    print(f'{count} license and notice files in {DEST}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
