"""Check that the licence texts, the third-party notices and the source offer are in an image: run inside the built image by .github/workflows/image.yml
(mounted read-only, as the image's unprivileged user), so it reads the image itself. docker/licenses/collect.py fails the build on the same gaps; this
is the second look, at what was really built. Exits 1 and names every missing or empty file.
"""
import glob
import os
import sys

DIR = os.environ.get('CVENGINE_LICENSES_DIR', '/usr/share/licenses/cvengine-sentinel')

# file -> a phrase it must contain (None: only present and not empty)
FILES = {
    'LICENSE': 'GNU GENERAL PUBLIC LICENSE',
    'THIRD-PARTY-NOTICES.txt': 'uses the Nmap Security Scanner',
    'SOURCE-OFFER.txt': 'Written offer',
    'nmap/LICENSE': 'Nmap Public Source License',
    'node2shell-scanner/LICENSE': 'Copyright (c) 2026 Assetnote',
    'wpscan/LICENSE': 'WPScan Public Source License',
    'nuclei/LICENSE.md': 'MIT',
    'naabu/LICENSE.md': 'MIT',
    'sshamble/LICENSE.md': None,
    'go/LICENSE': None,
    'gowitness/go.mod': None,
    'gowitness/go.sum': None,
    'gowitness/MODIFICATIONS': 'docker/gotools/build.sh',
    'nuclei/modules/INDEX.txt': None,
    'testssl.sh/LICENSE': None,
    'nuclei-templates/LICENSE.md': None,
    'kingfisher/NOTICE': None,
    'python/venv/INDEX.txt': 'wafw00f',
    'python/bbot-venv/INDEX.txt': 'bbot',
    'ubuntu-packages.txt': None,
}
# patterns that must match at least one non-empty file
GLOBS = ('gowitness/LICENSE*', 'trajan/LICENSE*', 'ruby-gems/wpscan-*/LICENSE', 'python/venv/wafw00f-*/licenses/LICENSE',
         'python/venv/python_gvm-*/licenses/LICENSE', 'python/bbot-venv/bbot-*/licenses/LICENSE', 'python/bbot-venv/blastdns-*/licenses/LICENSE',
         'python/bbot-venv/blasthttp-*/licenses/LICENSE')


def problems(root=DIR):
    bad = []
    for rel, phrase in FILES.items():
        path = os.path.join(root, rel)
        try:
            with open(path, encoding='utf-8', errors='replace') as handle:
                text = handle.read()
        except OSError:
            bad.append(f'{rel} (missing or unreadable)')
            continue
        if not text.strip():
            bad.append(f'{rel} (empty)')
        elif phrase and phrase not in text:
            bad.append(f'{rel} (does not say {phrase!r})')
    for pattern in GLOBS:
        if not any(os.path.getsize(p) > 0 for p in glob.glob(os.path.join(root, pattern)) if os.path.isfile(p)):
            bad.append(f'{pattern} (no file)')
    return bad


def main():
    bad = problems()
    if bad:
        print('licence files missing from the image:\n  ' + '\n  '.join(bad), file=sys.stderr)
        return 1
    count = sum(len(files) for _, _, files in os.walk(DIR))
    print(f'{count} licence and notice files in {DIR}, every required one present')
    return 0


if __name__ == '__main__':
    sys.exit(main())
