#!/usr/bin/env python3
"""Report which pinned tools of the Sentinel image are behind their newest release.

  python3 scripts/check_tool_versions.py [--json] [--fail-if-behind] [--github-warnings] [--root DIR]

Every tool the image is built from is pinned: the ``ARG ..._VERSION`` lines of the Dockerfile, the ``name==version`` lines of requirements.txt (and the
test extra of pyproject.toml), the pip bootstrap pins in the Dockerfile, the Ubuntu base image digest and the Greenbone images pinned by digest in
docker-compose.yml. This reads all of them and compares each with its upstream (GitHub releases and tags, PyPI, proxy.golang.org, go.dev/dl,
rubygems.org, nmap.org, Docker Hub, the Greenbone registry, Chrome's version history) and prints a table: tool, pinned, latest, state.

Exit status is 0 whatever the answer, 2 when the script itself crashes, or 1 with --fail-if-behind when any tool is behind, a pin cannot be found in its file, a version ARG has no known
upstream, or a newest version cannot be read (the gate fails closed: a renamed pin or an unreachable site must not pass a release; the weekly report,
which runs without the flag, shows such a row as "unknown" and never calls it behind). --github-warnings adds one ``::warning::`` line per problem for
the pull request job, which reports and never fails. The workflows are .github/workflows/tool-releases.yml (weekly, pull requests) and the release gate
in tag-release.yml.

The Chromium build Playwright drives is an advisory row (Chrome's newest stable is compared; the build is fixed by the Playwright pin, so it moves
with that release): shown, never a gate. Not covered: the gems of docker/wpscan/Gemfile.lock (WPScan's own pin is) and the nuclei templates the
server supplies at run time (the baked-in set is).

The nuclei-templates pin has a second gate: the service-port allowlist (cvengine_scanner/data/nuclei_service_allowlist.json, made by
scripts/generate_service_allowlist.py) lists the templates a service run may send for ONE release. When the pinned release is not the release the list was generated
for (or the list is missing), the line "regenerate the service-port allowlist" is printed and --fail-if-behind fails: a new release must be regenerated and reviewed
before it ships, because a template the list does not know is not run on a service port.

Network use is this script's own fixed https lookups; the tests feed recorded answers and never touch the network (client/tests/test_tool_versions.py)."""
import json
import os
import re
import sys
import traceback
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# PyPI's JSON for a package with many releases (cryptography, pymongo) is several MB, and a cut-off answer is not JSON: it would read as "unknown".
MAX_ANSWER = 30_000_000
GREENBONE = 'registry.community.greenbone.net'
GREENBONE_ACCEPT = ', '.join(('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json',
                              'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'))


def version_key(text):
    return tuple(int(part) for part in re.findall(r'\d+', text))


def fetch(url, as_json=True):
    headers = {'User-Agent': 'cvengine-sentinel-tool-check', 'Accept': 'application/json, text/html'}
    # Unauthenticated, api.github.com allows 60 requests an hour per address, which shared CI runners use up: the lookup then reads as "unknown",
    # and the gate (which fails closed) turns red for no reason. The token goes to GitHub's API and to nothing else.
    token = os.environ.get('GITHUB_TOKEN', '')
    if token and url.startswith('https://api.github.com/'):
        headers['Authorization'] = 'Bearer ' + token
    if url.startswith(f'https://{GREENBONE}/v2/'):
        return greenbone_digest(url)
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https URLs below
        body = response.read(MAX_ANSWER).decode('utf-8', 'replace')
    return json.loads(body) if as_json else body


def greenbone_digest(url):
    """The digest the registry serves for a manifest URL (the ``stable`` tag): ``{'digest': 'sha256:...'}``. The registry hands out an anonymous pull token."""
    image = re.search(r'/v2/(community/[a-z0-9-]+)/manifests/', url).group(1)
    token_url = f'https://{GREENBONE}/service/token?service=harbor-registry&scope=repository:{image}:pull'
    with urllib.request.urlopen(urllib.request.Request(token_url, headers={'User-Agent': 'cvengine-sentinel-tool-check'}), timeout=30) as response:  # noqa: S310
        token = json.loads(response.read(100_000).decode('utf-8', 'replace'))['token']
    request = urllib.request.Request(url, method='HEAD', headers={'Authorization': 'Bearer ' + token, 'Accept': GREENBONE_ACCEPT})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return {'digest': response.headers.get('Docker-Content-Digest', '')}


# ----------------------------------------------------------------------------- how each upstream answers

def latest_nmap(html):
    versions = re.findall(r'nmap-(\d+\.\d+(?:\.\d+)?)\.tar\.bz2', html or '')
    return max(versions, key=version_key) if versions else None


def latest_rubygem(data):
    return str(data.get('version') or '') or None


def latest_go_module(data):
    """proxy.golang.org/<module>/@latest answers {"Version": "v3.11.1"}: the newest release that is not a pre-release."""
    return str(data.get('Version') or '').lstrip('v') or None


def latest_pypi(data):
    return str((data.get('info') or {}).get('version') or '') or None


def latest_go_toolchain(data):
    """go.dev/dl/?mode=json lists releases newest first: [{"version": "go1.27.3", "stable": true}, ...]."""
    for release in data if isinstance(data, list) else []:
        if release.get('stable'):
            return str(release.get('version') or '').removeprefix('go') or None
    return None


def latest_github_release(data):
    """api.github.com/repos/<repo>/releases/latest answers {"tag_name": "v2.18.1"}."""
    return str(data.get('tag_name') or '').lstrip('v') or None


def latest_github_tag(data):
    """api.github.com/repos/<repo>/tags lists the newest first: the newest plain vX.Y(.Z) tag (development tags such as v3.3dev are ignored)."""
    names = [t.get('name', '') for t in data] if isinstance(data, list) else []
    versions = [n.lstrip('v') for n in names if re.fullmatch(r'v\d+\.\d+(?:\.\d+)?', n)]
    return max(versions, key=version_key) if versions else None


def latest_chrome_stable(data):
    """versionhistory.googleapis.com lists Chrome's releases on a channel: [{"version": "158.0.8127.18"}, ...]."""
    versions = [str(v.get('version') or '') for v in (data.get('versions') or [])] if isinstance(data, dict) else []
    versions = [v for v in versions if re.fullmatch(r'\d+(?:\.\d+){3}', v)]
    return max(versions, key=version_key) if versions else None


def digest_of(data):
    """Docker Hub's tag endpoint and the Greenbone lookup answer {"digest": "sha256:..."}."""
    digest = str(data.get('digest') or '') if isinstance(data, dict) else ''
    return digest if re.fullmatch(r'sha256:[0-9a-f]{64}', digest) else None


GO_PROXY = 'https://proxy.golang.org/{}/@latest'
PYPI = 'https://pypi.org/pypi/{}/json'
GITHUB_LATEST = 'https://api.github.com/repos/{}/releases/latest'
CHROME = 'https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions'

# Dockerfile ARG -> (label, where the newest version is read from, how to read it, required, advisory). A version ARG missing here fails the gate closed.
DOCKERFILE_ARGS = {
    'GOVERSION': ('go (toolchain)', 'https://go.dev/dl/?mode=json', latest_go_toolchain, True, False),
    'NMAPVERSION': ('nmap', 'https://nmap.org/dist/', latest_nmap, True, False),
    'NUCLEI_VERSION': ('nuclei', GO_PROXY.format('github.com/projectdiscovery/nuclei/v3'), latest_go_module, True, False),
    'NAABU_VERSION': ('naabu', GO_PROXY.format('github.com/projectdiscovery/naabu/v2'), latest_go_module, True, False),
    'WPSCAN_VERSION': ('wpscan', 'https://rubygems.org/api/v1/gems/wpscan.json', latest_rubygem, True, False),
    'WAFW00F_VERSION': ('wafw00f', PYPI.format('wafw00f'), latest_pypi, True, False),
    'PYSOCKS_VERSION': ('pysocks', PYPI.format('PySocks'), latest_pypi, True, False),
    'TESTSSL_VERSION': ('testssl.sh', 'https://api.github.com/repos/testssl/testssl.sh/tags?per_page=30', latest_github_tag, True, False),
    'BBOT_VERSION': ('bbot', PYPI.format('bbot'), latest_pypi, True, False),
    'TZDATA_VERSION': ('tzdata', PYPI.format('tzdata'), latest_pypi, True, False),
    'BLASTDNS_VERSION': ('blastdns', PYPI.format('blastdns'), latest_pypi, True, False),
    'BLASTHTTP_VERSION': ('blasthttp', PYPI.format('blasthttp'), latest_pypi, True, False),
    'BADDNS_VERSION': ('baddns', PYPI.format('baddns'), latest_pypi, True, False),
    'BADSECRETS_VERSION': ('badsecrets', PYPI.format('badsecrets'), latest_pypi, True, False),
    'KINGFISHER_VERSION': ('kingfisher', GITHUB_LATEST.format('mongodb/kingfisher'), latest_github_release, True, False),
    'SSHAMBLE_VERSION': ('sshamble', GITHUB_LATEST.format('runZeroInc/sshamble'), latest_github_release, True, False),
    'NUCLEI_TEMPLATES_VERSION': ('nuclei-templates', GITHUB_LATEST.format('projectdiscovery/nuclei-templates'), latest_github_release, True, False),
    'PLAYWRIGHT_CHROMIUM_VERSION': ('chromium (Playwright build)', CHROME, latest_chrome_stable, False, True),
}
# The pip bootstrap pins of the Dockerfile (pip install ... pip==25.2 setuptools==80.9.0 ...), checked as the PyPI packages they are.
BOOTSTRAP = ('pip', 'setuptools', 'wheel', 'setuptools-scm', 'packaging')


def all_urls():
    """Every fixed lookup address (the digest lookups are built from the pins they check)."""
    return sorted({url for _, url, *_ in DOCKERFILE_ARGS.values()} | {PYPI.format('pip')})


# ----------------------------------------------------------------------------- reading the pins

def read(root, name):
    path = Path(root) / name
    return path.read_text(encoding='utf-8') if path.is_file() else ''


def row(name, have, latest, advisory=False):
    behind = bool(have and latest and version_key(have) < version_key(latest))
    if advisory:
        return {'tool': name, 'pinned': have, 'latest': latest, 'behind': False, 'behind_advisory': behind, 'advisory': True}
    return {'tool': name, 'pinned': have, 'latest': latest, 'behind': behind}


def digest_row(name, have, latest):
    short = lambda digest: digest[:19] if digest else None  # noqa: E731 - "sha256:" and 12 hex characters
    return {'tool': name, 'pinned': short(have), 'latest': short(latest), 'behind': bool(have and latest and have != latest)}


def safely(get, url, as_json=True):
    """The answer, or None when the site cannot be reached: one unreachable site must not hide the others."""
    try:
        return get(url, as_json)
    except Exception:  # noqa: BLE001 - network, HTTP and JSON errors all mean "unknown"
        return None


def pins(root):
    """Every pin as ``(label, pinned, url, reader, make, as_json)``: ``make`` turns (label, pinned, newest) into a row."""
    found = []
    dockerfile = read(root, 'Dockerfile')
    for arg, (label, url, reader, required, advisory) in DOCKERFILE_ARGS.items():
        match = re.search(rf'(?m)^ARG {arg}=v?(\S+)$', dockerfile)
        if match or required:
            found.append((label, match.group(1) if match else None, url, reader, (lambda n, h, l, a=advisory: row(n, h, l, a)), url != 'https://nmap.org/dist/'))
    for arg in re.findall(r'(?m)^ARG ([A-Z0-9_]*VERSION)=\S+$', dockerfile):
        if arg not in DOCKERFILE_ARGS:  # a pin nobody taught this script about: no upstream, so the gate fails closed
            found.append((arg, re.search(rf'(?m)^ARG {arg}=v?(\S+)$', dockerfile).group(1), None, None, row, True))
    for name, version in sorted(set(re.findall(rf'\b({"|".join(BOOTSTRAP)})==(\d[\d.]*)', dockerfile))):
        found.append((name, version, PYPI.format(name), latest_pypi, row, True))
    for image, tag, digest in sorted(set(re.findall(r'(?m)^FROM ([a-z0-9._/-]+):([\w.-]+)@(sha256:[0-9a-f]{64})', dockerfile))):
        found.append((f'{image}:{tag} (base image)', digest, f'https://hub.docker.com/v2/repositories/library/{image}/tags/{tag}', digest_of, digest_row, True))
    requirements = read(root, 'requirements.txt')
    seen = set()
    for line in requirements.splitlines():
        match = re.match(r'([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.]*)', line)
        if match:
            seen.add(match.group(1).lower())
            found.append((match.group(1).lower(), match.group(2), PYPI.format(match.group(1)), latest_pypi, row, True))
    for name, version in re.findall(r'"([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.]*)"', read(root, 'pyproject.toml')):
        if name.lower() not in seen:
            seen.add(name.lower())
            found.append((name.lower(), version, PYPI.format(name), latest_pypi, row, True))
    compose = read(root, 'docker-compose.yml')
    for image, digest in sorted(set(re.findall(rf'{re.escape(GREENBONE)}/community/([a-z0-9-]+):stable@(sha256:[0-9a-f]{{64}})', compose))):
        found.append((f'greenbone {image}', digest, f'https://{GREENBONE}/v2/community/{image}/manifests/stable', digest_of, digest_row, True))
    return found


ALLOWLIST = 'cvengine_scanner/data/nuclei_service_allowlist.json'


def allowlist_problem(root=ROOT):
    """The line to print when the service-port allowlist is not the one for the pinned nuclei-templates release, else ``None``: a different release, or a list that is
    missing or unreadable (the gate fails closed, like every other pin)."""
    match = re.search(r'(?m)^ARG NUCLEI_TEMPLATES_VERSION=v?(\S+)$', read(root, 'Dockerfile'))
    if not match:
        return None  # no pin: the pin's own row already says so
    pinned = match.group(1)
    fix = 'regenerate the service-port allowlist (python3 scripts/generate_service_allowlist.py --templates <the pinned nuclei-templates> --write), review what it keeps and leaves out, and commit it'
    try:
        generated = str(json.loads(read(root, ALLOWLIST))['nuclei_templates']).lstrip('v')
    except (ValueError, KeyError, TypeError):
        return f'The service-port allowlist ({ALLOWLIST}) is missing or unreadable: {fix}.'
    if generated != pinned:
        return f'nuclei-templates is pinned at {pinned} but the service-port allowlist was generated for {generated or "no release"}: {fix}.'
    return None


def collect(get=fetch, root=ROOT):
    rows, cache = [], {}
    for label, have, url, reader, make, as_json in pins(root):
        latest = None
        if url:
            if url not in cache:
                cache[url] = safely(get, url, as_json)
            answer = cache[url]
            latest = reader(answer) if answer else None
        rows.append(make(label, have, latest))
    return rows


# ----------------------------------------------------------------------------- output

def state(r):
    if r.get('behind_advisory'):
        return 'behind (advisory)'
    if r['behind']:
        return 'behind'
    return 'unknown' if r['pinned'] is None or r['latest'] is None else 'current'


def report(rows):
    lines = ['| Tool | Pinned | Latest | State |', '| --- | --- | --- | --- |']
    lines += [f"| {r['tool']} | {r['pinned'] or '?'} | {r['latest'] or '?'} | {state(r)} |" for r in rows]
    return '\n'.join(lines)


def warnings(rows):
    lines = []
    for r in rows:
        if r['behind'] or r.get('behind_advisory'):
            lines.append(f"::warning::{r['tool']}: {r['pinned']} is pinned, {r['latest']} is the newest release.")
        elif r['pinned'] is None:
            lines.append(f"::warning::{r['tool']}: its pin was not found in the repository.")
        elif r['latest'] is None:
            lines.append(f"::warning::{r['tool']}: the newest release could not be read.")
    return lines


def failing(rows):
    """The rows the release gate refuses: behind, no pin found or no newest version (advisory rows never)."""
    return [r for r in rows if not r.get('advisory') and (r['behind'] or r['pinned'] is None or r['latest'] is None)]


def run(argv=None):
    """``main``, with a crash turned into exit status 2: Python exits 1 on an uncaught error, which is also the gate's answer "behind", and the release
    workflow lets a reasoned override pass 1 but never a crash."""
    try:
        main(argv)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001 - whatever went wrong, the gate must not read it as "behind"
        traceback.print_exc()
        sys.exit(2)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    root = Path(argv[argv.index('--root') + 1]) if '--root' in argv else ROOT
    rows = collect(root=root)
    problem = allowlist_problem(root)
    print(json.dumps(rows) if '--json' in argv else report(rows))
    if problem:
        print(problem, file=sys.stderr if '--json' in argv else sys.stdout)
    if '--github-warnings' in argv:
        print('\n'.join(warnings(rows) + ([f'::warning::{problem}'] if problem else [])))
    if '--fail-if-behind' in argv and (failing(rows) or problem):
        sys.exit(1)


if __name__ == '__main__':
    run()
