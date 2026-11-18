"""What the pinned nuclei-templates release holds, and which of its templates each template policy approves: a shipped index, never the templates.

The cvENGINE server keeps no copy of the template library and runs no nuclei. What it needs to know about the templates (which tags they use and which
products they name, the template that covers a CVE, the product a panel template names, and whether a template may run under the policy in force) it reads
from this index. A Sentinel reads the same index to build the approved set from the templates baked into its image (``client.templates``): a file runs
only when the index records its path with exactly its sha256 and the recorded verdict passes the task's policy. A release whose files differ from what
the index recorded therefore runs nothing that differs, never something unjudged.

The index (``data/nuclei_template_index.json``) is made by ``scripts/generate_template_index.py`` from the release the Sentinel image pins
(``nuclei_templates``, the Dockerfile's ``NUCLEI_TEMPLATES_VERSION``), with this library's own rules: ``checks.readonly_problem`` (read-only and
destination-bound), ``checks.credential_problem`` (a credential of its own) and the credential tags (``flags.NUCLEI_CREDENTIAL_TAGS``). The release gate
(``scripts/check_tool_versions.py``) fails when the pinned release moves and the index is not made again.

Each template entry: ``sha256`` of the file, ``id``, ``tags`` (from ``info.tags``), ``vendor`` and ``product``
(``info.metadata``), ``cpe`` (``part:vendor:product`` of ``info.classification.cpe``) and the verdicts, each the number of a reason in ``reasons`` or
absent when there is nothing to say: ``refuse`` (never runs: larger than the size limit, or not UTF-8), ``ro`` (not read-only, credentials left aside),
``cred`` (sends a credential of its own) and ``ctag`` (tagged as a check that sends credentials).

This module has no side effect and needs nothing but the standard library: it reads one JSON file, once.
"""
import hashlib
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent / 'data'
INDEX_FILE = DATA / 'nuclei_template_index.json'
MAX_TEMPLATE_BYTES = 200_000  # an installed template larger than this never runs (the server's MAX_INSTALLED_TEMPLATE_BYTES, ``checks.MAX_TEMPLATE_BYTES``)
VERDICTS = ('refuse', 'ro', 'cred', 'ctag')

_cache = {}


def _empty():
    return {'nuclei_templates': '', 'rules': 0, 'reasons': [], 'templates': {}, 'sha256': ''}


def load(path=INDEX_FILE):
    """The index: ``{'nuclei_templates', 'rules', 'reasons', 'templates': {path: entry}, 'sha256'}`` (``sha256`` of the file's bytes). A missing or unreadable
    file is an empty index: nothing is approved (the safe side), never everything. Read once."""
    key = str(path)
    if key not in _cache:
        try:
            raw = Path(path).read_bytes()
            data = json.loads(raw.decode('utf-8'))
            templates, reasons = data['templates'], data['reasons']
            if not isinstance(templates, dict) or not isinstance(reasons, list):
                raise TypeError('templates')
            _cache[key] = {'nuclei_templates': str(data.get('nuclei_templates') or ''), 'rules': int(data.get('rules') or 0), 'reasons': reasons,
                           'templates': templates, 'sha256': hashlib.sha256(raw).hexdigest()}
        except (OSError, ValueError, KeyError, TypeError):
            _cache[key] = _empty()
    return _cache[key]


def forget():
    """Drop what was read (a test that points the index elsewhere)."""
    _cache.clear()


def release(index=None):
    """The nuclei-templates release the index describes (``v10.5.2``), or '' with no index."""
    return (index or load())['nuclei_templates']


def digest(index=None):
    """The sha256 of the index file: what a set built from it is named by."""
    return (index or load())['sha256']


def reason(entry, verdict, index=None):
    """The text of one of ``entry``'s verdicts, or '' when it has none."""
    number = entry.get(verdict) if isinstance(entry, dict) else None
    if number is None:
        return ''
    reasons = (index or load())['reasons']
    return str(reasons[number]) if isinstance(number, int) and 0 <= number < len(reasons) else 'template not validated: unknown verdict'


def policy_problem(entry, read_only=True, allow_credentials=False, index=None):
    """Why the installed template ``entry`` may not run under the policy (``read_only``: the read-only set, else every template; ``allow_credentials``: a
    person turned on "Allow checks that send credentials"), or ''. The server's rule for an installed template (``cveFeed.validation.installed_template_problem``):
    a template tagged default-login or bruteforce is refused while credentials are off; under the read-only policy a template must be read-only and, while
    credentials are off, send no credential of its own; with every template allowed only that last rule applies, and nothing at all once credentials are on.
    A template the index refuses outright never runs."""
    if not isinstance(entry, dict):
        return 'template not validated: not in the template index'
    index = index or load()
    refused = reason(entry, 'refuse', index)
    if refused:
        return refused
    if not allow_credentials:
        tagged = reason(entry, 'ctag', index)
        if tagged:
            return tagged
    if read_only:
        problem = reason(entry, 'ro', index)
        if problem:
            return problem
    return '' if allow_credentials else reason(entry, 'cred', index)


def approved(read_only=True, allow_credentials=False, index=None):
    """``{path: entry}`` of the templates the policy approves, in path order."""
    index = index or load()
    return {path: entry for path, entry in sorted(index['templates'].items()) if not policy_problem(entry, read_only, allow_credentials, index)}


def policy_name(read_only=True, allow_credentials=False):
    """A short name of the policy: ``readonly``, ``readonly-cred``, ``all`` or ``all-cred``."""
    return ('readonly' if read_only else 'all') + ('-cred' if allow_credentials else '')


def entry_for(path, index=None):
    """The entry of the template at ``path`` (relative to the release root, ``/`` separated), or ``None``."""
    return (index or load())['templates'].get(str(path or ''))


def _stem(path):
    name = str(path).rsplit('/', 1)[-1]
    return name.rpartition('.')[0].lower() if '.' in name else name.lower()


def _lookups(index):
    """``(by file stem, by sha256)``, each ``{key: [path]}`` in path order, made once per index."""
    if '_lookups' not in index:
        stems, hashes = {}, {}
        for path, entry in sorted(index['templates'].items()):
            stems.setdefault(_stem(path), []).append(path)
            hashes.setdefault(entry.get('sha256'), []).append(path)
        index['_lookups'] = (stems, hashes)
    return index['_lookups']


def for_cve(cve_id, index=None):
    """``[(path, entry)]`` of the templates named for ``cve_id`` (the file is ``CVE-2021-44228.yaml``: upstream names a CVE's template by its id), in path
    order."""
    index = index or load()
    wanted = str(cve_id or '').strip().lower()
    return [(path, index['templates'][path]) for path in _lookups(index)[0].get(wanted, [])] if wanted else []


def by_sha256(sha256, index=None):
    """``[(path, entry)]`` of the templates whose file hashes to ``sha256``."""
    index = index or load()
    return [(path, index['templates'][path]) for path in _lookups(index)[1].get(sha256, [])]
