"""Other sites served from the same address, copied from cvENGINE's ``cveFeed.vhost_scan`` (the ``vhost_probe`` kind).

One address can serve several sites, told apart by the Host header (and, over TLS, the server name). cvENGINE picks the addresses and the names
(only names the project already knows, in scope, not asked within the ledger window) and decides what an answer means; this module asks. For
each address of a task:

- one GET of ``/`` at the address itself (the default response, what the address answers any name with);
- one GET of ``/`` for each name, sent to that address with the name as the Host header (and the TLS server name), no body, no cookie, no
  credential, redirects never followed, 64 KB read at most;
- for a name whose answer differs from the default, the name's own site: the front page cvENGINE stored for it (sent with the task), else one GET
  of the name at the address it resolves to.

Every request is paced at the task's ``gap`` and passes the task's scope policy and this Sentinel's floor. An edge that challenges the request
ends the address (reported as ``challenged``, never retried or worked around); a plain 429 or 503 ends it too (``busy``). A request the policy
refuses, or that could not be made at all, is simply not reported: cvENGINE reads that as unknown and asks again later, never as "no site here".

The verdict rules (``fingerprint_of``, ``similar``, ``classify``) are cvENGINE's; they are used here to decide which pages to send back, and
cvENGINE applies them again to the fingerprints it receives. The page of a name judged distinct is returned so cvENGINE can read the versions it
states.
"""
import logging
import time
from http.client import HTTPException
from urllib.parse import urlsplit

from . import http, names
from .policy import ScopePolicy
from .version_probes import challenge_of

logger = logging.getLogger(__name__)

MAX_ADDRESSES = 10
MAX_NAMES = 200
MAX_RESPONSE_BYTES = 64 * 1024  # cveFeed.slow_web.MAX_RESPONSE_BYTES
MAX_PAGE_BODY = 64 * 1024
MIN_GAP, MAX_GAP = 0.2, 60.0
ANSWERS = (200, 301, 302, 303, 307, 308, 401, 403)  # a name the address serves: anything else is "no such site here"
SCHEMES = ('http', 'https')


# ----------------------------------------------------------------------------- fingerprints and the verdict (pure)

def location_path(location):
    """The part of a redirect target that says where it leads, without the host (a name redirects to itself, an address to its address)."""
    if not location:
        return ''
    try:
        parts = urlsplit(location.strip())
    except ValueError:
        return ''
    return ((parts.path or '/') + ('?' + parts.query if parts.query else '')).lower()[:200]


def fingerprint_of(response):
    """What is compared between two answers: status, title, length and where a redirect leads. Never the body."""
    body = response.get('body') or ''
    title = response.get('title')
    if title is None:
        title = http.page_title(body)
    return {'status': int(response.get('status') or 0), 'title': ' '.join(str(title or '').split())[:200],
            'length': int(response.get('bytes') if response.get('bytes') is not None else len(body)),
            'location': location_path(response.get('location')), 'server': str(response.get('server') or '')[:60]}


def similar(a, b):
    """Whether two fingerprints are the same answer: both redirect to the same place, or the same status, the same title and a length within
    10% (or 64 bytes)."""
    a_redirect, b_redirect = 300 <= a['status'] < 400, 300 <= b['status'] < 400
    if a_redirect or b_redirect:
        return a_redirect and b_redirect and a['location'] == b['location']
    if a['status'] != b['status'] or a['title'].lower() != b['title'].lower():
        return False
    return abs(a['length'] - b['length']) <= max(64, 0.1 * max(a['length'], b['length']))


def classify(candidate, default, own):
    """``no_answer`` (the address has no site for this name), ``default_site`` (it answers as it answers any name), ``same_app`` (it answers
    as the name's own site does elsewhere) or ``distinct`` (another application). ``default`` and ``own`` are fingerprints or None."""
    if candidate['status'] not in ANSWERS:
        return 'no_answer'
    if default is not None and similar(candidate, default):
        return 'default_site'
    if own is not None and similar(candidate, own):
        return 'same_app'
    return 'distinct'


def busy(response):
    """A plain "try later" (429, 503 with no edge signature): not a result, and not asked again at this sweep."""
    return (response.get('status') or 0) in (429, 503) and not response.get('challenge')


def authority(host, port, scheme):
    """``host`` or ``host:port`` for a URL, the port omitted when it is the scheme's default, an IPv6 literal bracketed."""
    name = f'[{host}]' if ':' in host else host
    return name if port == (443 if scheme == 'https' else 80) else f'{name}:{port}'


def page_of(response):
    """What a distinct application's own page states: the response cvENGINE reads versions from, clipped."""
    headers = response.get('headers') or {}
    return {'status': int(response.get('status') or 0), 'title': str(response.get('title') or '')[:300], 'server': str(response.get('server') or '')[:200],
            'content_type': str(response.get('content_type') or '')[:100], 'powered_by': str(response.get('powered_by') or '')[:200],
            'url': str(response.get('url') or '')[:500], 'body': str(response.get('body') or '')[:MAX_PAGE_BODY],
            'headers': {str(k)[:100]: str(v)[:200] for k, v in list(headers.items())[:60]}}


# ----------------------------------------------------------------------------- the task

def _fingerprint(raw):
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError('a stored front page is malformed')
    try:
        return {'status': int(raw['status']), 'title': str(raw['title'])[:200], 'length': int(raw['length']), 'location': str(raw['location'])[:200],
                'server': str(raw['server'])[:60]}
    except (KeyError, TypeError, ValueError):
        raise ValueError('a stored front page is malformed') from None


def _item(raw):
    if not isinstance(raw, dict):
        return None
    ident, address, scheme, port = raw.get('id'), raw.get('address'), raw.get('scheme'), raw.get('port')
    if not all(isinstance(v, str) and v for v in (ident, address)) or scheme not in SCHEMES:
        return None
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        return None
    if not names.is_ip(address):
        return None
    raw_names = raw.get('names')
    if not isinstance(raw_names, list) or not raw_names or len(raw_names) > MAX_NAMES:
        return None
    entries = []
    for entry in raw_names:
        name = names.clean(entry.get('name')) if isinstance(entry, dict) and isinstance(entry.get('name'), str) else ''
        if not name or len(name) > 253 or any(c.isspace() or ord(c) < 32 for c in name):
            return None
        entries.append({'name': name, 'own': _fingerprint(entry.get('own'))})
    return {'id': str(ident)[:300], 'address': str(address).strip('[]'), 'scheme': scheme, 'port': port, 'names': entries}


class Gap:
    """Waits ``seconds`` between two requests of one task. ``sleep`` and ``clock`` are replaced in tests."""

    def __init__(self, seconds, sleep=time.sleep, clock=time.monotonic):
        self.seconds, self.sleep, self.clock = seconds, sleep, clock
        self.last = None

    def wait(self):
        if self.last is not None:
            remaining = self.seconds - (self.clock() - self.last)
            if remaining > 0:
                self.sleep(remaining)
        self.last = self.clock()


def clamp_gap(value):
    try:
        gap = float(value)
    except (TypeError, ValueError):
        return MAX_GAP
    return min(MAX_GAP, max(MIN_GAP, gap)) if gap == gap else MAX_GAP


class _Asker:
    """One request: the gap, the GET, the edge that answered. Raises ``ValueError`` when the policy refuses and ``OSError`` when nothing answers."""

    def __init__(self, policy, gap, probe):
        self.policy, self.gap, self.probe = policy, gap, probe

    def __call__(self, url, connect_ip=None):
        self.gap.wait()
        kwargs = {'connect_ip': connect_ip} if connect_ip else {}
        response = self.probe(url, self.policy, max_bytes=MAX_RESPONSE_BYTES, **kwargs)
        return {**response, 'challenge': challenge_of(response)}


def _answer(response):
    """``('challenged' | 'busy' | 'answered', row)`` of one response."""
    fp = fingerprint_of(response)
    if response.get('challenge'):
        return 'challenged', {'state': 'challenged', 'challenge': str(response['challenge'])[:60], 'fingerprint': fp}
    if busy(response):
        return 'busy', {'state': 'busy'}
    return 'answered', {'state': 'answered', 'fingerprint': fp}


def _own(name, scheme, port, ask, cache):
    """The fingerprint of the name's own site (one GET of the name at its own address), or None when it cannot be asked or does not answer."""
    if name in cache:
        return cache[name]
    cache[name] = None
    try:
        response = ask(f'{scheme}://{authority(name, port, scheme)}/')
    except ValueError:
        ask.policy.refuse(name)
        return None
    except (OSError, HTTPException):
        return None
    if not response.get('challenge') and not busy(response):
        cache[name] = fingerprint_of(response)
    return cache[name]


def sweep_address(item, ask, policy, cache):
    """The report of one address, or None when the policy refuses the address itself (nothing was asked: cvENGINE reads that as unknown)."""
    address, scheme, port = item['address'], item['scheme'], item['port']
    try:
        response = ask(f'{scheme}://{authority(address, port, scheme)}/')
    except ValueError:
        policy.refuse(address)
        return None
    except (OSError, HTTPException):
        return {'id': item['id'], 'default': {'state': 'no_answer'}, 'names': []}
    state, row = _answer(response)
    if state != 'answered':
        return {'id': item['id'], 'default': row, 'names': []}
    default = row['fingerprint']
    out = []
    for entry in item['names']:
        name = entry['name']
        try:
            response = ask(f'{scheme}://{authority(name, port, scheme)}/', connect_ip=address)
        except ValueError:
            policy.refuse(name)  # not answered, not reported: asked again later
            continue
        except (OSError, HTTPException):
            out.append({'name': name, 'state': 'no_answer'})
            continue
        state, row = _answer(response)
        row = {'name': name, **row}
        if state == 'answered':
            candidate = row['fingerprint']
            if candidate['status'] in ANSWERS and not similar(candidate, default):
                own = entry['own']
                if own is None:
                    own = _own(name, scheme, port, ask, cache)
                    row['own'] = own
                if classify(candidate, default, own) == 'distinct':
                    row['page'] = page_of(response)
        out.append(row)
        if state != 'answered':
            break  # the edge (or the server) answers for the whole address: nothing more is asked of it
    return {'id': item['id'], 'default': {'state': 'answered', 'fingerprint': default}, 'names': out}


def run_batch(target, probe=None, sleep=time.sleep, clock=time.monotonic):
    """Run a ``vhost_probe`` task: ``target['addresses']`` under ``target['scope']``, ``target['gap']`` seconds between requests. Returns
    ``{'addresses': [{'id', 'default', 'names'}], 'touched', 'refused'}``. ``probe(url, policy, max_bytes=, connect_ip=)`` replaces the network
    (tests)."""
    raw = target.get('addresses') if isinstance(target.get('addresses'), list) else []
    if not raw or len(raw) > MAX_ADDRESSES:
        raise ValueError(f'a task names between 1 and {MAX_ADDRESSES} addresses')
    items = [_item(a) for a in raw]
    if any(i is None for i in items):
        raise ValueError('an address is malformed')
    policy = ScopePolicy(target.get('scope'))
    ask = _Asker(policy, Gap(clamp_gap(target.get('gap')), sleep, clock), probe or http.probe_url)
    cache = {}
    out = []
    for item in items:
        report = sweep_address(item, ask, policy, cache)
        if report is not None:
            out.append(report)
    return {'addresses': out, 'touched': policy.touched, 'refused': policy.refused}
