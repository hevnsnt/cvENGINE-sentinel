"""The scope policy a probe task carries, and its enforcement on every hop.

cvENGINE decides what a probe may touch when it builds the task (its exclusions, archived hosts, the targets' name scope, a bug bounty program's
scope, the hosts a page may read scripts from, and which private addresses the project authorised) and sends the answer as ``target['scope']``:

``hosts``           exact names (or address literals) that may be asked;
``domains``         a name equal to or under one of these may be asked;
``excluded``        exact names that are never asked, whatever else says;
``excluded_trees``  a name equal to or under one of these is never asked;
``private``         the server allows private addresses at all (a lab install with CVENGINE_ALLOW_PRIVATE_TARGETS);
``addresses``       private addresses the project authorised (its own tailnet devices), only ever when asked for as the literal address;
``blocked``         further ranges the server never scans.

``ScopePolicy`` holds it and is asked at every hop: the first request, every redirect, every script a page loads, every follow-up request.
A name must pass ``host_refusal`` and every address it resolves to must pass ``address_refusal``, which applies this Sentinel's own floor
(``cvengine_scanner.scope``: loopback, metadata, link-local, its own addresses, and private space unless this machine is internal) before the
policy. The policy can only narrow the floor, never widen it. Every host a request was actually sent to is kept in ``touched``, and every host a hop was refused for in ``refused``; the
result reports both, so the server can see that nothing outside the policy was asked.
"""
import ipaddress
import threading

from cvengine_scanner import scope as floor

from . import names

MAX_HOSTS = 5000
MAX_DOMAINS = 200
MAX_EXCLUDED = 5000
MAX_TREES = 1000
MAX_ADDRESSES = 1000
MAX_BLOCKED = 100
MAX_TOUCHED = 2000  # hosts reported back in one result


class ScopeRefused(ValueError):
    """A host or address the task's scope policy (or this Sentinel's floor) does not allow. The message names the reason, never more than the host."""


def _names(values, limit):
    out = set()
    for value in (values or [])[:limit]:
        if isinstance(value, str):
            name = names.clean(value).strip('[]')
            if name:
                out.add(name)
    return frozenset(out)


def _networks(values, limit):
    out = []
    for value in (values or [])[:limit]:
        try:
            out.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            continue
    return tuple(out)


def _canonical_ip(value):
    try:
        return ipaddress.ip_address(str(value).strip().strip('[]'))
    except ValueError:
        return None


def _from_scope_policy(doc):
    """The contract's ``scope_policy`` (a discovery task: in-scope domains, an exact host, exclusions, deny ranges) read as a ``probe_scope``, so
    the same enforcement serves both."""
    domains = [d for d in doc.get('in_scope_domains') or [] if isinstance(d, str)]
    exclusions = [e for e in doc.get('exclusions') or [] if isinstance(e, dict) and isinstance(e.get('host'), str)]
    exact = doc.get('exact_host') is True
    return {'hosts': domains if exact else [], 'domains': [] if exact else domains,
            'excluded': [e['host'] for e in exclusions if not e.get('subtree')], 'excluded_trees': [e['host'] for e in exclusions if e.get('subtree')],
            'blocked': [r for r in doc.get('deny_ranges') or [] if isinstance(r, str)]}


class ScopePolicy:
    """One task's scope policy. ``doc`` is ``target['scope']``; a missing or malformed policy allows nothing (every host is refused).
    ``internal`` overrides this machine's own network setting (tests); by default the floor reads it."""

    def __init__(self, doc=None, internal=None):
        doc = _from_scope_policy(doc) if isinstance(doc, dict) and 'in_scope_domains' in doc else doc
        doc = doc if isinstance(doc, dict) else {}
        self.hosts = _names(doc.get('hosts'), MAX_HOSTS)
        self.domains = _names(doc.get('domains'), MAX_DOMAINS)
        self.excluded = _names(doc.get('excluded'), MAX_EXCLUDED)
        self.excluded_trees = _names(doc.get('excluded_trees'), MAX_TREES)
        self.private = doc.get('private') is True
        self.addresses = frozenset(ip for ip in (_canonical_ip(a) for a in (doc.get('addresses') or [])[:MAX_ADDRESSES]) if ip is not None)
        self.blocked = _networks(doc.get('blocked'), MAX_BLOCKED)
        self.internal = internal
        self._touched, self._refused = [], []
        self._seen, self._seen_refused = set(), set()
        self._lock = threading.Lock()

    # -- names

    def _excluded(self, name):
        if name in self.excluded:
            return True
        probe = name
        while True:
            if probe in self.excluded_trees:
                return True
            if '.' not in probe:
                return False
            probe = probe.split('.', 1)[1]

    def host_refusal(self, host):
        """'' when ``host`` (a name or an address literal) may be asked, else why not."""
        name = names.clean(host).strip('[]') if isinstance(host, str) else ''
        if not name:
            return 'no host'
        if self._excluded(name):
            return 'excluded'
        if name in self.hosts:
            return ''
        if not names.is_ip(name) and any(name == d or name.endswith('.' + d) for d in self.domains):
            return ''
        return 'outside the scope policy'

    def check_host(self, host):
        why = self.host_refusal(host)
        if why:
            raise ScopeRefused(f'{str(host)[:100]!r} is not allowed ({why})')
        return names.clean(host).strip('[]')

    # -- addresses

    def address_refusal(self, value, literal=False):
        """'' when a connection may be made to the address ``value``, else why not. ``literal``: the address was asked for as itself (a task that
        names the address), not as what a name resolved to; only then may a private address the project authorised be reached."""
        ip = _canonical_ip(value)
        if ip is None or getattr(ip, 'scope_id', None):
            return 'not a plain address'
        internal = floor.internal_allowed() if self.internal is None else self.internal
        try:
            judged = floor._judge(ip, internal)
        except floor.ScopeError as exc:
            return str(exc)
        if any(judged.version == net.version and judged in net for net in self.blocked):
            return 'a range the server never scans'
        if any(judged.version == net.version and judged in net for net in floor.PRIVATE):
            if not (self.private or (literal and judged is ip and ip in self.addresses)):
                return 'a private address the server did not authorise'
        return ''

    def check_address(self, value, literal=False):
        why = self.address_refusal(value, literal)
        if why:
            raise ScopeRefused(f'{str(value)[:60]!r} is not allowed ({why})')
        return str(_canonical_ip(value))

    # -- what was touched

    def touch(self, host):
        """Record that a request was sent to ``host`` (a name or an address)."""
        name = names.clean(host).strip('[]') if isinstance(host, str) else ''
        if not name:
            return
        with self._lock:
            if name not in self._seen and len(self._touched) < MAX_TOUCHED:
                self._seen.add(name)
                self._touched.append(name)

    def refuse(self, host):
        """Record that a hop to ``host`` was not made because the policy refused it (a redirect or a script elsewhere)."""
        name = names.clean(host).strip('[]') if isinstance(host, str) else ''
        if not name:
            return
        with self._lock:
            if name not in self._seen_refused and len(self._refused) < MAX_TOUCHED:
                self._seen_refused.add(name)
                self._refused.append(name)

    @property
    def refused(self):
        with self._lock:
            return list(self._refused)

    @property
    def touched(self):
        with self._lock:
            return list(self._touched)

    def to_doc(self):
        """The policy as the task carried it (normalised), for a test or a log."""
        return {'hosts': sorted(self.hosts), 'domains': sorted(self.domains), 'excluded': sorted(self.excluded),
                'excluded_trees': sorted(self.excluded_trees), 'private': self.private, 'addresses': sorted(str(a) for a in self.addresses),
                'blocked': [str(n) for n in self.blocked]}
