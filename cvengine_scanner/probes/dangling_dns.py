"""Rating bbot's baddns dangling-DNS findings by what an outsider can actually claim, copied from cvENGINE's ``cveFeed.dangling_dns`` (the
``dangling_dns_check`` kind).

cvENGINE reads baddns's description and sends each finding it rates as ``{id, host, kind, triggers}`` with the provider lists it keeps in
``cveFeed/data/takeover_providers.json`` (the one copy), and decides what to store. This module asks the questions the rating needs and applies the
same rules:

- a dangling NS record is evaluated at the client's own zone cut, found by walking down from the registry (``find_cut``, each level asked
  non-recursively); a CNAME is not a delegation the client made (dropped); at the deepest cut every delegated name server is asked for the zone's
  SOA: all REFUSED or SERVFAIL is a lame delegation, a zone anyone can create at a self-service DNS provider (high), lame elsewhere stays medium,
  and a delegation one of whose servers answers for the zone is served (low);
- a dangling CNAME whose target does not resolve is a takeover only when the target is at a claimable provider or its registrable domain is not
  registered (RDAP); otherwise it is a stale record (low);
- a dangling CNAME whose provider "not found" page matched is checked against a control request to the same addresses with a random host name:
  the same answer means the page says nothing about this host (dropped).

DNS questions go straight to the name servers being evaluated, recursion off, only to addresses the task's scope policy and this Sentinel's floor
allow; the HTTP control goes through ``transport`` under the policy. A check that gets no answer is reported ``unknown``: cvENGINE then keeps
baddns's own rating, never a "gone" or "clean".
"""
import logging
import re
import secrets
from dataclasses import dataclass, field

from . import hygiene, names, rdap, transport

logger = logging.getLogger(__name__)

FIRE_SEVERITY, SMOKE_SEVERITY, ICE_SEVERITY = 3, 2, 1  # high, medium, low: cveFeed.threat.SEVERITY_HEAT
KIND_NS, KIND_NXDOMAIN, KIND_HTTP = 'ns', 'cname_nxdomain', 'cname_http'
KINDS = (KIND_NS, KIND_NXDOMAIN, KIND_HTTP)
DNS_TIMEOUT = 3.0
HTTP_TIMEOUT = 8
MAX_BODY = 64 * 1024
MAX_SERVERS = 4  # name servers asked per level before the level counts as unanswered
LAME_RCODES = ('REFUSED', 'SERVFAIL')
MAX_CHECKS = 50
MAX_PROVIDERS = 200
MAX_PROVIDER_ITEMS = 50
MAX_PATTERN = 200


def _clean(name):
    return (name or '').strip().lower().rstrip('.')


# ----------------------------------------------------------------------------- the provider list (sent by cvENGINE with the task)

class Providers:
    """The provider lists of ``takeover_providers.json`` as the task carries them: ``cname`` is ``[{service, suffixes}]`` (names a released
    name can be claimed at) and ``nameservers`` is ``[{service, patterns}]`` (self-service DNS providers, regular expressions)."""

    def __init__(self, doc):
        if not isinstance(doc, dict):
            raise ValueError('providers are malformed')
        cname, ns = doc.get('cname'), doc.get('nameservers')
        if not isinstance(cname, list) or not isinstance(ns, list) or len(cname) > MAX_PROVIDERS or len(ns) > MAX_PROVIDERS:
            raise ValueError('providers are malformed')
        try:
            self.cname = [(p['service'], tuple(s.lower() for s in p['suffixes'][:MAX_PROVIDER_ITEMS])) for p in cname]
            self.nameservers = [(p['service'], tuple(re.compile(x[:MAX_PATTERN], re.I) for x in p['patterns'][:MAX_PROVIDER_ITEMS])) for p in ns]
        except (KeyError, TypeError, AttributeError, re.error) as exc:
            raise ValueError('providers are malformed') from exc

    def claimable_provider(self, target):
        """The listed provider a CNAME target is at (a suffix on a label boundary), or None."""
        name = _clean(target)
        for service, suffixes in self.cname:
            if any(name == s or name.endswith('.' + s) for s in suffixes):
                return service
        return None

    def self_service_provider(self, nameservers):
        """The self-service DNS provider every one of ``nameservers`` belongs to, or None when any of them is not at a listed provider."""
        found = []
        for ns in nameservers:
            service = next((s for s, patterns in self.nameservers if any(p.match(_clean(ns)) for p in patterns)), None)
            if service is None:
                return None
            if service not in found:
                found.append(service)
        return ' and '.join(found) or None


# ----------------------------------------------------------------------------- the network (replaced in tests)

@dataclass
class Reply:
    """One DNS answer: the rcode as text, the AA flag, and the answer and authority records as ``(owner, type, value)``, all lower case
    without the trailing dot."""
    rcode: str
    aa: bool = False
    answer: list = field(default_factory=list)
    authority: list = field(default_factory=list)

    def values(self, owner, rtype, sections=('answer', 'authority')):
        owner = _clean(owner)
        return [v for s in sections for o, t, v in getattr(self, s) if o == owner and t == rtype]


class Net:
    """The lookups the rating makes, under the task's scope policy ``policy``. DNS questions go straight to the name servers being evaluated,
    recursion off; an address the policy or this Sentinel's floor does not allow is never asked. The HTTP control goes through ``transport``."""

    def __init__(self, policy):
        self.policy = policy
        self._addresses = {}

    def _resolver(self):
        return hygiene._resolver()

    def ns(self, name):
        """The NS host names of ``name`` from the recursive resolver ([] when there are none or DNS fails)."""
        return [_clean(v) for v in hygiene.fetch_records(name, 'NS', resolver=self._resolver())]

    def allowed(self, address):
        return not self.policy.address_refusal(address)

    def addresses(self, host):
        host = _clean(host)
        if host not in self._addresses:
            self._addresses[host] = [ip for ip in hygiene.fetch_records(host, 'A', resolver=self._resolver()) if self.allowed(ip)]
        return self._addresses[host]

    def ask(self, server, qname, rdtype):
        """One non-recursive question to one server address, or None when it gave no answer."""
        import dns.exception
        import dns.flags
        import dns.message
        import dns.query
        if not self.allowed(server):
            self.policy.refuse(server)
            return None
        query = dns.message.make_query(qname, rdtype)
        query.flags &= ~dns.flags.RD
        self.policy.touch(server)
        try:
            response = dns.query.udp(query, server, timeout=DNS_TIMEOUT)
            if response.flags & dns.flags.TC:
                response = dns.query.tcp(query, server, timeout=DNS_TIMEOUT)
        except (dns.exception.DNSException, OSError, ValueError):
            return None
        return reply_from(response)

    def registered(self, domain):
        """True when ``domain`` is registered, False when its registry says it is not, None when that cannot be told. A domain with name
        servers is registered; only an NXDOMAIN is asked of the registry (RDAP), and only its explicit "not found" counts."""
        import dns.exception
        import dns.resolver
        try:
            self._resolver().resolve(domain, 'NS')
            return True
        except dns.resolver.NoAnswer:
            return True
        except dns.resolver.NXDOMAIN:
            return rdap.registered(domain, self.policy)
        except (dns.exception.DNSException, OSError):
            return None

    def http_control(self, host):
        """``(real, control, control_name)``: the answer to ``GET /`` for ``host`` and for a random name sent to the same addresses, each
        ``(status, body)``; plain HTTP first, then HTTPS (certificate not checked: the provider's default certificate is the point). None when
        neither got an answer, or when the policy does not let ``host`` be asked."""
        control = f'cvengine-control-{secrets.token_hex(6)}.{_clean(host)}'
        for port, tls in ((80, False), (443, True)):
            try:
                addresses = transport.resolve(_clean(host), port, self.policy)
            except (ValueError, OSError):
                if self.policy.host_refusal(host):
                    self.policy.refuse(host)
                return None
            real = self._get(_clean(host), port, addresses, tls)
            if real is None:
                continue
            other = self._get(control, port, addresses, tls)
            return (real, other, control) if other is not None else None
        return None

    def _get(self, name, port, addresses, tls):
        import http.client
        import ssl
        context = None
        if tls:
            context = ssl.create_default_context()
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        connection = transport.HTTPConnection(name, port, addresses, HTTP_TIMEOUT, self.policy, context=context)
        try:
            connection.request('GET', '/', headers={'User-Agent': 'cvENGINE takeover check', 'Accept': '*/*', 'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            return response.status, transport.read_body(response, MAX_BODY)
        except (OSError, ValueError, http.client.HTTPException):
            return None
        finally:
            connection.close()


def reply_from(response):
    """A ``Reply`` from a dnspython message."""
    import dns.flags
    import dns.rcode
    import dns.rdatatype

    def records(section):
        return [(_clean(rrset.name.to_text()), dns.rdatatype.to_text(rrset.rdtype),
                 rd.to_text() if rrset.rdtype == dns.rdatatype.SOA else _clean(rd.to_text().split()[-1]))
                for rrset in section for rd in rrset]
    return Reply(dns.rcode.to_text(response.rcode()), bool(response.flags & dns.flags.AA), records(response.answer), records(response.authority))


def ask_any(net, servers, qname, rdtype):
    for server in list(servers)[:MAX_SERVERS]:
        reply = net.ask(server, qname, rdtype)
        if reply is not None:
            return reply
    return None


def _addresses(net, hosts):
    out = []
    for host in hosts:
        out += [a for a in net.addresses(host) if a not in out]
    return out


# ----------------------------------------------------------------------------- the zone cut

@dataclass
class Cut:
    kind: str  # 'zone' (a delegation), 'cname' (a name of the client's is a CNAME) or 'unknown'
    name: str = ''
    nameservers: list = field(default_factory=list)
    target: str = ''


def find_cut(name, net):
    """The deepest delegation on the way to ``name``, walking down from its registry: each level's servers are asked (recursion off) for
    the next name's NS, and a referral or an NS answer for that name is a cut. Stops at a CNAME (``kind='cname'``: whatever lies past it
    is the CNAME target's zone, not the client's), at a server that refuses (a lame delegation: the cut above is the one to evaluate) and at a
    name that does not exist."""
    name = _clean(name)
    apex = names.apex_domain(name)
    if not apex or '.' not in apex:
        return Cut('unknown')
    labels = name[:-len(apex)].rstrip('.').split('.') if name != apex else []
    chain = [apex]
    for label in reversed([x for x in labels if x]):
        chain.append(f'{label}.{chain[-1]}')
    servers = _addresses(net, net.ns(apex.split('.', 1)[1]))
    cut = None
    for qname in chain:
        reply = ask_any(net, servers, qname, 'NS')
        if reply is not None and reply.rcode in LAME_RCODES and cut is not None:
            break  # the servers of the cut above refuse: that delegation is the one to evaluate
        if reply is None or reply.rcode not in ('NOERROR', 'NXDOMAIN'):
            return Cut('unknown')  # no answer: a shallower cut is not evaluated in place of one that may lie deeper
        target = reply.values(qname, 'CNAME', ('answer',))
        if target:
            return Cut('cname', qname, target=target[0])
        nameservers = reply.values(qname, 'NS')
        if nameservers:
            cut = Cut('zone', qname, sorted(set(nameservers)))
            servers = _addresses(net, cut.nameservers)
            if not servers:
                break
            continue
        if reply.rcode == 'NXDOMAIN':
            return Cut('unknown')  # the name does not exist where baddns saw a delegation: nothing to rate
    return cut or Cut('unknown')


def soa_state(zone, nameservers, net):
    """'lame' when every delegated name server answered a non-recursive SOA question for ``zone`` with REFUSED or SERVFAIL, 'served' when
    one answered for it, None otherwise (a server gave no answer, or answered something else)."""
    replies = []
    for ns in nameservers:
        reply = ask_any(net, net.addresses(ns), zone, 'SOA')
        if reply is None:
            return None
        replies.append(reply)
    if not replies:
        return None
    if any(r.rcode == 'NOERROR' and (r.aa or r.values(zone, 'SOA', ('answer',))) for r in replies):
        return 'served'
    if all(r.rcode in LAME_RCODES for r in replies):
        return 'lame'
    return None


@dataclass
class Rating:
    severity: int = None  # None: keep baddns's
    drop: bool = False
    note: str = ''
    zone: str = ''


@dataclass
class Check:
    id: str
    host: str
    kind: str
    triggers: list = field(default_factory=list)


def assess(check, net, providers):
    """The rating of one check, or None when the network gave no usable answer. Never raises."""
    try:
        return {KIND_NS: _assess_ns, KIND_NXDOMAIN: _assess_nxdomain, KIND_HTTP: _assess_http}[check.kind](check.host, check, net, providers)
    except Exception:  # noqa: BLE001 - a check that fails leaves baddns's rating, it never loses the finding
        logger.exception('dangling DNS check of %s failed', check.host)
        return None


def _assess_ns(host, parsed, net, providers):
    cut = find_cut(host, net)
    if cut.kind == 'cname':
        return Rating(drop=True, zone=cut.name, note=(
            f'{cut.name} is a CNAME to {cut.target}. The name servers baddns reached serve the zone of the CNAME target (the provider), not '
            f'a delegation of this domain, so how they answer is the provider\'s DNS behaviour, not a dangling delegation.'))
    if cut.kind != 'zone':
        return None
    state = soa_state(cut.name, cut.nameservers, net)
    servers = ', '.join(cut.nameservers)
    if state == 'served':
        return Rating(severity=ICE_SEVERITY, zone=cut.name, note=(
            f'The delegation of {cut.name} ({servers}) is served: a delegated name server answers for the zone with its SOA. '
            f'baddns\'s reading is not reproduced.'))
    if state != 'lame':
        return None
    provider = providers.self_service_provider(cut.nameservers)
    if provider:
        return Rating(severity=FIRE_SEVERITY, zone=cut.name, note=(
            f'{cut.name} is delegated to {provider} ({servers}) and every delegated name server answers a non-recursive SOA query for it '
            f'with REFUSED or SERVFAIL: no account there hosts the zone. {provider} lets any customer create a zone of any name, so anyone '
            f'can create {cut.name} there and answer for it (a zone takeover).'))
    return Rating(severity=SMOKE_SEVERITY, zone=cut.name, note=(
        f'{cut.name} is delegated to {servers} and every delegated name server refuses it, but that provider is not one where anyone can '
        f'create a zone of any name: the delegation is broken, a takeover is not shown.'))


def _assess_nxdomain(host, parsed, net, providers):
    target = parsed.triggers[-1] if parsed.triggers else ''
    if not target or target == 'self':
        return None
    provider = providers.claimable_provider(target)
    if provider:
        return Rating(note=f'{target} is at {provider}, where a released name can be claimed by another customer.')
    domain = names.apex_domain(target)
    if not domain:
        return None
    registered = net.registered(domain)
    if registered is False:
        return Rating(note=f'{domain}, the registrable domain of {target}, is not registered: anyone can register it and answer for this name.')
    if registered is None:
        return None
    return Rating(severity=ICE_SEVERITY, note=(
        f'{target} does not resolve, but it is not at a provider where another customer can claim a name, and {domain} is registered, so '
        f'no outsider can create it: a stale record to remove, not a takeover.'))


def _normalised(answer, name):
    status, body = answer
    text = body.decode('utf-8', 'replace') if isinstance(body, (bytes, bytearray)) else str(body or '')
    return status, ' '.join(text.replace(name, '{host}').split())


def same_answer(real, control, host, control_name):
    """Whether the control request got the same status and body as the real one (each with its own host name blanked out)."""
    return _normalised(real, host) == _normalised(control, control_name)


def _assess_http(host, parsed, net, providers):
    target = parsed.triggers[-1] if parsed.triggers else ''
    if target and target != 'self' and providers.claimable_provider(target):
        return None
    pair = net.http_control(host)
    if pair is None:
        return None
    real, control, control_name = pair
    if same_answer(real, control, host, control_name):
        return Rating(drop=True, note=(
            f'A control request to the same addresses with a random host name ({control_name}) got the same answer (HTTP {real[0]}, same '
            f'body): the provider answers every host name this way, claimed or not, so the matched text says nothing about {host}.'))
    return None


# ----------------------------------------------------------------------------- the task

def _check(raw):
    if not isinstance(raw, dict):
        return None
    ident, host, kind, triggers = raw.get('id'), raw.get('host'), raw.get('kind'), raw.get('triggers', [])
    if not isinstance(ident, str) or not ident or not isinstance(host, str) or not _clean(host) or len(host) > 260 or kind not in KINDS:
        return None
    if not isinstance(triggers, list) or len(triggers) > 10 or any(not isinstance(t, str) or len(t) > 260 for t in triggers):
        return None
    return Check(ident[:200], _clean(host), kind, [_clean(t) for t in triggers if _clean(t)])


def rating_doc(check_id, rating):
    """One result row: ``state`` is ``unknown`` when the network gave no usable answer (cvENGINE then keeps baddns's rating)."""
    if rating is None:
        return {'id': check_id, 'state': 'unknown'}
    return {'id': check_id, 'state': 'rated', 'severity': rating.severity, 'drop': bool(rating.drop), 'note': (rating.note or '')[:2000],
            'zone': (rating.zone or '')[:260]}


def run_batch(target, net=None):
    """Run a ``dangling_dns_check`` task: ``target['checks']`` under ``target['scope']`` with ``target['providers']``. Returns ``{'ratings':
    [{'id', 'state', ...}], 'touched', 'refused'}``. ``net`` replaces the network (tests)."""
    from .policy import ScopePolicy
    raw = target.get('checks') if isinstance(target.get('checks'), list) else []
    if len(raw) > MAX_CHECKS:
        raise ValueError(f'a task names at most {MAX_CHECKS} checks')
    checks = [_check(item) for item in raw]
    if any(c is None for c in checks):
        raise ValueError('a check is malformed')
    providers = Providers(target.get('providers'))
    policy = ScopePolicy(target.get('scope'))
    net = net or Net(policy)
    out = []
    for check in checks:
        if policy.host_refusal(check.host):
            policy.refuse(check.host)
            out.append(rating_doc(check.id, None))
            continue
        out.append(rating_doc(check.id, assess(check, net, providers)))
    return {'ratings': out, 'touched': policy.touched, 'refused': policy.refused}
