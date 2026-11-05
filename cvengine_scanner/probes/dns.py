"""Name resolution for cvENGINE's discovery, copied from ``cveFeed.discovery.resolve_names`` (the ``dns_resolve`` kind).

The scanner's view of DNS is the one that matters: the addresses it resolves are the ones its probes and scans will reach. A lookup asks this
Sentinel's resolver only, never the host, so a name the task's scope policy accepts is resolved and every address it answers is reported as it
is: cvENGINE judges the addresses with the same gates it applies after a lookup of its own (exclusions, blocked and internal ranges). A name
the policy refuses is not looked up at all.
"""
import concurrent.futures
import logging
import socket

from .policy import ScopePolicy

logger = logging.getLogger(__name__)

MAX_NAMES = 500
MAX_ADDRESSES_PER_NAME = 32
LOOKUP_TIMEOUT = 10  # seconds one name's lookup may take (cveFeed.discovery.IP_LOOKUP_TIMEOUT)
WORKERS = 20

_NO_SUCH_NAME = {getattr(socket, n) for n in ('EAI_NONAME', 'EAI_NODATA') if hasattr(socket, n)}


def _no_such_name(exc):
    """Whether a lookup error means the name has no address (an answer), not that the resolver could not answer."""
    return isinstance(exc, socket.gaierror) and exc.errno in _NO_SUCH_NAME


def resolve_names(names, policy, timeout=LOOKUP_TIMEOUT, workers=WORKERS, resolver=socket.getaddrinfo):
    """``(pairs, errors, refused)``: ``{name: [addresses]}`` for the names that resolve, ``{name: reason}`` for a lookup that could not be
    answered (a timeout, a temporary resolver failure: never mistaken for a name without an address), and the names ``policy`` refused. A name the
    resolver answers "no such name" for is simply absent."""
    pairs, failed, refused = {}, {}, []
    wanted = []
    for name in names:
        if policy.host_refusal(name):
            refused.append(name)
        else:
            wanted.append(name)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = {pool.submit(resolver, name, None, 0, socket.SOCK_STREAM): name for name in wanted}
        for future, name in futures.items():
            try:
                found = []
                for info in future.result(timeout=timeout):
                    address = str(info[4][0]).split('%')[0]
                    if address not in found:
                        found.append(address)
                if found:
                    pairs[name] = found[:MAX_ADDRESSES_PER_NAME]
            except concurrent.futures.TimeoutError:
                failed[name] = f'no answer within {timeout} seconds'
            except Exception as exc:  # noqa: BLE001 - one lookup failing never stops the rest
                if not _no_such_name(exc):
                    failed[name] = f'{type(exc).__name__}: {exc}'[:120]
    finally:
        pool.shutdown(wait=False)
    if failed:
        logger.warning('DNS lookup could not be answered for %s of %s names', len(failed), len(wanted))
    return pairs, failed, refused


def run_batch(target, resolver=socket.getaddrinfo, timeout=LOOKUP_TIMEOUT):
    """Run a ``dns_resolve`` task: ``target['names']`` under ``target['scope']``. Returns ``{'resolved': {name: [ip]}, 'errors': {name: reason},
    'refused': [names]}``."""
    names = target.get('names') if isinstance(target.get('names'), list) else []
    if len(names) > MAX_NAMES:
        raise ValueError(f'a task names at most {MAX_NAMES} names')
    clean = []
    for name in names:
        if not isinstance(name, str) or not name.strip() or len(name) > 253:
            raise ValueError('a name is malformed')
        clean.append(name.strip().lower().rstrip('.'))
    policy = ScopePolicy(target.get('scope'))
    pairs, failed, refused = resolve_names(list(dict.fromkeys(clean)), policy, timeout=timeout, resolver=resolver)
    return {'resolved': pairs, 'errors': failed, 'refused': refused}
