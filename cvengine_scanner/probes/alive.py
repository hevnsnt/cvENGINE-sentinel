"""Whether a retired name's last known addresses still answer, copied from cvENGINE's ``cveFeed.zombie`` (the ``alive_check`` kind).

A host that disappears from DNS is normally retired; if the address it was last seen on still serves its pages, the asset is not gone, only
unnamed (a zombie). cvENGINE picks the addresses and ports (``zombie.endpoints``, ``tcp_endpoints``) and decides what an answer means; this
module asks:

- an ``http`` or ``https`` check is a plain GET of ``/`` to the address with the old name in the Host header (and as the TLS server name), no
  credential, no cookie, no redirect followed, 4 KB read: any HTTP answer counts;
- a ``tcp`` check is a connect, closed at once: nothing sent, no banner read.

Every address is asked as itself and must pass the task's scope policy and this Sentinel's floor; the policy records what was touched.
"""
import ipaddress
import logging
import socket

from . import http, transport
from .policy import ScopePolicy

logger = logging.getLogger(__name__)

MAX_CHECKS = 600
CHECK_TIMEOUT = (3, 4)  # cveFeed.zombie.CHECK_TIMEOUT
SCHEMES = ('http', 'https', 'tcp')


def _check(raw):
    if not isinstance(raw, dict):
        return None
    ident, host, ip, port, scheme = raw.get('id'), raw.get('host'), raw.get('ip'), raw.get('port'), raw.get('scheme')
    if not all(isinstance(v, str) and v for v in (ident, host, ip)) or scheme not in SCHEMES:
        return None
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        return None
    try:
        ip = str(ipaddress.ip_address(ip.strip('[]')))
    except ValueError:
        return None
    if len(host) > 260 or any(c.isspace() or ord(c) < 32 for c in host):
        return None
    return {'id': ident[:200], 'host': host.lower().rstrip('.'), 'ip': ip, 'port': port, 'scheme': scheme}


def http_alive(check, policy, probe=None):
    """Whether ``ip:port`` answers a GET of ``/`` as ``host`` (any status). Raises ``ValueError`` when the policy refuses the address."""
    probe = probe or http.probe_url
    policy.check_host(check['ip'])
    policy.check_address(check['ip'], literal=True)  # asked before anything is sent (the transport asks again when it connects)
    name = f"[{check['ip']}]" if ':' in check['ip'] else check['ip']
    try:
        probe(f"{check['scheme']}://{name}:{check['port']}/", policy, timeout=CHECK_TIMEOUT, max_bytes=4096, headers={'Host': check['host']})
        return True
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - a refused connection, a timeout or a TLS failure: nothing answers there
        return False


def tcp_alive(check, policy, connect=None):
    """Whether a connection to ``ip:port`` is accepted: connect, close. Raises ``ValueError`` when the policy refuses the address."""
    policy.check_host(check['ip'])
    policy.check_address(check['ip'], literal=True)
    family = socket.AF_INET6 if ':' in check['ip'] else socket.AF_INET
    address = (check['ip'], check['port'], 0, 0) if family == socket.AF_INET6 else (check['ip'], check['port'])
    try:
        sock = (connect or transport.open_socket)(((family, address),), CHECK_TIMEOUT[0], policy, host=check['ip'], literal=True)
    except ValueError:
        raise
    except OSError:
        return False
    sock.close()
    return True


def run_batch(target, probe=None, connect=None):
    """Run an ``alive_check`` task: ``target['checks']`` under ``target['scope']``. Returns ``{'checks': [{'id', 'alive', 'error'?}], 'touched',
    'refused'}``. A check the policy refuses is reported with an error and ``alive: false``; cvENGINE reads it as unknown, never as gone."""
    raw = target.get('checks') if isinstance(target.get('checks'), list) else []
    if len(raw) > MAX_CHECKS:
        raise ValueError(f'a task names at most {MAX_CHECKS} checks')
    checks = [_check(item) for item in raw]
    if any(c is None for c in checks):
        raise ValueError('a check is malformed')
    policy = ScopePolicy(target.get('scope'))
    out = []
    for check in checks:
        try:
            alive = (tcp_alive(check, policy, connect) if check['scheme'] == 'tcp' else http_alive(check, policy, probe))
            out.append({'id': check['id'], 'alive': alive})
        except ValueError as exc:
            policy.refuse(check['ip'])
            out.append({'id': check['id'], 'alive': False, 'error': f'not run: {exc}'[:200]})
    return {'checks': out, 'touched': policy.touched, 'refused': policy.refused}
