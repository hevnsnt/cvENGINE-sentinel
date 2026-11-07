"""Read-only inspection of an SSH service (the ``ssh_probe`` kind): what runZeroInc's sshamble reports about a server's own handshake.

The Sentinel runs ``sshamble scan`` with exactly one check, ``badkeys-blocklist`` (host key inspection), and nothing that submits a credential or a
key is ever wired (``check_argv`` below refuses every other command line). This module is the pure half: the allow-listed command line and the
parser that turns the tool's JSON lines into the contract's observations. It reads nothing from the network.

Rules the parser keeps:

- It reports what the server says about itself: the banner and software version, the host key algorithms and key sizes, the authentication methods
  offered, the algorithm lists (key exchange, host key, ciphers, MACs, compression) and the protocol extensions. It does not judge them: weak
  algorithms, password authentication being on and an obsolete software version are classes the nuclei templates already report, and are not
  repeated here as findings.
- A compromised host key (the badkeys blocklist) is the one verdict: an observation and a check hit. The blocklist data is a rolling download
  that is not baked into the image; without it the check did nothing, which is reported as unverified, never as "not on the blocklist".
- Missing, unparseable or not-SSH data is unverified (``reached`` false or an observation with ``verified`` false), never clean. Every size is clipped.
"""
import base64
import json
import re

SSHAMBLE_VERSION = '0.5.1'  # the release the Dockerfile pins (a test holds them together)
CHECKS = 'badkeys-blocklist'  # the one check ever passed to --checks
CHECK_HIT_ID = 'badkeys-blocklist'

MAX_TARGETS = 25
MAX_OUTPUT_BYTES = 256 * 1024  # of the tool's output file for one target; more is not read
MAX_LINES = 20  # JSON lines read for one target (the tool writes one)
MAX_OBSERVATIONS = 20
MAX_CHECK_HITS = 20
MAX_LIST_ITEMS = 40  # of one algorithm or method list
MAX_ITEM_LEN = 80
MAX_HOSTKEYS = 10
EVIDENCE_LEN = 300
TITLE_LEN = 200
ERROR_LEN = 200
BANNER_LEN = 200

# the only command line there is: ``sshamble scan -p <port> --checks badkeys-blocklist --timeout 5 -m 4 -o <out> -l /dev/null <address>``
CONNECT_TIMEOUT = 5
MAX_CONNECTIONS = 4
LOG_SINK = '/dev/null'

# Flags that submit a credential, a key or a guess, take a target or settings from a file, or open a session. None is ever in an argv; the list
# is what the argv test proves, ``check_argv`` itself accepts only the one fixed shape.
FORBIDDEN_FLAGS = ('-u', '--users', '--password', '--password-file', '--private-key', '--private-key-passphrase', '--pubkey-hunt-file',
                   '--pubkey-hunt-conn-limit', '--mikrotik-pubkey', '-I', '--interact', '--interact-auto', '-i', '--input-targets', '--config',
                   '--categories', '--userenum-test-count', '--userenum-max-per-session-count', '--pubkey-bulk-limit', '--client-version')


class ArgvError(ValueError):
    """A command line that is not the one fixed shape."""


def build_argv(binary, address, port, out_path, checks=CHECKS):
    """The command line for one target. ``checks`` is a parameter only so that a caller cannot widen it: anything but ``CHECKS`` is refused."""
    if checks != CHECKS:
        raise ArgvError(f'only the {CHECKS} check is ever run')
    return check_argv([binary, 'scan', '-p', str(port), '--checks', CHECKS, '--timeout', str(CONNECT_TIMEOUT), '-m', str(MAX_CONNECTIONS),
                       '-o', out_path, '-l', LOG_SINK, address])


def check_argv(argv):
    """Refuse every command line that is not exactly ``scan -p <port> --checks badkeys-blocklist --timeout 5 -m 4 -o <file> -l /dev/null <address>``.
    The shape is fixed, so no flag that carries a credential, a key, a user list or a session can be added by a caller."""
    words = [str(a) for a in argv]
    if len(words) != 15 or words[1] != 'scan':
        raise ArgvError('only "sshamble scan" with its fixed arguments is ever run')
    expect = {2: '-p', 4: '--checks', 5: CHECKS, 6: '--timeout', 7: str(CONNECT_TIMEOUT), 8: '-m', 9: str(MAX_CONNECTIONS), 10: '-o',
              12: '-l', 13: LOG_SINK}
    for index, word in expect.items():
        if words[index] != word:
            raise ArgvError(f'refused: unexpected argument {words[index][:40]!r}')
    port, out, address = words[3], words[11], words[14]
    if not re.fullmatch(r'[0-9]{1,5}', port) or not 0 < int(port) < 65536:
        raise ArgvError('refused: not a port')
    for value in (out, address):
        if not value or value.startswith('-'):
            raise ArgvError('refused: a value that reads as a flag')
    return argv


# ----------------------------------------------------------------------------- reading values

_PRINTABLE = re.compile(r'[^\x20-\x7e]')


def clip(value, size):
    """``value`` as printable ASCII text of at most ``size`` characters."""
    text = _PRINTABLE.sub('?', value if isinstance(value, str) else '')
    return text if len(text) <= size else text[:size - 3] + '...'


def _names(value):
    """A list of short printable names from a JSON list, at most ``MAX_LIST_ITEMS``; ``None`` when it is not a list of strings."""
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        return None
    return [clip(v, MAX_ITEM_LEN) for v in value[:MAX_LIST_ITEMS]]


def _join(names, size=EVIDENCE_LEN):
    return clip(', '.join(names), size)


def _read_string(buf, pos):
    if pos + 4 > len(buf):
        raise ValueError('short key')
    n = int.from_bytes(buf[pos:pos + 4], 'big')
    if pos + 4 + n > len(buf):
        raise ValueError('short key')
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


_CURVE_BITS = {'nistp256': 256, 'nistp384': 384, 'nistp521': 521}


def key_bits(blob):
    """``(algorithm, bits)`` of an SSH public key blob (base64), ``bits`` ``None`` for a type whose size is not read here. ``ValueError`` when
    the blob is not a key."""
    try:
        raw = base64.b64decode(blob, validate=True)
    except (ValueError, TypeError):
        raise ValueError('not base64') from None
    name, pos = _read_string(raw, 0)
    alg = name.decode('ascii', errors='replace')
    if alg == 'ssh-rsa':
        _e, pos = _read_string(raw, pos)
        n, _ = _read_string(raw, pos)
        return alg, int.from_bytes(n, 'big').bit_length()
    if alg == 'ssh-dss':
        p, _ = _read_string(raw, pos)
        return alg, int.from_bytes(p, 'big').bit_length()
    if alg == 'ssh-ed25519':
        return alg, 256
    if alg.startswith('ecdsa-sha2-'):
        curve, _ = _read_string(raw, pos)
        return alg, _CURVE_BITS.get(curve.decode('ascii', errors='replace'))
    return alg, None


def _obs(ident, title, severity, evidence, verified):
    return {'id': ident, 'title': clip(title, TITLE_LEN), 'severity': severity, 'evidence': clip(evidence, EVIDENCE_LEN), 'verified': bool(verified)}


def host_entry(address, port, reached, observations, check_hits=(), error=None):
    entry = {'address': address, 'port': port, 'reached': bool(reached), 'observations': list(observations)[:MAX_OBSERVATIONS],
             'check_hits': list(check_hits)[:MAX_CHECK_HITS]}
    if error:
        entry['error'] = clip(error, ERROR_LEN)
    return entry


def unverified(address, port, why, ident='ssh_not_inspected'):
    """What a target the tool gave nothing usable for is reported as: nothing is known, so nothing is clean."""
    why = clip(why, ERROR_LEN)
    return host_entry(address, port, False, [_obs(ident, 'SSH service could not be inspected', 0, why, False)], error=why)


# ----------------------------------------------------------------------------- the parser

def _is_banner(version):
    return isinstance(version, str) and version.startswith('SSH-') and len(version) <= 255


def _banner_observation(version):
    parts = version.split(' ', 1)
    ident = parts[0]
    software = ident.split('-', 2)[2] if ident.count('-') >= 2 else ''
    comment = f' ({clip(parts[1], 60)})' if len(parts) > 1 else ''
    return _obs('ssh_banner', 'SSH banner and software version', 0, f'{clip(ident, BANNER_LEN)}{comment}; software: {clip(software, 80) or "unknown"}', True)


def _hostkey_observation(hostkeys):
    if not isinstance(hostkeys, dict) or not hostkeys:
        return _obs('ssh_hostkeys', 'SSH host keys were not read', 0, 'the server presented no host key the tool recorded', False)
    parts, complete = [], True
    for name, blob in sorted(hostkeys.items())[:MAX_HOSTKEYS]:
        try:
            alg, bits = key_bits(blob)
        except (ValueError, TypeError):
            parts.append(f'{clip(str(name), MAX_ITEM_LEN)} (unreadable)')
            complete = False
            continue
        parts.append(f'{clip(alg, MAX_ITEM_LEN)} {bits} bits' if bits else f'{clip(alg, MAX_ITEM_LEN)} (size not read)')
    return _obs('ssh_hostkeys', 'SSH host key algorithms and key sizes', 0, '; '.join(parts), complete)


def _methods_observation(methods):
    names = _names(methods)
    if names is None:
        return _obs('ssh_auth_methods', 'SSH authentication methods were not read', 0, 'the tool recorded no usable method list', False)
    if not names:
        return _obs('ssh_auth_methods', 'SSH authentication methods offered', 0, 'none listed by the server', False)
    return _obs('ssh_auth_methods', 'SSH authentication methods offered', 0, _join(names), True)


_ALGORITHM_LISTS = (('kexAlgos', 'key exchange'), ('hostKeyAlgos', 'host key'), ('cipherC2S', 'ciphers client-to-server'),
                    ('cipherS2C', 'ciphers server-to-client'), ('macC2S', 'MACs client-to-server'), ('macS2C', 'MACs server-to-client'),
                    ('compC2S', 'compression client-to-server'), ('compS2C', 'compression server-to-client'))


def _algorithm_observations(kex):
    """One observation per list the server offered; a missing or malformed list is one unverified observation, never an empty (clean) one."""
    if not isinstance(kex, dict):
        return [_obs('ssh_algorithms', 'SSH algorithm lists were not read', 0, 'the tool recorded no key exchange data', False)]
    out, missing = [], []
    for key, label in _ALGORITHM_LISTS:
        names = _names(kex.get(key))
        if not names:
            missing.append(label)
            continue
        out.append(_obs(f'ssh_algorithms_{key.lower()}', f'SSH {label} algorithms offered', 0, _join(names), True))
    if missing:
        out.append(_obs('ssh_algorithms_missing', 'Some SSH algorithm lists were not read', 0, 'missing: ' + ', '.join(missing), False))
    return out


def _extension_observation(extensions):
    if extensions is None:
        return None
    if not isinstance(extensions, dict):
        return _obs('ssh_extensions', 'SSH protocol extensions were not read', 0, 'the tool recorded an unusable extension list', False)
    if not extensions:
        return None  # the server sent none: nothing to report
    parts = []
    for name in sorted(extensions)[:MAX_LIST_ITEMS]:
        value = extensions[name]
        parts.append(clip(str(name), MAX_ITEM_LEN) + (f'={clip(value, 100)}' if isinstance(value, str) and value not in ('', '0') else ''))
    return _obs('ssh_extensions', 'SSH protocol extensions offered', 0, _join(parts), True)


def _check_hits(vulns):
    """The badkeys-blocklist hits of the line (``vulns``: id, ref, proof). Only that check's entries are read; the rest of the list is dropped."""
    hits = []
    if not isinstance(vulns, list):
        return hits
    for item in vulns:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'].startswith('badkeys-'):
            continue
        hits.append({'check': CHECK_HIT_ID, 'id': clip(item['id'], 200), 'ref': clip(item.get('ref') if isinstance(item.get('ref'), str) else '', 200),
                     'proof': clip(item.get('proof') if isinstance(item.get('proof'), str) else '', 300)})
        if len(hits) >= MAX_CHECK_HITS:
            break
    return hits


def parse_host(address, port, text, badkeys_checked):
    """The contract's host entry for one target from the tool's output (``text``: JSON lines). ``badkeys_checked`` is whether the blocklist data was
    present for the run: without it the check did nothing, so the entry says so (unverified) instead of implying the keys are clean."""
    if not isinstance(text, str) or not text.strip():
        return unverified(address, port, 'the tool wrote no result: the address was unreachable, nothing there speaks SSH, or the handshake did not finish')
    if len(text) > MAX_OUTPUT_BYTES:
        return unverified(address, port, 'the tool output was larger than is read')
    record = None
    for number, line in enumerate(text.splitlines()):
        if number >= MAX_LINES:
            break
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            return unverified(address, port, 'the tool output could not be parsed', 'ssh_unparseable')
        if isinstance(doc, dict) and doc.get('port') == port and str(doc.get('host', '')).strip('[]') == address:
            record = doc
            break
    if record is None:
        return unverified(address, port, 'the tool output had no entry for this address and port')
    version = record.get('version')
    if not _is_banner(version):
        return unverified(address, port, 'no SSH identification string was read: the service may not be SSH', 'ssh_not_identified')

    observations = [_banner_observation(version), _hostkey_observation(record.get('hostkeys')), _methods_observation(record.get('methods'))]
    observations.extend(_algorithm_observations(record.get('kex')))
    extension = _extension_observation(record.get('extensions'))
    if extension:
        observations.append(extension)

    hits = _check_hits(record.get('vulns')) if badkeys_checked else []
    if not badkeys_checked:
        observations.append(_obs('badkeys_not_checked', 'Host keys were not checked against the badkeys blocklist', 0,
                                 'the blocklist data is not present on this Sentinel; a compromised host key would not have been found', False))
    elif hits:
        for hit in hits:
            observations.append(_obs('badkeys_blocklist_hit', 'SSH host key is on the badkeys compromised-key blocklist', 4, f"{hit['id']} {hit['proof']}", True))
    elif isinstance(record.get('hostkeys'), dict) and record['hostkeys']:
        observations.append(_obs('badkeys_blocklist_clear', 'Host keys are not on the badkeys blocklist', 0, 'checked against the blocklist data on this Sentinel', True))
    return host_entry(address, port, True, observations, hits)
