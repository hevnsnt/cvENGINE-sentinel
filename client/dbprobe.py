"""One credential-less connection attempt to a database (the ``db_probe`` kind), the same checks ``cveFeed.db_exposure`` runs on the server.

Exactly one read-only attempt with no credential, never a second username or password, and nothing is read once connected beyond what proves the
door was open: a PONG, a version, or a count of database names (never their names, never a document). The server makes the finding; this module
only answers ``open`` (True: the attempt was let through; False: it was not, or nothing answered; None: no client for this database here) and a
short evidence line. The host answers are untrusted text: they are clipped here and again by the server.
"""
import json
import socket
import struct
import time

import requests

CONNECT_TIMEOUT = 3
MAX_BODY_BYTES = 65536  # a status page or a list of database names; a server that sends more is not answering this question
TOTAL_SECONDS = 10  # the whole request, so a server that drips one byte at a time cannot hold the task
EVIDENCE_LEN = 300


def _clip(text):
    return ''.join(ch for ch in str(text) if ch.isprintable())[:EVIDENCE_LEN]


def _netloc(host, port):
    return f'[{host}]:{port}' if ':' in str(host) else f'{host}:{port}'


def check_redis(host, port):
    """A single PING with no password: open when the server answers instead of demanding auth."""
    try:
        import redis
    except ImportError:
        return None, ''
    client = None
    try:
        client = redis.Redis(host=host, port=port, socket_connect_timeout=CONNECT_TIMEOUT, socket_timeout=CONNECT_TIMEOUT)
        if not client.ping():
            return False, ''
        reply = 'PONG'
        try:
            reply += f' (redis {client.info("server").get("redis_version", "?")})'
        except Exception:  # noqa: BLE001 - the version is a nicety; the PONG is the evidence
            pass
        return True, reply
    except Exception:  # noqa: BLE001 - NOAUTH, a protected-mode DENIED, refused, timeout: not exposed
        return False, ''
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


def check_memcached(host, port):
    """Memcached has no authentication at all: an instance that answers a read-only ``version`` is reachable with none."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.sendall(b'version\r\n')
            reply = sock.recv(256)
    except OSError:
        return False, ''
    if reply.startswith(b'VERSION'):
        return True, reply.decode('ascii', 'replace').strip().splitlines()[0]
    return False, ''


def _recv_exact(sock, size, deadline):
    data = b''
    while len(data) < size:
        if time.monotonic() > deadline:
            raise TimeoutError('the server is too slow')
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError('the server closed the connection')
        data += chunk
    return data


def check_postgres(host, port):
    """One startup message for the ``postgres`` role and database, with no password: open only when the server answers AuthenticationOk at once
    (its access policy trusts this connection outright). Any password, MD5 or SCRAM request, or an error, is "not open"; no password is ever sent.
    The protocol is spoken directly (startup and the first answer only), so the image needs no PostgreSQL client library."""
    params = b'user\0postgres\0database\0postgres\0application_name\0cvengine-sentinel\0\0'
    startup = struct.pack('!ii', 8 + len(params), 196608) + params
    deadline = time.monotonic() + TOTAL_SECONDS
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.sendall(startup)
            kind = _recv_exact(sock, 1, deadline)
            length = struct.unpack('!i', _recv_exact(sock, 4, deadline))[0]
            if kind != b'R' or not 8 <= length <= 1024:
                return False, ''
            code = struct.unpack('!i', _recv_exact(sock, 4, deadline))[0]
            if code != 0:
                return False, ''
            version = ''
            for _ in range(64):  # ParameterStatus messages follow; server_version is among them
                kind = _recv_exact(sock, 1, deadline)
                length = struct.unpack('!i', _recv_exact(sock, 4, deadline))[0]
                if not 4 <= length <= 4096:
                    break
                body = _recv_exact(sock, length - 4, deadline)
                if kind == b'S':
                    name, _, value = body.partition(b'\0')
                    if name == b'server_version':
                        version = value.rstrip(b'\0').decode('ascii', 'replace')
                        break
                elif kind in (b'Z', b'E'):
                    break
            sock.sendall(b'X\0\0\0\4')  # Terminate
    except (OSError, ValueError, struct.error):
        return False, ''
    return True, f'PostgreSQL {version}' if version else 'connected as postgres, no password'


def _bounded_json(url):
    """GET ``url`` (no redirects) and parse its JSON body, reading at most MAX_BODY_BYTES within TOTAL_SECONDS; None unless the answer is a 200 with
    JSON inside those bounds. The scanned server controls how much it sends and how slowly, so neither is trusted."""
    deadline = time.monotonic() + TOTAL_SECONDS
    with requests.Session() as session:
        session.trust_env = False
        with session.get(url, timeout=CONNECT_TIMEOUT, allow_redirects=False, stream=True) as resp:
            if resp.status_code != 200:
                return None
            body, size = [], 0
            for chunk in resp.iter_content(1):  # one byte per read, so a dripping server cannot hold a larger read past the deadline
                body.append(chunk)
                size += len(chunk)
                if size > MAX_BODY_BYTES or time.monotonic() > deadline:
                    return None
            return json.loads(b''.join(body)) if body else None


def check_elasticsearch(host, port):
    """A plain GET /: Elasticsearch with no security configured answers with cluster info and no challenge."""
    try:
        info = _bounded_json(f'http://{_netloc(host, port)}/')
    except Exception:  # noqa: BLE001
        return False, ''
    if not isinstance(info, dict) or 'cluster_name' not in info:
        return False, ''
    version = info.get('version') if isinstance(info.get('version'), dict) else {}
    return True, f'cluster {info.get("cluster_name")}, version {version.get("number", "?")}'


def check_couchdb(host, port):
    """GET /_all_dbs: database names only, never a document. CouchDB with no admin ever configured answers it with no credential."""
    try:
        names = _bounded_json(f'http://{_netloc(host, port)}/_all_dbs')
    except Exception:  # noqa: BLE001
        return False, ''
    if not isinstance(names, list):
        return False, ''
    return True, f'/_all_dbs answered with {len(names)} database name(s)'  # a count, never the names


def check_mysql(host, port):
    """One connection as root with no password: open when the server lets it straight through."""
    try:
        import pymysql
    except ImportError:
        return None, ''
    conn = None
    try:
        conn = pymysql.connect(host=host, port=port, user='root', password='', connect_timeout=CONNECT_TIMEOUT,
                               read_timeout=CONNECT_TIMEOUT, write_timeout=CONNECT_TIMEOUT)
        version = conn.get_server_info()
        return True, f'connected as root with no password (MySQL {version})' if version else 'connected as root with no password'
    except Exception:  # noqa: BLE001 - access denied, refused, reset: not exposed
        return False, ''
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def check_mongodb(host, port):
    """One listDatabases (names only) with no prior authentication: open when the server lets it through."""
    try:
        import pymongo
    except ImportError:
        return None, ''
    client = None
    ms = int(CONNECT_TIMEOUT * 1000)
    try:
        client = pymongo.MongoClient(host=host, port=port, serverSelectionTimeoutMS=ms, connectTimeoutMS=ms, socketTimeoutMS=ms, directConnection=True)
        result = client.admin.command('listDatabases', 1, nameOnly=True)
        return True, f'listDatabases answered with {len(result.get("databases") or [])} database name(s)'  # a count, never the names
    except Exception:  # noqa: BLE001 - Unauthorized, refused, timeout: not exposed
        return False, ''
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


CHECKS = {'redis': check_redis, 'memcached': check_memcached, 'postgres': check_postgres, 'elastic': check_elasticsearch,
          'couchdb': check_couchdb, 'mysql': check_mysql, 'mongodb': check_mongodb}


def probe(host, port, db):
    """``{'open': True|False|None, 'evidence': str}`` for one database service. Never raises for a network problem."""
    checker = CHECKS[db]
    try:
        opened, evidence = checker(host, port)
    except Exception:  # noqa: BLE001 - a checker crashing is "not shown open", never a crashed task
        opened, evidence = False, ''
    return {'open': opened, 'evidence': _clip(evidence) if opened else ''}
