"""The result contract between cvENGINE and a Sentinel (``sentinel_contract.json``), read from the file packaged here.

This file is the single source of truth: the cvENGINE server keeps no copy and reads it from its install of this library (pinned by commit sha
in its ``web/requirements.txt``). A contract change lands here first, then the server bumps its sha. The helpers below are the reading half
the server's ``agentapi/sentinel_contract.py`` delegates to."""
import json
from pathlib import Path

PATH = Path(__file__).with_name('sentinel_contract.json')
FIXTURES = Path(__file__).resolve().parent.parent / 'fixtures'


def load():
    return json.loads(PATH.read_text(encoding='utf-8'))


def version():
    """The contract version this copy describes, which is the one a Sentinel built from it declares."""
    return load()['contract_version']


def min_supported():
    return load()['min_supported_contract_version']


def kind_since(kind):
    """The contract version that introduced ``kind``: a Sentinel declaring an older one cannot run it. ``KeyError`` for an unknown kind."""
    return load()['kind_since'][kind]


def external_since(kind):
    """The contract version from which a Sentinel that is not the install's built-in scanner may be offered a ``kind`` the built-in scanner used to
    keep to itself (``external_since``, contract 4: ``nuclei_validate`` needs the template hash and the server's approval, version 4; ``path_probe``
    is unchanged, version 3), or ``None`` for every other kind and for a contract without the table: never offered outside, as before."""
    return (load().get('external_since') or {}).get(kind)


def result_schema(kind):
    """A self-contained schema for the result of a ``kind`` task (``$defs`` included, so a validator needs nothing else). ``KeyError`` for a
    kind the contract does not describe."""
    doc = load()
    if kind not in doc['$defs']['results']:
        raise KeyError(kind)
    return {'$schema': doc['$schema'], '$ref': f'#/$defs/results/{kind}', '$defs': doc['$defs']}


def target_schema(kind):
    """A self-contained schema for the ``target`` the server hands a Sentinel for a ``kind`` task."""
    doc = load()
    if kind not in doc['$defs']['targets']:
        raise KeyError(kind)
    return {'$schema': doc['$schema'], '$ref': f'#/$defs/targets/{kind}', '$defs': doc['$defs']}


def streamed():
    """The kinds that post partial results while they run (``$defs.partials``: ``bbot_discovery``, contract version 3) before the result that closes them."""
    return tuple(load()['$defs'].get('partials', {}))


def partial_schema(kind):
    """A self-contained schema for one batch of partial results a streamed ``kind`` task posts while it runs."""
    doc = load()
    if kind not in doc['$defs'].get('partials', {}):
        raise KeyError(kind)
    return {'$schema': doc['$schema'], '$ref': f'#/$defs/partials/{kind}', '$defs': doc['$defs']}
