"""The result contract between cvENGINE and a Sentinel (``sentinel_contract.json``), read from the copy packaged here.

The file is a byte-identical copy of the server's ``web/agentapi/sentinel_contract.json`` (CI checks it); the helpers below are the
reading half of the server's own ``agentapi/sentinel_contract.py``."""
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
