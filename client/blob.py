"""Decode (and, for completeness, encode) the Sentinel provisioning blob.

The blob is standard base64 (RFC 4648, with padding) of compact JSON, nothing more: no custom framing, no new key
material, no signing. It is exactly the payload one of the server's three enrollment endpoints already returns
(``{enrollment_token, server_url, expires_at, scope}``, plus ``project`` or ``org`` where ``scope`` names one:
``POST projects/{slug}/sentinels/enroll`` for a project, ``orgs/{slug}/sentinels/enroll`` for an organization, or
``sentinels/enroll`` for the whole instance), packaged as one copy-pasteable string for a Sentinel's
``CVENGINE_SENTINEL_BLOB`` environment variable. This module is the client-side half of the format the server
documents and produces in ``agentapi.sentinel_broker.encode_enrollment_blob``/``decode_enrollment_blob``; the two are
not a shared import (this client has no Django dependency and ships separately from the server), so both sides
implement the same few lines independently, documented identically in both places.

``server_url`` is validated on decode (``httpclient.validate_server_url``): it must be ``https`` unless the operator set
``CVENGINE_SENTINEL_ALLOW_INSECURE=1``, and may carry no userinfo, query or fragment, so a blob can never point the
enrollment token at a cleartext or credential-bearing URL.
"""
import base64
import binascii
import json

from . import httpclient

REQUIRED_FIELDS = ('enrollment_token', 'server_url')


class BlobError(ValueError):
    """CVENGINE_SENTINEL_BLOB was not a valid provisioning blob. The message says why, never the raw value: it may be
    (or contain) a live enrollment secret, so callers must not log it."""


def decode_blob(raw):
    """``CVENGINE_SENTINEL_BLOB`` -> ``{enrollment_token, server_url, expires_at, scope, project|org}`` (``project``/``org``
    present only where ``scope`` names one; absent for an instance-wide blob). Raises ``BlobError`` (never anything
    else) on anything that is not valid base64-encoded JSON, that is missing a field the client needs, or whose
    ``server_url`` is not one this client will talk to (see the module docstring)."""
    if not isinstance(raw, str) or not raw.strip():
        raise BlobError('CVENGINE_SENTINEL_BLOB is empty')
    try:
        data = json.loads(base64.b64decode(raw.strip(), validate=True).decode('utf-8'))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise BlobError('CVENGINE_SENTINEL_BLOB is not a valid base64 JSON provisioning blob') from exc
    if not isinstance(data, dict):
        raise BlobError('CVENGINE_SENTINEL_BLOB is not a valid base64 JSON provisioning blob')
    missing = [key for key in REQUIRED_FIELDS if not isinstance(data.get(key), str) or not data[key]]
    if missing:
        raise BlobError(f'CVENGINE_SENTINEL_BLOB is missing: {", ".join(missing)}')
    try:
        httpclient.validate_server_url(data['server_url'])
    except httpclient.ServerURLError as exc:
        raise BlobError(f'CVENGINE_SENTINEL_BLOB has an unusable server_url: {exc}') from None
    return data


def encode_blob(payload):
    """The inverse of ``decode_blob``; not needed by the client in normal operation (the server builds the blob a
    person copies in), but kept here, tested, as the one place both sides of the format are written down."""
    return base64.b64encode(json.dumps(payload, separators=(',', ':')).encode('utf-8')).decode('ascii')
