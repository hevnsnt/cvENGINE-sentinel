"""What one HTTP response says it runs, for the probes: the shared reader (``cvengine_scanner.fingerprint``) plus what the page's scripts
state, read here with ``js_libraries`` (which the shared reader leaves to its caller). The same functions as cvENGINE's ``cveFeed.fingerprint``."""
from urllib.parse import urlsplit

from .. import fingerprint as shared
from ..fingerprint import MAX_FINGERPRINTS, categorize, extend, generator_content, script_srcs, versioned  # noqa: F401 - the reader's API

__all__ = ['MAX_FINGERPRINTS', 'categorize', 'extend', 'from_response', 'from_script_body', 'from_script_urls', 'generator_content',
           'script_sources', 'script_srcs', 'versioned']


def from_response(server="", powered_by="", body="", content_type="", scripts=(), script_bodies=(), headers=None):
    """``[{'name', 'source'}]`` for one response (``cvengine_scanner.fingerprint.from_response``). ``scripts`` are the script URLs the page loads
    and ``script_bodies`` the text of ones read from the same host: what they name is added after the page's own markers."""
    pairs = from_script_urls(scripts)
    for text in script_bodies:
        pairs += from_script_body(text)
    return shared.from_response(server, powered_by, body, content_type, from_scripts=pairs, headers=headers)


def script_sources(body, page_url, limit=4):
    """``(all script URLs, same-host ones to read)`` of a page: absolute URLs, at most ``limit`` to fetch. A script on another host (a CDN) is
    identified by its name only, never fetched. The page is read the way a browser tokenizes it (``js_libraries.parse_page``): a ``<script
    src>`` inside an HTML comment or inside another script's text is not a script the page loads, and a fallback written only when another
    script fails is not either."""
    from . import js_libraries
    page = urlsplit(page_url or "")
    every, local = [], []
    for entry in js_libraries.parse_page(body, page_url):
        absolute = entry.get("url")
        if not absolute or entry.get("fallback"):
            continue
        try:
            parts = urlsplit(absolute)
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or not parts.hostname or absolute in every:
            continue
        every.append(absolute)
        if parts.hostname.lower() == (page.hostname or "").lower() and parts.port == page.port and len(local) < limit:
            local.append(absolute)
    return every[:40], local


def from_script_urls(urls):
    """``[(name, 'script:filename')]`` from the names of the scripts a page loads, with the version a file name or CDN path carries. A hint
    only; a query string never gives a version."""
    from . import js_libraries
    out = []
    for url in urls:
        hint = js_libraries.identify(url)
        if hint['library']:
            out.append((versioned(js_libraries.LIBRARIES[hint['library']][0], hint['filename_version']), "script:filename"))
    return out


def from_script_body(text):
    """``[(name, 'script:body')]`` a script's own text states: its comment banner or, for jQuery and a few others, code only its file has."""
    from . import js_libraries
    return [(versioned(js_libraries.LIBRARIES[key][0], version), "script:body") for key, version, _how in js_libraries.read_body(text)]
