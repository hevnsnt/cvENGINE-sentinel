#!/usr/bin/env python3
"""The browser half of the ``web_screenshot`` kind (``client/shot.py`` is the other half), copied from cvENGINE's ``cveFeed.shot_worker``. It runs as a
child process of the daemon, never inside it: a browser that leaks or crashes must die with its process instead of growing the daemon, the daemon
can kill the whole process group, and Playwright's own threads stay out of the daemon's. One child serves one task's pages, one after another (one
browser, one fresh context per page), then exits.

This file imports nothing of the daemon. The parent sends one JSON line on stdin: ``{"targets": [{"key", "url", "out"}], "settings": {...},
"proxy": {"server", "password"}}``, and the child answers one JSON line per page on stdout (``{"op": "result", "key", "outcome", "reason", ...}``),
then ``{"op": "done"}`` (or ``{"op": "fatal", "reason"}`` when the browser could not run).

The child never connects anywhere itself. Every page's browser context is pointed at the parent's vetting proxy (``client/shotproxy.py``, with the
page key as the proxy user), and loopback is sent through it too, so the task's scope policy judges the page, every redirect hop and every
sub-resource before a byte leaves; a job without a proxy is refused. A page gets a fresh context: no cookies or storage carry over, downloads are
refused, no permission is granted, service workers are blocked, dialogs and pop-ups are dismissed. HTTPS errors are ignored on purpose: an expired
or self-signed certificate is exactly the kind of host this is for. Nothing here is a scan; it loads a page once, the way a person would, and takes a
picture of it.

Chromium's own sandbox is always on: every launch is checked before the first page is opened (the renderer must be in a user namespace and a PID
namespace of its own, under a seccomp filter of its own, and the browser must not carry ``--no-sandbox``), and a browser whose sandbox cannot start or
did not engage loads nothing: the child answers ``fatal`` with a reason that starts with ``sandbox: ``. There is no switch that turns it off.
``python3 -m client.shot_child --probe`` runs only that check (one ``result`` line with ``engaged``), loads nothing from anywhere and needs no proxy.
"""
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

from cvengine_scanner.probes import screenshots as lib

VIEWPORT = lib.VIEWPORT
NAV_TIMEOUT_MS = 15000       # for the page to commit and parse
TOTAL_SECONDS = lib.DEFAULT_SECONDS  # the whole of one page: navigation, settling and the picture
SETTLE_MS = 600              # a last moment for fonts and late layout after the load event
LAUNCH_ARGS = ('--disable-dev-shm-usage', '--disable-gpu', '--mute-audio', '--no-first-run', '--disable-extensions',
               '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-notifications',
               '--hide-scrollbars',
               # WebRTC sends UDP straight from the browser, around the vetting proxy (a STUN URL in a page names a host and a port of its choosing, loopback
               # and the metadata address included, and its name is resolved by Chromium itself): with this policy only proxied traffic is allowed, and
               # none of it is UDP. QUIC is UDP too.
               '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-quic',
               # one renderer, with a heap ceiling: a hostile page cannot start a process per frame or grow without bound (the parent also kills the
               # whole tree above CVENGINE_SCREENSHOT_MAX_RSS_MB)
               '--renderer-process-limit=1', '--js-flags=--max-old-space-size=512')
LOCAL_SCHEMES = ('data', 'blob', 'about')
NETWORK_SCHEMES = ('http', 'https')
SANDBOX_PREFIX = lib.SANDBOX_PREFIX
classify_error = lib.classify_error


class Capturer:
    """Captures one page at a time with a browser that is already running, every page through the parent's vetting proxy."""

    def __init__(self, browser, settings=None, clock=time.monotonic):
        self.browser, self.clock = browser, clock
        self.settings = dict(settings or {})
        proxy = self.settings.get('proxy') or {}
        if not proxy.get('server') or not proxy.get('password'):
            raise ValueError('no vetting proxy: the browser is never run without one')

    def _context(self, key):
        width, height = self.settings.get('viewport') or VIEWPORT
        proxy = self.settings['proxy']
        options = {'viewport': {'width': width, 'height': height}, 'ignore_https_errors': True, 'accept_downloads': False,
                   'service_workers': 'block', 'java_script_enabled': True, 'locale': 'en-US', 'timezone_id': 'UTC',
                   'permissions': [], 'bypass_csp': False,
                   # <-loopback>: localhost and 127.0.0.1 go through the proxy too (Chromium bypasses it for them otherwise), so a redirect to
                   # one is judged and refused there instead of reaching this container's own services
                   'proxy': {'server': proxy['server'], 'username': str(key), 'password': proxy['password'], 'bypass': '<-loopback>'}}
        agent = self.settings.get('user_agent')
        if agent:
            options['user_agent'] = agent
        return self.browser.new_context(**options)

    def capture(self, target):
        """The result dict of one page: ``outcome`` (ok, timeout, unreachable, tls_error or error), a plain ``reason``, and for a page that was
        reached ``final_url``, ``status``, ``title`` and the ``path`` of the PNG written. ``blocked`` is the parent's call: it knows which
        connections its proxy refused."""
        started = self.clock()
        total = float(self.settings.get('total_seconds') or TOTAL_SECONDS)
        nav_ms = int(self.settings.get('nav_timeout_ms') or NAV_TIMEOUT_MS)
        result = {'key': target['key'], 'outcome': 'error', 'reason': '', 'final_url': '', 'status': None, 'title': '', 'path': ''}
        context = page = None

        def remaining():
            return max(1.0, total - (self.clock() - started))
        try:
            context = self._context(target['key'])
            page = context.new_page()
            page.on('dialog', lambda dialog: _quietly(dialog.dismiss))
            page.on('popup', lambda popup: _quietly(popup.close))
            page.route('**/*', _only_web)
            try:
                response = page.goto(target['url'], wait_until='domcontentloaded', timeout=int(min(nav_ms, remaining() * 1000)))
            except Exception as exc:  # noqa: BLE001 - classified
                result['outcome'], result['reason'] = classify_error(exc)
                return result
            for wait, cap in (('load', 6000), ('networkidle', 2500)):  # a page that never goes idle is photographed as it is
                _quietly(lambda wait=wait, cap=cap: page.wait_for_load_state(wait, timeout=int(min(cap, remaining() * 1000))))
            _quietly(lambda: page.wait_for_timeout(SETTLE_MS))
            final = page.url or ''
            if final.startswith(('chrome-error:', 'about:')):
                result['outcome'], result['reason'] = 'unreachable', 'The browser showed an error page instead of the site.'
                return result
            result['final_url'] = final[:2000]
            result['status'] = response.status if response is not None else None
            result['title'] = _title(page)
            out = target['out']
            os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
            page.screenshot(path=out, type='png', full_page=False, timeout=int(min(10000, max(2000, remaining() * 1000))),
                            animations='disabled', caret='hide')
            if not os.path.isfile(out) or os.path.getsize(out) == 0:
                result['outcome'], result['reason'] = 'error', 'The browser produced an empty picture.'
                return result
            result.update(outcome='ok', path=out)
            return result
        except Exception as exc:  # noqa: BLE001 - one page failing must never end the batch
            result['outcome'], result['reason'] = classify_error(exc)
            return result
        finally:
            for closer in (page and page.close, context and context.close):
                if closer:
                    _quietly(closer)


def _only_web(route):
    """Anything that is not http, https or an inline ``data:`` or ``blob:`` URL never leaves the browser (``file:``, ``ftp:``, ``chrome:``)."""
    try:
        scheme = (urlsplit(route.request.url).scheme or '').lower()
        if scheme in LOCAL_SCHEMES + NETWORK_SCHEMES:
            return route.continue_()
        return route.abort('blockedbyclient')
    except Exception:  # noqa: BLE001 - when in doubt the request does not go out
        _quietly(lambda: route.abort('blockedbyclient'))


def _quietly(call):
    try:
        return call()
    except Exception:  # noqa: BLE001 - teardown and optional waits never decide the outcome
        return None


def _title(page):
    try:
        return re.sub(r'\s+', ' ', page.title() or '').strip()[:300]
    except Exception:  # noqa: BLE001 - a page that is gone has no title
        return ''


# ----------------------------------------------------------------------------- Chromium's sandbox

class SandboxError(Exception):
    """Chromium's sandbox could not start, or the browser runs without it: the message says why in plain words."""


def verify_sandbox(browser, inspect=lib.browser_processes):
    """Open a blank page (nothing is loaded from anywhere: a context without a proxy of its own has only the browser's placeholder) so a renderer
    exists, then check it is sandboxed. Returns '' or why not."""
    context = browser.new_context()
    try:
        page = context.new_page()
        page.set_content('<!doctype html><title>sandbox check</title>')
        return lib.judge_sandbox(*inspect())
    finally:
        _quietly(context.close)


APPARMOR = ("the host's AppArmor profile blocks Chromium's sandbox: run the scanner with an AppArmor profile that allows user namespaces "
            "(config/apparmor/cvengine-scanner in the cvENGINE repository, docs/DEPLOYMENT.md \"Screenshots and AppArmor\")")


def apparmor_words(message):
    """The plain reason when Chromium's own log says the kernel refused it the user namespace its sandbox needs (``FATAL:credentials.cc ... Check failed:
    Permission denied (13)``: Docker's ``docker-default`` AppArmor profile on a host that restricts unprivileged user namespaces), or ''. Playwright's own
    message is only \"Target page, context or browser has been closed\", with the browser log after it; either form is recognised."""
    low = str(message or '').lower()
    if 'credentials.cc' in low or ('permission denied (13)' in low and ('check failed' in low or 'fatal' in low)):
        return APPARMOR
    return ''


def launch(playwright, verify=verify_sandbox):
    """The browser, started with Chromium's sandbox (Playwright's own default is without it) and checked before it is used. There is no way to ask
    for it without the sandbox. Raises ``SandboxError`` when the sandbox could not start or did not engage; a browser that runs without it is closed,
    never handed back."""
    try:
        # 'per-context': every page's context names its own proxy (and credentials), see Capturer._context; nothing goes direct
        browser = playwright.chromium.launch(args=list(LAUNCH_ARGS), proxy={'server': 'per-context'}, chromium_sandbox=True)
    except Exception as exc:  # noqa: BLE001 - the sandbox's own failures are told apart from the rest
        words = apparmor_words(exc) or lib.sandbox_words(exc)
        if words:
            raise SandboxError(words) from exc
        raise
    try:
        why = verify(browser)
    except Exception as exc:  # noqa: BLE001 - a check that could not run is not a pass
        if apparmor_words(exc):
            _quietly(browser.close)
            raise SandboxError(APPARMOR) from exc
        detail = re.sub(r'\s+', ' ', str(exc))[:120] or type(exc).__name__
        why = f'the check could not run ({detail})'
    if why:
        _quietly(browser.close)
        raise SandboxError(f"Chromium's sandbox did not engage: {why}.")
    return browser


# ----------------------------------------------------------------------------- the child process

def _emit(stream, obj):
    stream.write(json.dumps(obj, separators=(',', ':')) + '\n')
    stream.flush()


def probe(stdout):
    """``--probe``: start the browser with its sandbox, check it engaged, and answer one ``result`` line (``engaged``, ``reason``, ``version``)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _emit(stdout, {'op': 'fatal', 'reason': 'Playwright is not installed.'})
        return 2
    try:
        with sync_playwright() as playwright:
            browser = launch(playwright)
            version = browser.version
            _quietly(browser.close)
    except SandboxError as exc:
        _emit(stdout, {'op': 'result', 'key': 'sandbox', 'engaged': False, 'reason': str(exc)})
        _emit(stdout, {'op': 'done'})
        return 1
    except Exception as exc:  # noqa: BLE001 - the browser did not start for another reason: not a verdict on the sandbox
        _emit(stdout, {'op': 'fatal', 'reason': re.sub(r'\s+', ' ', str(exc))[:300] or type(exc).__name__})
        return 2
    _emit(stdout, {'op': 'result', 'key': 'sandbox', 'engaged': True, 'reason': '', 'version': version})
    _emit(stdout, {'op': 'done'})
    return 0


def main(stdin=None, stdout=None, argv=()):
    stdout = stdout or os.fdopen(os.dup(1), 'w', buffering=1)
    sys.stdout = sys.stderr  # whatever a library prints is not the protocol
    if '--probe' in argv:
        return probe(stdout)
    stdin = stdin or sys.stdin
    job = json.loads(stdin.readline() or '{}')
    settings = dict(job.get('settings') or {})
    settings['proxy'] = job.get('proxy') or {}
    if not (settings['proxy'].get('server') and settings['proxy'].get('password')):
        _emit(stdout, {'op': 'fatal', 'reason': 'No vetting proxy was given; the browser is never run without one.'})
        return 2
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _emit(stdout, {'op': 'fatal', 'reason': 'Playwright is not installed.'})
        return 2
    try:
        with sync_playwright() as playwright:
            try:
                browser = launch(playwright)
            except SandboxError as exc:
                _emit(stdout, {'op': 'fatal', 'reason': SANDBOX_PREFIX + str(exc)})
                return 4
            try:
                _emit(stdout, {'op': 'sandbox', 'engaged': True, 'version': browser.version})  # the proof above passed: only now does any page open
                if not settings.get('user_agent'):
                    settings['user_agent'] = f'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser.version} Safari/537.36'
                capturer = Capturer(browser, settings)
                for target in job.get('targets') or []:
                    _emit(stdout, {'op': 'result', **capturer.capture(target)})
                    if not browser.is_connected():
                        _emit(stdout, {'op': 'fatal', 'reason': 'The browser stopped.'})
                        return 3
            finally:
                _quietly(browser.close)
    except Exception as exc:  # noqa: BLE001 - the parent is told why nothing was captured
        _emit(stdout, {'op': 'fatal', 'reason': re.sub(r'\s+', ' ', str(exc))[:300] or type(exc).__name__})
        return 2
    _emit(stdout, {'op': 'done'})
    return 0


if __name__ == '__main__':
    sys.exit(main(argv=sys.argv[1:]))
