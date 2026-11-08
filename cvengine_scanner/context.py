"""The text around a secret, masked, for the ``context`` of a ``secrets_scan`` finding and of a ``route_probe`` credential.

The server shows a person WHAT was found: the line of the page or script around the value, with the value itself hidden. The hiding happens HERE, on
the Sentinel, before anything is sent: the value never leaves this machine inside a snippet. Pure: no I/O, no network, no logging.

The rules are the server's (``cveFeed.secrets_catalog.mask`` / ``mask_context`` / ``context_snippet`` and ``cveFeed.secret_redaction.redact_text``,
copied here the way ``probes.sensitive`` copies the server's detectors); the server's tests run both on one corpus and hold them equal, and run a
snippet from here through the server's own masking to check it is left as it is (the server masks again on receipt, as defence in depth):

* the value becomes its mask: the public format prefix of its kind, an ellipsis and its last four characters (``AIza…x7Qz``), the prefix alone for a
  value shorter than ``MIN_TAIL_LENGTH``, ``PEM RSA PRIVATE KEY`` for a private key;
* every OTHER secret-looking token in the stretch is masked too: the shapes of well-known secrets, a ``password=`` or ``x-api-key:`` pair, a bearer
  token, a URL's password (``redact_text``), and any other long run of letters and digits (``mask_runs``);
* control characters are replaced by a space, white space is collapsed, and the stretch is cut to ``WIDTH`` characters either side of the match, at most
  ``MAX_CONTEXT`` in all, with ``...`` where it was cut;
* a stretch in which the value, or a piece of 12 characters of it, can still be read is not sent at all (no context, never a half-masked one).

HTML is not escaped here: the server escapes it when it shows it.
"""
import re
import unicodedata

MASK_LEN = 80
TAIL = 4
MIN_TAIL_LENGTH = 16  # a value shorter than this shows no character of its own, only its prefix
MAX_CONTEXT = 200  # a snippet is at most this long (the contract allows 400: the server's own limit is looser than a correct Sentinel's)
WIDTH = 80  # characters kept either side of the value
MIN_VALUE = 8
_NOT_TEXT = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn'})  # control, format (a right-to-left override, a zero-width joiner), surrogate, private use, unassigned


def _chars(text):
    """``text`` with its control and format characters as spaces (a tab and a line break stay, so a value of several lines is still found in it)."""
    return ''.join(' ' if unicodedata.category(c) in _NOT_TEXT and c not in '\t\n' else c for c in text)
_ELLIPSIS = '…'

# ----------------------------------------------------------------------------- the mask of one value (``cveFeed.secrets_catalog``)

_PREFIXES = re.compile(
    r'^(?:AIza|AKIA|ASIA|AGPA|AIDA|AROA|github_pat_|gh[pousr]_|glpat-|gldt-|glrt-|xox[abposre]-|xapp-|[spr]k_(?:live|test)_|sk-ant-(?:api\d\d-|admin\d\d-)?|'
    r'sk-(?:proj-|svcacct-|admin-)?|SG\.|key-|npm_|pypi-|eyJ|pk\.|sk\.|AC|SK|https?://hooks\.slack\.com/|https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/|'
    r'[a-z][a-z0-9+.-]{1,20}://)')
_PEM = re.compile(r'-----BEGIN ((?:[A-Z0-9]{1,12} ){0,3}PRIVATE KEY(?: BLOCK)?)-----')


def normalise(value):
    """The value without surrounding white space or quotes (``cveFeed.secrets_catalog.normalise``)."""
    text = str(value if value is not None else '').strip()
    while len(text) >= 2 and text[0] == text[-1] and text[0] in '"\'`':
        text = text[1:-1].strip()
    return text


def mask(value, kind=''):
    """How a secret is shown: its format prefix, an ellipsis and its last four characters (``AIza…x7Qz``); the prefix alone for a value shorter than
    ``MIN_TAIL_LENGTH``; ``PEM RSA PRIVATE KEY`` for a private key. Never more than the prefix and four characters."""
    text = normalise(value)
    if not text:
        return ''
    pem = _PEM.search(text[:200])
    if pem or kind == 'private-key':
        return (f'PEM {pem.group(1)}' if pem else 'PEM PRIVATE KEY')[:MASK_LEN]
    found = _PREFIXES.match(text)
    prefix = found.group(0) if found else ''
    if len(prefix) > 40 or len(prefix) >= len(text) - TAIL:
        prefix = prefix[:12] if len(text) - TAIL > 12 else ''
    tail = text[-TAIL:] if len(text) >= MIN_TAIL_LENGTH else ''
    return f'{prefix}{_ELLIPSIS}{tail}'[:MASK_LEN]


# ----------------------------------------------------------------------------- the other secrets in the text (``cveFeed.secret_redaction``)

MAX_TEXT = 2_000_000


def _mark(value, kind, prefix=''):
    # the server's ``_mask`` with no keyed fingerprint: a Sentinel holds no server key, and a fingerprint is the server's to add
    return f'{prefix}\u2026[redacted {len(str(value))} chars, {kind}]'


_B = r'(?<![A-Za-z0-9_-])'
_PEM_KIND = r'(?:[A-Z]{2,10} ){0,3}PRIVATE KEY(?: BLOCK)?'
_BASE64_RUN = r'[A-Za-z0-9+/=]{20,8192}'
SHAPES = (
    ('private_key', '', re.compile(
        r'-----BEGIN ' + _PEM_KIND + r'-----(?:\s|\\n){0,4}' + _BASE64_RUN + r'(?:(?:\s|\\n){1,4}' + _BASE64_RUN + r'){0,200}'
        r'(?:(?:\s|\\n){0,4}[A-Za-z0-9+/=]{0,76}(?:\s|\\n){0,4}-----END ' + _PEM_KIND + r'-----)?')),
    ('jwt', 'eyJ', re.compile(_B + r'eyJ[A-Za-z0-9_-]{5,4096}\.eyJ[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{0,4096}')),
    ('google_api_key', 'AIza', re.compile(_B + r'AIza[0-9A-Za-z_-]{35,64}')),
    ('google_oauth_secret', 'GOCSPX-', re.compile(_B + r'GOCSPX-[0-9A-Za-z_-]{20,64}')),
    ('aws_access_key_id', 'AKIA|ASIA', re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])')),
    ('github_token', r'gh[pousr]_|github_pat_', re.compile(_B + r'(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})')),
    ('gitlab_token', 'glpat-', re.compile(_B + r'glpat-[A-Za-z0-9_-]{20,64}')),
    ('slack_token', r'xox[abprs]-', re.compile(_B + r'xox[abprs]-[A-Za-z0-9-]{10,250}')),
    ('slack_webhook', 'https://hooks[.]slack[.]com/', re.compile(r'https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,200}')),
    ('discord_webhook', '', re.compile(r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{5,30}/[A-Za-z0-9_-]{20,200}')),
    ('stripe_key', r'[spr]k_(?:live|test)_', re.compile(_B + r'[spr]k_(?:live|test)_[0-9A-Za-z]{10,99}')),
    ('anthropic_key', 'sk-ant-', re.compile(_B + r'sk-ant-[A-Za-z0-9_-]{20,200}')),
    ('openai_key', 'sk-', re.compile(_B + r'sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}')),
    ('sendgrid_key', 'SG[.]', re.compile(_B + r'SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}')),
    ('mailgun_key', 'key-', re.compile(_B + r'key-[0-9a-f]{32}(?![0-9A-Za-z])')),
    ('twilio_sid_or_key', 'AC|SK', re.compile(r'(?<![A-Za-z0-9])(?:AC|SK)[0-9a-f]{32}(?![0-9A-Za-z])')),
    ('npm_token', 'npm_', re.compile(_B + r'npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])')),
    ('pypi_token', 'pypi-', re.compile(_B + r'pypi-[A-Za-z0-9_-]{50,200}')),
    ('azure_storage_key', '', re.compile(r'(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{30,100}={0,2}')),
    ('aws_secret_access_key', '', re.compile(r'(?i:aws_secret_access_key|secret_access_key)["\']?\s{0,3}[:=]\s{0,3}["\']?[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])')),
)
_URL_CREDENTIAL = re.compile(r'(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:/@"\'\\,<>?#]{0,128}:)([^\s/"\'\\,<>?#]{1,256})(@)')
_KEY_VALUE = re.compile(
    r'(?<![A-Za-z0-9])((?:[A-Za-z0-9]{1,20}[_-]){0,3}(?:password|passwd|api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)'
    r'["\']?\s{0,3}[:=]\s{0,3}(["\']?))([^\s"\'<>,;&\\]{6,512})', re.I)
_PLACEHOLDER = re.compile(r'^(?:[*x#.\-_]+|null|none|true|false|undefined|required|optional|string|your[_-].*|example|changeme)$', re.I)
_BEARER = re.compile(r'(\bBearer\s+)(?!(?-i:[a-z-]+)(?![A-Za-z0-9._~+/=-]))([A-Za-z0-9._~+/=-]{16,2048})', re.I)
_AUTH_HEADER = re.compile(r'(\bAuthorization["\']?\s{0,3}[:=]\s{0,3}["\']?(?:Basic|Token|Digest)\s+)([A-Za-z0-9._~+/=-]{8,2048})', re.I)
_BBOT_BRACKET = re.compile(r'(\b(?:Secret|Raw ?(?:V2)? result)\s{0,3}:\s{0,3}\[)([^\[\]\n]{1,1024})(\])')
_BBOT_PRODUCT = re.compile(r'(\bProduct\s{0,3}:\s{0,3}\[)([^\[\]\s]{40,2048})(\])')
_MASKED = '\u2026[redacted '


def _prefix_of(text, prefix):
    found = re.match(prefix, text) if prefix else None
    return found.group(0) if found else ''


def _sub_shape(kind, prefix):
    return lambda match: _mark(match.group(0), kind, _prefix_of(match.group(0), prefix))


_A_MASK = re.compile('^[A-Za-z0-9_.:/+-]{0,40}\u2026[A-Za-z0-9_-]{0,4}$')  # what ``mask`` makes of a value: a prefix, an ellipsis, up to four characters


def _plausible_value(value, quoted):
    if value.startswith(('\u2026', '$', '{', '%', '@')) or '[redacted' in value or _A_MASK.match(value) or _PLACEHOLDER.match(value):
        return False
    return quoted or bool(re.search(r'[0-9!#$%^*_+=/~]', value))


def _mask_key_value(match):
    if not _plausible_value(match.group(3), bool(match.group(2))):
        return match.group(0)
    return match.group(1) + _mark(match.group(3), 'secret_value')


def _redact_piece(text):
    for kind, prefix, pattern in SHAPES:
        text = pattern.sub(_sub_shape(kind, prefix), text)
    text = _URL_CREDENTIAL.sub(lambda m: m.group(1) + _mark(m.group(2), 'url_password') + m.group(3), text)
    text = _KEY_VALUE.sub(_mask_key_value, text)
    text = _BEARER.sub(lambda m: m.group(1) + _mark(m.group(2), 'bearer_token'), text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + _mark(m.group(2), 'auth_header'), text)
    text = _BBOT_BRACKET.sub(lambda m: m.group(0) if _MASKED in m.group(2) else m.group(1) + _mark(m.group(2), 'secret') + m.group(3), text)
    return _BBOT_PRODUCT.sub(lambda m: m.group(1) + _mark(m.group(2), 'secret_product') + m.group(3), text)


def redact_text(text):
    """``text`` with every well-known secret shape masked (the server's ``secret_redaction.redact_text``, without its keyed fingerprint)."""
    if not isinstance(text, str) or len(text) < 8:
        return text
    if len(text) <= MAX_TEXT:
        return _redact_piece(text)
    return ''.join(_redact_piece(text[i:i + MAX_TEXT]) for i in range(0, len(text), MAX_TEXT))


# A run of letters and digits that holds both and is long enough to be a key, a token or a hash: masked even when no detector knows its provider
# (a header such as ``x-api-key: <hex>``, a hash, a session id). Plain words, paths and identifiers hold no digit or are shorter than this.
_RUN = re.compile(r'(?<![A-Za-z0-9])[A-Za-z0-9]{24,512}(?![A-Za-z0-9])')


def mask_runs(text):
    def sub(match):
        run = match.group(0)
        return _mark(run, 'token') if re.search(r'[0-9]', run) and re.search(r'[A-Za-z]', run) else run
    return _RUN.sub(sub, text)


# ----------------------------------------------------------------------------- the snippet

def mask_context(context, value, kind='', others=()):
    """``context`` (text around a secret) with ``value`` replaced by its mask, every other secret-looking token masked, control characters removed
    and the length clipped. ``''`` when ``value`` could still be read in the result: a snippet that cannot be proved clean is not sent."""
    text = _chars(str(context or ''))
    values = [(normalise(v), kind if v is value else '') for v in (value, *others)]
    for needle, k in values:
        if needle:
            masked = mask(needle, k)
            for variant in dict.fromkeys((needle, needle.replace('/', '\\/'), needle.replace('\\', '\\\\'), needle.replace('"', '\\"'))):
                text = text.replace(variant, masked)
    text = mask_runs(redact_text(text))
    for needle, k in values:
        shown = mask(needle, k) if needle else ''
        if needle and (needle in text or any(piece in text and piece not in shown for piece in (needle[i:i + 12] for i in range(0, max(1, len(needle) - 11), 4)))):
            return ''
    return re.sub(r'\s+', ' ', text).strip()


def snippet(line_text, start, end, value, kind='', width=WIDTH, others=()):
    """The masked stretch of ``line_text`` around ``line_text[start:end]`` (the match, ``value`` in full): ``width`` characters either side, at most
    ``MAX_CONTEXT`` in all, centred on the match, ``...`` where the line goes on. ``''`` when it cannot be shown safely."""
    low, high = max(0, start - width), min(len(line_text), end + width)
    out = mask_context(line_text[low:high], value, kind, others)
    if not out:
        return ''
    out = ('... ' if low > 0 else '') + out + (' ...' if high < len(line_text) else '')
    if len(out) > MAX_CONTEXT:  # long masks of other tokens: keep the middle (the match), which is the centre of the stretch
        cut = (len(out) - MAX_CONTEXT) // 2
        out = '... ' + out[cut + 4:cut + MAX_CONTEXT - 4] + ' ...'
    return out


def context_snippet(text, value, kind='', width=WIDTH):
    """``(line, snippet)`` for the first place ``value`` is in ``text``: its 1-based line and the masked stretch of that line around it
    (``cveFeed.secrets_catalog.context_snippet`` for a value that is whole). ``(None, '')`` when the value is not in the text or is too short to look for."""
    text = str(text or '')
    needle = normalise(value)
    if len(needle) < MIN_VALUE:
        return None, ''
    at = text.find(needle)
    if at < 0:
        return None, ''
    line = text.count('\n', 0, at) + 1
    start = text.rfind('\n', 0, at) + 1
    end = text.find('\n', at + len(needle))
    end = len(text) if end < 0 else end
    return line, snippet(text[start:end], at - start, at - start + len(needle), needle, kind, width)


# ----------------------------------------------------------------------------- a Kingfisher finding

def locate(text, line, value, column=None):
    """``(line text, start, end, whole value)`` of the match Kingfisher reported at 1-based ``line`` of ``text``, or ``None``. ``value`` is Kingfisher's
    ``snippet`` (the matched value); ``column`` its 0-based ``column_start``, used to pick the right one when the line holds the value twice. A value
    that is not on that line (Kingfisher decoded it from base64, say) is not guessed at."""
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return None
    lines = str(text or '').split('\n')
    needle = normalise(value)
    if line > len(lines) or len(needle) < MIN_VALUE:
        return None
    row = lines[line - 1].rstrip('\r')
    starts, at = [], row.find(needle)
    while at >= 0 and len(starts) < 50:
        starts.append(at)
        at = row.find(needle, at + 1)
    if not starts:
        return None
    near = column if isinstance(column, int) and not isinstance(column, bool) else 0
    start = min(starts, key=lambda a: abs(a - near))
    return row, start, start + len(needle), needle


def finding_context(text, line, value, column=None, kind='', others=()):
    """The masked snippet for one Kingfisher finding, or ``''``."""
    where = locate(text, line, value, column)
    if where is None:
        return ''
    row, start, end, whole = where
    return snippet(row, start, end, whole, kind, others=others)
