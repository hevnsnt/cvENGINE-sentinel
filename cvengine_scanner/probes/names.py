"""Host name helpers the probes need, copied from cvENGINE's ``targetApp.target_types`` and ``targetApp.shared_domains`` so the library has no
Django in it: whether a value is a domain name, its registrable domain, and the shared (multi-tenant) domains whose tenants each own only their
own name. Pure."""
import ipaddress
import re

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z][A-Za-z0-9-]{0,62}$"  # TLD must start with a letter (excludes 999.1.1.1)
)
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc"}
_suffix_extractor = None

# kept equal to targetApp.shared_domains.SHARED_DOMAINS on the server
SHARED_DOMAINS = frozenset({
    'jfrog.com', 'jfrog.io', 'atlassian.net', 'atlassian.com', 'jira.com', 'zendesk.com', 'freshdesk.com',
    'statuspage.io', 'readthedocs.io', 'readthedocs.org', 'surge.sh', 'myshopify.com', 'wpengine.com',
    'service-now.com', 'salesforce.com', 'force.com', 'okta.com', 'oktapreview.com', 'okta-emea.com',
    'cloudflareaccess.com', 'onmicrosoft.com', 'sharepoint.com',
    'github.io', 'gitlab.io', 'netlify.app', 'netlify.com', 'vercel.app', 'pages.dev', 'workers.dev',
    'herokuapp.com', 'herokudns.com', 'web.app', 'firebaseapp.com',
    'amazonaws.com', 's3.amazonaws.com', 'elasticbeanstalk.com', 'cloudfront.net', 'awsapprunner.com',
    'azurewebsites.net', 'cloudapp.azure.com', 'cloudapp.net', 'azureedge.net', 'azurefd.net', 'trafficmanager.net',
    'windows.net', 'blob.core.windows.net',
    'appspot.com', 'cloudfunctions.net', 'run.app', 'googleusercontent.com',
    'fastly.net', 'akamaihd.net', 'akamaized.net', 'edgekey.net', 'edgesuite.net', 'b-cdn.net',
    'onrender.com', 'blogspot.com', 'fly.dev', 'railway.app', 'deno.dev', 'glitch.me', 'repl.co', 'replit.app', 'replit.dev',
    'wixsite.com', 'squarespace.com', 'webflow.io', 'ondigitalocean.app', 'digitaloceanspaces.com', 'r2.dev',
    'storage.googleapis.com', 'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'loca.lt',
})


def clean(name):
    return (name or '').strip().lower().rstrip('.')


def is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip().strip('[]'))
        return True
    except ValueError:
        return False


def is_domain(value):
    """Whether ``value`` is a domain name (not an address, a range or junk)."""
    text = (value or '').strip()
    return bool(text) and not is_ip(text) and bool(_DOMAIN_RE.match(text))


def apex_domain(name):
    """The registrable domain of a domain name (``www.example.com`` -> ``example.com``), through tldextract's bundled list when it is installed,
    else the last two labels (three after a two-letter country code that follows a generic second level). None for anything not a domain."""
    global _suffix_extractor
    name = clean(name)
    if not is_domain(name):
        return None
    try:
        if _suffix_extractor is None:
            import tldextract
            _suffix_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
        return _suffix_extractor(name).top_domain_under_public_suffix or None
    except ImportError:
        labels = name.split(".")
        if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])


def shared_domain_of(name):
    """The SHARED_DOMAINS entry that ``name`` is or sits under (the longest), or None."""
    labels = clean(name).split('.')
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if candidate in SHARED_DOMAINS:
            return candidate
    return None
