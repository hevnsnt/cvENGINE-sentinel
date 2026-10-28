"""Run against a real, pinned gvmd (see .github/workflows/openvas-integration.yml): take over the default login the way a first-start Sentinel does,
prove the new login works, and ask whether GVM can scan yet. Prints what happened, never a password. Exits non-zero when the bootstrap fails."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client import openvas  # noqa: E402


def main():
    username, _password = openvas.bootstrap_credentials()
    print(f'bootstrapped; this Sentinel logs in to gvmd as {username!r}')
    with openvas.session() as gmp:
        version = gmp.get_version()
        print('authenticated with the saved login; GMP version element:', version.find('version').text if version.find('version') is not None else '?')
    if openvas.load_credentials() is None:
        print('the credentials were not saved', file=sys.stderr)
        return 1
    ready, why = openvas.readiness()
    print('ready to scan:', ready, '-', why or 'ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
