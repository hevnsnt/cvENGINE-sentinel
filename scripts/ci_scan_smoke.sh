#!/bin/sh
# Scan smoke test, run by .github/workflows/image.yml INSIDE the built image under the settings docker-compose.yml gives the sentinel service
# (cap_drop ALL + NET_RAW and SYS_CHROOT, the Playwright seccomp profile), as the image's own unprivileged user (uid 10001).
# It scans only the container's own loopback (a web server and a TLS server it starts itself), never another host. Each tool must start, do its job
# and need nothing the service dropped: an "Operation not permitted", "Permission denied" or "Read-only file system" in a tool's output fails the run.
#
#   nmap -sS and -O and -sU, naabu -scan-type s   need raw sockets: this is what proves which capabilities the container must keep
#   nuclei, WPScan, wafw00f, testssl.sh, Kingfisher, sshamble, bbot   write their working files under $HOME or /tmp
set -u
fail() { echo "SMOKE FAILED: $*" >&2; FAILED=1; }
FAILED=0
echo "uid $(id -u), $(grep -c . /proc/self/status) status lines; capabilities:"; grep '^Cap' /proc/self/status
echo "--- mounts and what this user can write:"
grep -E ' /(tmp|home|var/lib/cvengine)' /proc/mounts | cut -c1-200
for dir in /tmp /home/sentinel/.cache /home/sentinel/.config /home/sentinel/.bbot/cache /home/sentinel/.bbot/logs /home/sentinel/.bbot/temp /var/lib/cvengine-sentinel; do
  if [ -d "$dir" ] && touch "$dir/.smoke-probe" 2>/dev/null; then rm -f "$dir/.smoke-probe"; echo "writable: $dir"; else echo "NOT writable: $dir ($(ls -ld "$dir" 2>&1))"; fi
done
echo "--- what the image keeps in ~/.bbot:"; du -sh "$HOME"/.bbot/* 2>&1 | head -n 20; ls -la "$HOME/.bbot/tools" 2>&1 | head -n 25
work=$(mktemp -d) || { echo "SMOKE FAILED: cannot make a temporary directory" >&2; exit 1; }
mkdir "$work/www" "$work/src"
echo '<html><head><title>smoke</title></head><body>cvengine smoke</body></html>' > "$work/www/index.html"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work/www" >/dev/null 2>&1 &
HTTP=$!
python3 - "$work" <<'PY' &
import datetime, http.server, ssl, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
work = sys.argv[1]
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
now = datetime.datetime.now(datetime.timezone.utc)
cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2)).sign(key, hashes.SHA256())
with open(work + '/c.pem', 'wb') as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
with open(work + '/k.pem', 'wb') as f:
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(work + '/c.pem', work + '/k.pem')
server = http.server.HTTPServer(('127.0.0.1', 18443), http.server.SimpleHTTPRequestHandler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
TLS=$!
trap 'kill $HTTP $TLS 2>/dev/null; rm -rf "$work"' EXIT
for port in 18080 18443; do
  i=0
  until python3 -c "import socket; socket.create_connection(('127.0.0.1', $port), 1)" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 40 ] && { fail "the local server on $port did not start"; break; }; sleep 0.5
  done
done

# run NAME TIMEOUT COMMAND...: the command's output goes to $work/NAME.txt (and is shown); sets RC. Output naming a write the container refused fails the run.
run() {
  name=$1; secs=$2; shift 2
  echo "=== $name: $*"
  timeout "$secs" "$@" > "$work/$name.txt" 2>&1; RC=$?
  tail -n 15 "$work/$name.txt"
  [ "$RC" = 0 ] || { echo "--- the whole output of $name:"; head -n 120 "$work/$name.txt"; }
  echo "--- $name exit status $RC"
  cp "$work/$name.txt" "$work/$name.checked"
  if grep -Eqi 'read-only file system|EROFS|permission denied|operation not permitted' "$work/$name.checked"; then
    fail "$name: it could not write or use something it needs (see the lines above)"
    grep -Ei 'read-only file system|EROFS|permission denied|operation not permitted' "$work/$name.checked" | head -n 5
  fi
}

# --- raw sockets ---------------------------------------------------------------------------------------------------------------------------
run nmap-syn 120 nmap -sS -Pn -n -p 18080,18081 -oG - 127.0.0.1
grep -q '18080/open/tcp' "$work/nmap-syn.txt" || fail "nmap -sS did not find the open port"
grep -q '18081/closed/tcp' "$work/nmap-syn.txt" || fail "nmap -sS did not see the closed port"
run nmap-os 180 nmap -sS -O -Pn -n -p 18080,18081 127.0.0.1
[ "$RC" = 0 ] || fail "nmap -O exited $RC"
grep -Eq 'OS detection performed|OS details|Aggressive OS guesses|No exact OS matches|Running|Device type|OS CPE' "$work/nmap-os.txt" || fail "nmap -O did not run OS detection"
grep -qi 'requires root privileges' "$work/nmap-os.txt" && fail "nmap -O wanted root privileges"
run nmap-udp 120 nmap -sU -Pn -n -p 53,161 --max-retries 1 127.0.0.1
[ "$RC" = 0 ] || fail "nmap -sU exited $RC"
grep -qi 'requires root privileges' "$work/nmap-udp.txt" && fail "nmap -sU wanted root privileges"
run nmap-flags 120 nmap -sS -Pn -n --reason --max-retries 0 --host-timeout 15s -p 18080 127.0.0.1   # the path_probe/udp flavours (flags.PATH_PROBE_PLAIN)
run nmap-t7 120 nmap -sF --scanflags FINPSHURG -Pn -n --max-retries 0 --host-timeout 15s -p 18080 127.0.0.1
[ "$RC" = 0 ] || fail "nmap's T7 probe exited $RC"
run naabu 120 naabu -host 127.0.0.1 -p 18080 -scan-type s -rate 1000 -retries 2 -c 25 -warm-up-time 2 -json -silent -nc
grep -q '18080' "$work/naabu.txt" || fail "naabu's SYN scan did not find the open port"

# --- tools that write under $HOME or /tmp --------------------------------------------------------------------------------------------------
# the daemon's start-up warm-up: a child process (python -I client/credential_templates.py --scan) lists the image templates that send a credential. It
# cannot write beside the read-only templates, so the list is kept under ~/.cache/cvengine-sentinel, which must be writable.
run credtemplates 300 python3 -c "import logging, sys; logging.basicConfig(level=logging.INFO, stream=sys.stdout); from client import tools; tools._credential_exclusion(None)"
[ "$RC" = 0 ] || fail "the credential-template list could not be made (exit $RC)"
{ ls "$HOME"/.cache/cvengine-sentinel/credential-templates-*.json || ls "$HOME"/nuclei-templates/.cvengine-credential-templates.json; } >/dev/null 2>&1 || fail "the credential-template list was kept nowhere"
echo "--- nuclei's config directory before it runs:"; ls -la "$HOME/.config/nuclei" 2>&1 | head; ls -ld "$HOME/nuclei-templates" "$HOME/nuclei-templates/http/technologies" 2>&1
run nuclei 240 nuclei -u http://127.0.0.1:18080 -tags tech -jsonl -silent -duc -ni -nc -rl 150 -c 40 -timeout 10 -retries 1
if [ "$RC" != 0 ]; then
  fail "nuclei exited $RC"
  echo "--- nuclei again, verbose:"; timeout 120 nuclei -u http://127.0.0.1:18080 -tags tech -duc -ni -nc -v -jsonl 2>&1 | grep -v '^{' | head -n 60
  ls -laR "$HOME/.config/nuclei" "$HOME/.cache/nuclei" 2>&1 | head -n 30
  echo "--- variant: NUCLEI_TEMPLATES_DIR"; NUCLEI_TEMPLATES_DIR="$HOME/nuclei-templates" timeout 120 nuclei -u http://127.0.0.1:18080 -tags tech -duc -ni -nc -silent -jsonl 2>&1 | cut -c1-160 | head -n 5
  echo "--- variant: -ud"; timeout 120 nuclei -ud "$HOME/nuclei-templates" -u http://127.0.0.1:18080 -tags tech -duc -ni -nc -silent -jsonl 2>&1 | cut -c1-160 | head -n 5
else
  echo "--- nuclei's templates config after a run that worked:"; cat "$HOME/.config/nuclei/.templates-config.json" 2>&1 | head -n 20
fi
run wpscan 300 wpscan --url http://127.0.0.1:18080 --no-banner --disable-tls-checks -f json -o "$work/wpscan.json"
run wafw00f 120 wafw00f http://127.0.0.1:18080
[ "$RC" = 0 ] || fail "wafw00f exited $RC"
run testssl 300 testssl.sh --quiet --color 0 --protocols --jsonfile "$work/testssl.json" 127.0.0.1:18443
[ "$RC" -lt 240 ] || fail "testssl.sh exited $RC (240 and above are its own failures)"
echo 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12"' > "$work/src/config.txt"
run kingfisher 120 kingfisher scan "$work/src" --output "$work/kingfisher.json" --no-validate --no-update-check
case "$RC" in 0|200|205) ;; *) fail "kingfisher exited $RC" ;; esac
run sshamble 60 sshamble scan --help
[ "$RC" = 0 ] || fail "sshamble exited $RC"
run bbot 600 python3 /opt/sentinel/scripts/ci_bbot_start.py
[ "$RC" = 0 ] || fail "the bbot start check exited $RC"
run bbot-deep 120 python3 /opt/sentinel/scripts/ci_bbot_deep_start.py  # a real scan of example.com for ten seconds, as the existing CI step runs it
[ "$RC" = 0 ] || fail "the deep bbot start check exited $RC"
run control 30 python3 -m client.control status
[ "$RC" = 0 ] || fail "client.control status exited $RC"

if [ "$FAILED" = 0 ]; then echo "SMOKE OK"; else echo "SMOKE FAILED (see the lines above)" >&2; fi
exit "$FAILED"
