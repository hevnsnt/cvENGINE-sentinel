#!/bin/sh
# Refresh nuclei's templates on every start (never pinned, see docs/UPDATES.md), then run the daemon. A failed or slow refresh is not fatal:
# it gets two minutes (an internal Sentinel whose egress blocks GitHub would otherwise stall its start, and update.sh's version check with it),
# and the templates baked into the image at build time are used until the next successful one.
set -e
timeout 120 nuclei -update-templates >/dev/null 2>&1 || echo "could not refresh nuclei templates; using the ones built into the image"
exec "$@"
