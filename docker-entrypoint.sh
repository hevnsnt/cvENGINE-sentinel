#!/bin/sh
# Start the daemon. The nuclei templates in the image are a pinned release and are NOT refreshed here: a task under the server's template policy runs on
# the server's own verified bundle (client/templates.py), and a task without one uses the pinned set, so an unreviewed download at every start would only
# let a Sentinel run templates nobody approved. CVENGINE_SENTINEL_UPDATE_TEMPLATES=1 restores the refresh for an operator who wants the newest
# community templates for tasks without a policy; it is limited to two minutes so a start is never held up (an internal Sentinel whose egress blocks
# GitHub would otherwise stall, and update.sh's version check with it).
set -e
if [ "${CVENGINE_SENTINEL_UPDATE_TEMPLATES:-}" = 1 ]; then
  timeout 120 nuclei -update-templates >/dev/null 2>&1 || echo "could not refresh nuclei templates; using the ones built into the image"
fi
exec "$@"
