#!/bin/sh
# Check every Greenbone image pinned by digest in docker-compose.yml against registry.community.greenbone.net:
#   ok        the pinned digest still exists and "stable" still points to it
#   CHANGED   the pinned digest still exists but "stable" has moved on (drift: refresh the pin when convenient)
#   MISSING   the pinned digest is gone from the registry, so `docker compose up` fails ("artifact ... not found"): refresh it now
# Exits 1 when any pin is MISSING; drift alone exits 0. Greenbone publishes no version tags and replaces the images behind "stable", so an
# old pin can disappear. To refresh: replace the sha256 of each CHANGED or MISSING image with the digest printed after now=.
set -eu
cd "$(dirname "$0")/.."
REGISTRY=registry.community.greenbone.net
ACCEPT="application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

# Every pin, not just the first of each image (openvas-scanner is pinned twice); identical pins are checked once.
pins=$(grep -o "$REGISTRY/community/[a-z0-9-]*:stable@sha256:[0-9a-f]*" docker-compose.yml | sort -u)
[ -n "$pins" ] || { echo "no pinned Greenbone images found in docker-compose.yml" >&2; exit 1; }

missing=0
for pin in $pins; do
  image=${pin#"$REGISTRY"/community/}
  image=${image%%:*}
  pinned=${pin##*@}
  token=$(curl -fsS "https://$REGISTRY/service/token?service=harbor-registry&scope=repository:community/$image:pull" | python3 -c 'import sys, json; print(json.load(sys.stdin)["token"])')
  if ! curl -fsSI -o /dev/null "https://$REGISTRY/v2/community/$image/manifests/$pinned" -H "Authorization: Bearer $token" -H "Accept: $ACCEPT"; then
    echo "MISSING  $image $pinned"
    missing=1
  fi
  now=$(curl -fsSI "https://$REGISTRY/v2/community/$image/manifests/stable" -H "Authorization: Bearer $token" -H "Accept: $ACCEPT" \
    | tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" {print $2}')
  if [ "$pinned" = "$now" ]; then echo "ok       $image $pinned"; else echo "CHANGED  $image pinned=$pinned now=$now"; fi
done
exit "$missing"
