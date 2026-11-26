#!/bin/sh
# Check that every Greenbone image docker-compose.yml names (each image and its tag: `stable` for the programs, `community` for the feed data) exists
# on registry.community.greenbone.net:
#   ok        the tag exists; the digest it points to now is printed for the record
#   MISSING   the registry has no such tag (an image renamed or withdrawn by Greenbone), so `docker compose pull` would fail
# Exits 1 when any tag is MISSING. The images are not pinned by digest: Greenbone publishes no version tags and deletes the old images behind
# `stable`, so a Sentinel follows `stable` (Greenbone's latest) and scripts/update.sh pulls it at every update.
set -eu
cd "$(dirname "$0")/.."
REGISTRY=registry.community.greenbone.net
ACCEPT="application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

# A reference pinned by digest is refused: the tag alone is what a Sentinel runs.
if grep -q "$REGISTRY/community/[a-z0-9-]*:[a-z0-9.-]*@sha256:" docker-compose.yml; then
  echo "a Greenbone image in docker-compose.yml is pinned by digest; Greenbone deletes old digests, so name the tag only" >&2
  exit 1
fi
# Every image reference once (openvas-scanner is named twice).
refs=$(grep -o "$REGISTRY/community/[a-z0-9-]*:[a-z0-9.-]*" docker-compose.yml | sort -u)
[ -n "$refs" ] || { echo "no Greenbone images found in docker-compose.yml" >&2; exit 1; }

missing=0
for ref in $refs; do
  name=${ref#"$REGISTRY"/community/}
  image=${name%%:*}
  tag=${name#*:}
  token=$(curl -fsS "https://$REGISTRY/service/token?service=harbor-registry&scope=repository:community/$image:pull" | python3 -c 'import sys, json; print(json.load(sys.stdin)["token"])')
  if head=$(curl -fsSI "https://$REGISTRY/v2/community/$image/manifests/$tag" -H "Authorization: Bearer $token" -H "Accept: $ACCEPT"); then
    now=$(printf '%s\n' "$head" | tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" {print $2}')
    echo "ok       $image:$tag ${now:-(no digest given)}"
  else
    echo "MISSING  $image:$tag"
    missing=1
  fi
done
exit "$missing"
