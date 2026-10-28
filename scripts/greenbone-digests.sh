#!/bin/sh
# Print the digest each pinned Greenbone image's "stable" tag points to today, ready to compare with docker-compose.yml.
# Greenbone publishes no version tags and replaces the images behind "stable", so an old pin can disappear from the registry
# ("artifact ... not found" on `docker compose up`). To refresh: run this, then replace the sha256 of any image that differs.
set -eu
REGISTRY=registry.community.greenbone.net
for image in gpg-data redis-server pg-gvm-migrator pg-gvm gvmd openvas-scanner ospd-openvas; do
  token=$(curl -fsS "https://$REGISTRY/service/token?service=harbor-registry&scope=repository:community/$image:pull" | python3 -c 'import sys, json; print(json.load(sys.stdin)["token"])')
  digest=$(curl -fsSI "https://$REGISTRY/v2/community/$image/manifests/stable" -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
    | tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" {print $2}')
  pinned=$(grep -o "community/$image:stable@sha256:[0-9a-f]*" docker-compose.yml | head -1 | sed 's/.*@//')
  if [ "$pinned" = "$digest" ]; then echo "ok       $image $digest"; else echo "CHANGED  $image pinned=$pinned now=$digest"; fi
done
