#!/bin/sh
# Builds one Go tool from its release source with the image's Go toolchain, after raising the dependencies listed in GO_DEPENDENCY_FLOOR that the
# tool already uses to at least the version named there (never lower, never a module the tool does not use). Used by the Dockerfile's gotools stage.
#
#   build.sh NAME URL SHA256 PACKAGE CGO [LDFLAGS]
#
# NAME: the output binary (/out/NAME); the licence files of the source go to /out/doc/NAME, with the go.mod and go.sum it was built from, the
# modules raised to a floor (MODIFICATIONS: the change made to the upstream source) and the licence files of every module linked in
# (modules/<module>@<version>/). URL: the release source tarball, checked against SHA256 before it is unpacked. PACKAGE: the main package inside
# the tarball (./cmd/nuclei, or . for the root). CGO: 0 or 1. LDFLAGS: extra -ldflags after "-s -w" (the version a tool stamps at build time).
#
# Reproducible: the source is pinned by checksum, every dependency version is the tool's own go.mod or a floor pinned in the Dockerfile, and every module
# Go downloads is checked against go.sum and the public checksum database (GOSUMDB, Go's default); GOTOOLCHAIN=local refuses any other toolchain.
set -eu
name=$1 url=$2 sha=$3 package=$4 cgo=$5 extra=${6:-}
work=/tmp/gotools/$name
mkdir -p "$work"
curl -fsSLo "$work.tgz" "$url"
echo "$sha  $work.tgz" | sha256sum -c -
tar -xzf "$work.tgz" -C "$work" --strip-components=1
rm "$work.tgz"
cd "$work"
raised=""
for pin in ${GO_DEPENDENCY_FLOOR}; do
    module=${pin%@*} floor=${pin#*@}
    have=$(go list -m -f '{{.Version}}' "$module" 2>/dev/null || true)
    [ -n "$have" ] || continue
    if [ "$(printf '%s\n%s\n' "$have" "$floor" | sort -V | head -n1)" != "$floor" ]; then
        echo "$name: $module $have -> $floor"
        raised="$raised$module $have -> $floor
"
        go get "$module@$floor"
    fi
done
go mod tidy
go mod verify
CGO_ENABLED=$cgo go build -trimpath -buildvcs=false -ldflags="-s -w $extra" -o "/out/$name" "$package"
go version -m "/out/$name" | head -n 1
doc=/out/doc/$name
mkdir -p "$doc"
cp LICENSE* "$doc/"
cp go.mod go.sum "$doc/"
{
    echo "$name, built from $url (sha256 $sha) by docker/gotools/build.sh."
    if [ -n "$raised" ]; then
        echo "Changed from the upstream source: these Go module requirements were raised (go get), then go mod tidy ran:"
        printf '%s' "$raised"
    else
        echo "No module requirement was raised; go mod tidy ran on the upstream go.mod."
    fi
} > "$doc/MODIFICATIONS"
# The licence files of every module linked into the binary (the Go runtime's own licence is the toolchain's, copied by the Dockerfile).
CGO_ENABLED=$cgo go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}} {{.Dir}}{{end}}{{end}}' "$package" | sort -u | sed '/^$/d' > /tmp/gotools-modules
while read -r module dir; do
    [ -n "$dir" ] && [ -d "$dir" ] || continue
    mkdir -p "$doc/modules/$module"
    for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "$dir"/PATENTS*; do
        if [ -f "$f" ]; then cp "$f" "$doc/modules/$module/"; fi
    done
done < /tmp/gotools-modules
cut -d' ' -f1 /tmp/gotools-modules > "$doc/modules/INDEX.txt"
rm -f /tmp/gotools-modules
cd / && rm -rf "$work"
