# The Sentinel client: a standalone image with nmap, naabu, nuclei, testssl.sh, WPScan, wafw00f, bbot, Kingfisher, sshamble, Playwright's headless Chromium and the client daemon, pinned
# to the exact same tool versions the cvENGINE server repository's web/Dockerfile pins (its scripts/check_tool_versions.py checks both; keep them equal on
# purpose, see docs/UPDATES.md "Pinned tools" in that repository), so a Sentinel's results are never skewed by running a different
# nmap/naabu/nuclei/testssl/wpscan than the instance it reports to would have run locally. The OpenVAS (GVM) stack
# itself is NOT in this image: it runs as the separate Greenbone services in docker-compose.yml, which this daemon
# talks GMP to over a shared unix socket (client/openvas.py), the same way cvENGINE's own server talks to its sidecar.
# bbot and the tzdata it needs, the same pins as the server repository's web/Dockerfile. Declared once, before the first stage, and used by two.
ARG BBOT_VERSION=3.1.0
ARG TZDATA_VERSION=2026.6
# bbot 3.1's own Rust and module dependencies, pinned to the versions bbot 3.1.0 resolves to (its requirements say blastdns>=2.0.4,<2.1 and blasthttp>=0.10.1,<0.11;
# its baddns and badsecrets modules install baddns~=2.5.0 and badsecrets~=1.3.0 at build time), so a rebuild never picks up a newer one the Sentinel has not been through.
ARG BLASTDNS_VERSION=2.0.4
ARG BLASTHTTP_VERSION=0.10.1
ARG BADDNS_VERSION=2.5.0
ARG BADSECRETS_VERSION=1.3.0
# bbot's own virtual environment is built in a stage of its own: one of its dependencies (yara-python) compiles from source on this Python, and
# the compiler and the headers it needs stay in this stage. The final image copies the finished venv to the same path, on the same base image.
FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96 AS bbot-builder
ARG BBOT_VERSION
ARG TZDATA_VERSION
ARG BLASTDNS_VERSION
ARG BLASTHTTP_VERSION
ARG BADDNS_VERSION
ARG BADSECRETS_VERSION
ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends build-essential ca-certificates libssl-dev python3 python3-dev python3-venv && \
    rm -rf /var/lib/apt/lists/*
# The build tools are the same pins as the client's venv below; yara-python and the other source packages build with them.
RUN python3 -m venv /opt/bbot-venv && \
    /opt/bbot-venv/bin/pip install --no-cache-dir pip==26.3 setuptools==84.2.1 wheel==0.48.0 && \
    /opt/bbot-venv/bin/pip install --no-cache-dir bbot==${BBOT_VERSION} tzdata==${TZDATA_VERSION} blastdns==${BLASTDNS_VERSION} blasthttp==${BLASTHTTP_VERSION} baddns==${BADDNS_VERSION} badsecrets==${BADSECRETS_VERSION} && \
    /opt/bbot-venv/bin/bbot --version

# The Python packages that ship no wheel for this image's Python on every architecture (arc4, a C extension, everywhere; aardwolf, a Rust
# extension, on arm64) are built here, in a stage that is thrown away: the same toolchain the server repository's web/Dockerfile builds them with
# (build-essential, python3-dev, rustc, cargo), on the same base image, so the wheels match the image's Python. Only the wheels are copied into the
# image below, which installs them with --no-index: no Python headers or Rust toolchain ship in it, and nothing is compiled or fetched there.
FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96 AS wheels
ENV DEBIAN_FRONTEND="noninteractive" PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends build-essential ca-certificates cargo python3 python3-dev python3-venv rustc && \
    rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/wheelvenv
COPY requirements.txt /tmp/requirements.txt
RUN /opt/wheelvenv/bin/pip install --no-cache-dir pip==26.3 setuptools==84.2.1 wheel==0.48.0 && \
    /opt/wheelvenv/bin/pip wheel --no-cache-dir -r /tmp/requirements.txt -w /wheels

FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96

ARG GOVERSION=1.27.4
ARG GO_SHA256_AMD64=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
ARG GO_SHA256_ARM64=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
ARG NMAPVERSION=7.993
ARG NUCLEI_VERSION=3.11.1
ARG NAABU_VERSION=2.7.0
# nmap: amd64 installs the project's own x86_64 release RPM (its libraries are linked in statically), arm64 builds the
# source tarball, because nmap.org publishes no arm64 binary. Both checksums are published beside the files at
# nmap.org/dist/sigs/ (identical to the server repository's web/Dockerfile pins).
ARG NMAP_SHA256=270e55f04915bfcecb5db8feb959d4c5ba86a48c094520a4f1c07571e1c79c59
ARG NMAP_RPM_SHA256_AMD64=997cb830c84a429aaa1d41708a1ebb9b1cc36e75d21801c9d359fe930a8c1f93
ARG WPSCAN_VERSION=4.2.0
# wafw00f (BSD-3-Clause, run as a separate program) names the WAF in front of a site, mirroring cveFeed/waf_scan.py's invocation. The same pins as the server
# repository's web/requirements.txt (wafw00f, and PySocks, which wafw00f's requests[socks] pulls in).
ARG WAFW00F_VERSION=2.4.2
ARG PYSOCKS_VERSION=1.7.1
# testssl.sh (GPLv2, run as a separate program) audits the TLS configuration of every TLS port, mirroring
# cveFeed/testssl_scan.py's own invocation. Pinned tarball with its checksum, never a branch.
ARG TESTSSL_VERSION=3.2.5
ARG TESTSSL_SHA256=23bb53d50ae093b89631e9fff547c087f632bf35f7a3d7dc78dd4ffff56cd779
# The nuclei templates baked into the image: a pinned community release with its checksum, used only for a task that names no approved bundle
# (an older server). Tasks under the server's template policy run on the server's own verified bundle instead (client/templates.py).
# Kingfisher (Apache-2.0, MongoDB; run as a separate program) finds secrets in the pages and scripts of the secrets_scan kind. The release tarball per
# architecture, pinned by sha256 (its build attestation is verified in CI, .github/workflows/tests.yml); never the PyPI kingfisher-bin. The library's
# cvengine_scanner/secrets.py KINGFISHER_VERSION is the same pin (a test holds them together), and so is the server's validation allow-list.
ARG KINGFISHER_VERSION=2.18.1
ARG KINGFISHER_SHA256_AMD64=8f29b5ba1818f13bccd0b079c798659cfd2eccf21998003c8aaf75f8a3794529
ARG KINGFISHER_SHA256_ARM64=37a6341c9899693d6cf2ef18d54bf65395a8ad9b6c6152aea90f8626b4be9d8e
# sshamble (BSD-2-Clause, runZero; run as a separate program) reads an SSH service's own handshake for the ssh_probe kind: the banner, host keys,
# algorithms, offered authentication methods and the badkeys blocklist check. Release tarball per architecture, pinned by sha256. The library's
# cvengine_scanner/probes/ssh_probe.py SSHAMBLE_VERSION is the same pin (a test holds them together). Only the host key check is ever run.
ARG SSHAMBLE_VERSION=0.5.1
ARG SSHAMBLE_SHA256_AMD64=38ba26a606ca51c3a974b91dd599717c3e21ac6720dc9bc4f4598d014793410e
ARG SSHAMBLE_SHA256_ARM64=2335aceee86e860524fdd42decf02b6db12b18ce2f3e4a5be923902bb14d809a
ARG NUCLEI_TEMPLATES_VERSION=v10.5.2
ARG NUCLEI_TEMPLATES_SHA256=016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574

ENV DEBIAN_FRONTEND="noninteractive" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# No root-only entries on PATH: the Go toolchain and its GOPATH (/root/go, mode 0700) exist only inside the one build step that uses them, below. A
# PATH entry the run-time user cannot read turns "command not found" (ENOENT) into "Permission denied" (EACCES) for every program looked up after it.
ENV PATH="/opt/venv/bin:${PATH}"

RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" != "arm64" ] && [ "${ARCH}" != "amd64" ]; then \
      echo "the Sentinel image supports amd64 and arm64, found: ${ARCH}" \
      && exit 1; \
    fi

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    bzip2 \
    ca-certificates \
    curl \
    python3 \
    python3-venv \
    tzdata \
    wget && \
    rm -rf /var/lib/apt/lists/*

# Everything at run time is an unprivileged user; raw sockets come from file capabilities on nmap and naabu only (see the end of the image), and
# the state volume is created owned by this user (docker-compose.yml's sentinel-init repairs the ownership of a volume made by an older image).
RUN useradd --system --uid 10001 --create-home --home-dir /home/sentinel --shell /usr/sbin/nologin sentinel \
    && mkdir -p /var/lib/cvengine-sentinel /var/lib/cvengine-sentinel/badkeys \
    && chown sentinel:sentinel /var/lib/cvengine-sentinel /var/lib/cvengine-sentinel/badkeys

# nmap, checksum verified, same pin and install method as the server repository's web/Dockerfile (see its own comment for why the two paths).
RUN set -e; cd /tmp \
    && if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        curl -fsSLO https://nmap.org/dist/nmap-${NMAPVERSION}-1.x86_64.rpm \
        && echo "${NMAP_RPM_SHA256_AMD64}  nmap-${NMAPVERSION}-1.x86_64.rpm" | sha256sum -c - \
        && apt-get update -y && apt-get install -y --no-install-recommends libarchive-tools \
        && mkdir nmap-rpm && bsdtar -xf nmap-${NMAPVERSION}-1.x86_64.rpm -C nmap-rpm \
        && install -D -m 0755 nmap-rpm/usr/bin/nmap /usr/local/bin/nmap \
        && mkdir -p /usr/local/share && cp -r nmap-rpm/usr/share/nmap /usr/local/share/nmap \
        && apt-get purge -y libarchive-tools && rm -rf /var/lib/apt/lists/* nmap-rpm nmap-${NMAPVERSION}-1.x86_64.rpm; \
    else \
        curl -fsSLO https://nmap.org/dist/nmap-${NMAPVERSION}.tar.bz2 \
        && echo "${NMAP_SHA256}  nmap-${NMAPVERSION}.tar.bz2" | sha256sum -c - \
        && tar xjf nmap-${NMAPVERSION}.tar.bz2 \
        && cd nmap-${NMAPVERSION} \
        && ./configure --prefix=/usr/local --without-zenmap --without-ndiff --without-nmap-update \
        && make -j"$(nproc)" \
        && make install \
        && cd / && rm -rf /tmp/nmap-${NMAPVERSION}*; \
    fi \
    && nmap --version | head -2
ENV NMAPDIR=/usr/local/share/nmap
RUN test -s "$NMAPDIR/nmap-service-probes"

# nuclei and naabu, built with a checksum-verified Go toolchain that is removed again in the same layer, with Go's module and build caches
# (GOPATH is /root/go): nothing at runtime runs go, only the two binaries, installed into /usr/local/bin where the unprivileged user can run them.
ENV GO111MODULE=on
RUN export GOROOT=/usr/local/go GOPATH=/root/go PATH="/usr/local/go/bin:${PATH}" \
    && ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then GO_SHA="${GO_SHA256_ARM64}"; else GO_SHA="${GO_SHA256_AMD64}"; fi \
    && curl -fsSLo /tmp/go.tgz https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz \
    && echo "${GO_SHA}  /tmp/go.tgz" | sha256sum -c - \
    && tar -xzC /usr/local -f /tmp/go.tgz \
    && rm /tmp/go.tgz \
    && printf "\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v${NUCLEI_VERSION}\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@v${NAABU_VERSION}\n" | \
    GOBIN=/usr/local/bin xargs -L1 go install -ldflags="-s -w" -v \
    && go clean -cache -modcache \
    && rm -rf "${GOROOT}" "${GOPATH}/pkg" /root/.cache/go-build

# The fallback templates: a pinned release, checksum verified, in the run-time user's home where nuclei looks by default. They are not refreshed at
# start (docker-entrypoint.sh); a newer set arrives with a rebuilt image, or, for a task under the server's policy, as the server's own bundle.
RUN curl -fsSLo /tmp/nuclei-templates.tgz "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" \
    && echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-templates.tgz" | sha256sum -c - \
    && mkdir -p /home/sentinel/nuclei-templates \
    && tar -xzf /tmp/nuclei-templates.tgz -C /home/sentinel/nuclei-templates --strip-components=1 \
    && rm /tmp/nuclei-templates.tgz \
    && chown -R sentinel:sentinel /home/sentinel
# The release of those baked templates, reported with every nuclei run that uses them (client.tools.IMAGE_TEMPLATES_VERSION).
ENV CVENGINE_NUCLEI_TEMPLATES_VERSION=${NUCLEI_TEMPLATES_VERSION}

# WPScan (GPLv3, run as a separate program, never linked): mirrors cveFeed/wpscan_scan.py's own invocation. Reproducible: WPScan and every gem it
# needs are installed at the exact versions of docker/wpscan/Gemfile.lock, each downloaded .gem checked against the lock's sha256 before anything is
# installed (nothing is resolved at build time, so two builds of one commit get the same gems). Its vulnerability database is NOT fetched here: it
# changes daily, so a build that fetched it could never be repeated. WPScan downloads it itself on the first run that needs it (a missing database
# is always fetched; `--no-update` is never passed) and keeps it in the run-time user's home.
COPY docker/wpscan/Gemfile docker/wpscan/Gemfile.lock /tmp/wpscan/
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ruby ruby-dev libcurl4-openssl-dev libxml2-dev libxslt1-dev libffi-dev zlib1g-dev pkg-config && \
    mkdir -p /tmp/wpscan/gems && cd /tmp/wpscan/gems && \
    awk '/^CHECKSUMS/ {on = 1; next} on && NF == 0 {on = 0} on && $1 != "bundler" {gsub(/[()]/, "", $2); sub(/^sha256=/, "", $3); print $1, $2, $3}' \
        /tmp/wpscan/Gemfile.lock > pins && \
    grep -qx "wpscan ${WPSCAN_VERSION} [0-9a-f]\{64\}" pins && \
    while read -r gem version sum; do \
        gem fetch "$gem" --version "$version" --platform ruby >/dev/null && \
        echo "${sum}  ${gem}-${version}.gem" | sha256sum -c - || exit 1; \
    done < pins && \
    test "$(ls ./*.gem | wc -l)" = "$(wc -l < pins)" && \
    NOKOGIRI_USE_SYSTEM_LIBRARIES=1 gem install --local --ignore-dependencies --no-document ./*.gem && \
    wpscan --version | grep -F "${WPSCAN_VERSION}" && \
    cd / && rm -rf /tmp/wpscan /var/lib/apt/lists/* /root/.gem /root/.local/share/gem

# testssl.sh: needs dig (--nodns none still checks for it), hexdump and ps; the x86_64 tarball bundles an openssl
# that still speaks SSLv2/SSLv3 and export ciphers (arm64 uses the system openssl).
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends bind9-dnsutils bsdextrautils procps && \
    curl -fsSL -o /tmp/testssl.tar.gz "https://github.com/testssl/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz" && \
    echo "${TESTSSL_SHA256}  /tmp/testssl.tar.gz" | sha256sum -c - && \
    mkdir -p /opt/testssl && tar -xzf /tmp/testssl.tar.gz -C /opt/testssl --strip-components=1 && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh && \
    rm -f /tmp/testssl.tar.gz && rm -rf /var/lib/apt/lists/* && \
    testssl.sh --version 2>&1 | grep -q "${TESTSSL_VERSION}"

# Kingfisher: the checksum-verified release tarball; its NOTICE files (Apache-2.0, Vectorscan) are kept with the binary. The client always passes
# --no-update-check and refuses self-update and revoke (cvengine_scanner/secrets.py check_argv).
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then KF_ARCH=arm64; KF_SHA="${KINGFISHER_SHA256_ARM64}"; else KF_ARCH=x64; KF_SHA="${KINGFISHER_SHA256_AMD64}"; fi \
    && curl -fsSLo /tmp/kingfisher.tgz "https://github.com/mongodb/kingfisher/releases/download/v${KINGFISHER_VERSION}/kingfisher-linux-${KF_ARCH}.tgz" \
    && echo "${KF_SHA}  /tmp/kingfisher.tgz" | sha256sum -c - \
    && mkdir -p /tmp/kingfisher && tar -xzf /tmp/kingfisher.tgz -C /tmp/kingfisher \
    && install -m 0755 /tmp/kingfisher/kingfisher /usr/local/bin/kingfisher \
    && mkdir -p /usr/share/doc/kingfisher && cp -r /tmp/kingfisher/notices/. /usr/share/doc/kingfisher/ \
    && rm -rf /tmp/kingfisher /tmp/kingfisher.tgz \
    && kingfisher --version | grep -q "${KINGFISHER_VERSION}"

# sshamble: the checksum-verified release tarball; its licence is kept with the binary. The client runs only "sshamble scan" with the one fixed
# --checks badkeys-blocklist (cvengine_scanner/probes/ssh_probe.py check_argv refuses any other command line). The binary has no version flag, so
# the build check is that the scan command runs and knows the check. The badkeys blocklist data is not baked in (a rolling download): the daemon
# refreshes it itself with "sshamble badkeys-update" (client/badkeys.py) into /var/lib/cvengine-sentinel/badkeys, a directory the unprivileged user
# owns (made above; docker-compose.yml mounts a named volume there so the data survives restarts). The client reports "not checked" while it is absent
# or when CVENGINE_BADKEYS_REFRESH=0 (air-gapped Sentinels).
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then SSH_SHA="${SSHAMBLE_SHA256_ARM64}"; else SSH_SHA="${SSHAMBLE_SHA256_AMD64}"; fi \
    && curl -fsSLo /tmp/sshamble.tgz "https://github.com/runZeroInc/sshamble/releases/download/v${SSHAMBLE_VERSION}/sshamble-v${SSHAMBLE_VERSION}-linux-${ARCH}.tar.gz" \
    && echo "${SSH_SHA}  /tmp/sshamble.tgz" | sha256sum -c - \
    && mkdir -p /tmp/sshamble-src && tar -xzf /tmp/sshamble.tgz -C /tmp/sshamble-src \
    && install -m 0755 /tmp/sshamble-src/sshamble/sshamble /usr/local/bin/sshamble \
    && mkdir -p /usr/share/doc/sshamble && cp /tmp/sshamble-src/sshamble/LICENSE.md /usr/share/doc/sshamble/LICENSE.md \
    && rm -rf /tmp/sshamble-src /tmp/sshamble.tgz \
    && sshamble scan --help 2>&1 | grep -q -- '--checks'

WORKDIR /opt/sentinel

RUN python3 -m venv /opt/venv
COPY requirements.txt /opt/sentinel/requirements.txt
# The bootstrap packages are pinned like everything else (requirements.txt pins the client's own). setuptools-scm and packaging build the scanner
# library below without build isolation, so the build tools are these pins and nothing fetched at build time.
# The client's own packages come from the wheels built in the first stage, and only from there (--no-index).
COPY --from=wheels /wheels /tmp/wheels
RUN pip install --no-cache-dir pip==26.3 setuptools==84.2.1 wheel==0.48.0 setuptools-scm==10.3.4 packaging==26.3 && \
    pip install --no-cache-dir --no-index --find-links /tmp/wheels -r /opt/sentinel/requirements.txt && \
    rm -rf /tmp/wheels

# wafw00f, pinned like every other tool, into the same venv: a plain pip package, no compiler and no network at run time.
RUN pip install --no-cache-dir wafw00f==${WAFW00F_VERSION} PySocks==${PYSOCKS_VERSION} && wafw00f --version | grep "v${WAFW00F_VERSION}" >/dev/null

# Web screenshots (kind web_screenshot, client/shot.py): Playwright's own headless Chromium, installed with the operating system libraries it needs on this
# release (Playwright 1.65 knows Ubuntu 26.04 on amd64 and arm64). The browser is fixed by the Playwright pin in requirements.txt: PLAYWRIGHT_CHROMIUM_VERSION
# is the build that release drives, and the build fails if it launches anything else, so a Playwright bump that moves the browser is read before it ships.
# Only the headless shell is installed (what a screenshot needs, about 100 MB smaller than the full browser), and without Playwright's ffmpeg (it records
# video; a screenshot never does). Playwright fetches its own pinned revision from its CDN: there is no checksum of the download to pin here, and the version
# check below is what verifies it. It is launched as root and as the unprivileged account the daemon runs as (sentinel), against about:blank, so a missing
# library or an unreadable install stops the build instead of the first task. Chromium's sandbox cannot be checked here: build steps run under the builder's
# default seccomp profile, which refuses the user namespaces the sandbox needs (so this check launches without it). The running container has Playwright's
# seccomp profile (docker-compose.yml, vendored in config/seccomp) and proves the sandbox engages at every start (client/daemon.py) and before every task
# (client/shot_child.py); a browser that cannot prove it takes no picture. A Playwright bump that moves the browser means rebuilding the image.
ARG PLAYWRIGHT_CHROMIUM_VERSION=158.0.8127.18
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
RUN set -e; playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* /opt/pw-browsers/ffmpeg-* \
    && chmod -R a+rX /opt/pw-browsers \
    && CHECK="import sys; from playwright.sync_api import sync_playwright as sp; p = sp().start(); b = p.chromium.launch(args=['--disable-dev-shm-usage']); pg = b.new_page(); pg.goto('about:blank'); v = b.version; b.close(); p.stop(); print('chromium', v); sys.exit(0 if v == '${PLAYWRIGHT_CHROMIUM_VERSION}' else 1)" \
    && python3 -c "$CHECK" \
    && runuser -u sentinel -- env HOME=/tmp python3 -c "$CHECK"

# bbot (GPLv3, run as a separate program, never imported) for a bbot_discovery task (client/bbot.py), in its own venv so its pins cannot clash with the
# client's. The same pins as the server repository's web/Dockerfile (BBOT_VERSION, TZDATA_VERSION: without zone data bbot cannot find "UTC").
ARG BBOT_VERSION
# The venv comes finished from the bbot-builder stage above (no compiler or headers in this image for it).
COPY --from=bbot-builder /opt/bbot-venv /opt/bbot-venv
RUN ln -s /opt/bbot-venv/bin/bbot /usr/local/bin/bbot && bbot --version | grep -F "${BBOT_VERSION}"
# Fail the build when this bbot no longer reads API keys the way client/bbot.py hands them over (a preset file listed after the named presets) or
# no longer loads gowitness. It runs no scan, but bbot installs the dependencies of the modules it loads before the dry run stops, so this is also
# what bakes gowitness and its browser into the image instead of fetching them in a running Sentinel. It runs as root (bbot installs system
# packages) with the run-time user's home, so bbot's own directory (~/.bbot) is the one the Sentinel uses, and is handed to that user.
RUN printf '{"config": {"modules": {"shodan_dns": {"api_key": "build-check"}}}}\n' > /tmp/keys.yml && \
    HOME=/home/sentinel bbot -t example.com -p subdomain-enum web web-screenshots /tmp/keys.yml -rf safe --force --dry-run -v 2>&1 | \
        tee /tmp/bbot-check.txt | grep -q 'Loading [0-9]* scan modules:.*shodan_dns' && \
    grep -q 'gowitness' /tmp/bbot-check.txt && \
    HOME=/home/sentinel bbot -t example.com -p subdomain-enum /tmp/keys.yml --current-preset 2>&1 | grep -q 'api_key: build-check' && \
    ! grep -q 'Error parsing' /tmp/bbot-check.txt && \
    rm -f /tmp/keys.yml /tmp/bbot-check.txt && rm -rf /var/lib/apt/lists/* /root/.cache && \
    chown -R sentinel:sentinel /home/sentinel
# Every module's dependencies, not only the ones the check above loads: a task may ask for any of the presets client/bbot.py accepts, with or without
# the flag filters, and kitchen-sink is the union of them. bbot installs them as root here (it needs apt, ansible and a compiler for some), into the
# run-time user's ~/.bbot (tools, lib, cache), and the tree is handed to that user. A running Sentinel installs nothing: bbot keys its record of
# "this module's dependencies are installed" (setup_status.json) by a hash that includes the container's hostname, so a record written at build never
# matches in a container (each has its own hostname), and every start would try to install again, which needs root this image does not have (no sudo,
# no root login: "PermissionError: Permission denied: 'sudo'", found first in dnscommonsrv, whose massdns dependency is installed here). So
# client/bbot.py starts bbot with --no-deps, and this image has to carry what the modules need: the check below runs bbot the way the client does.
RUN HOME=/home/sentinel bbot -t example.com -p kitchen-sink --force --dry-run -y --no-color > /tmp/bbot-deps.txt 2>&1; \
    status=$?; tail -n 20 /tmp/bbot-deps.txt; [ "$status" = 0 ] && rm -f /tmp/bbot-deps.txt && rm -rf /var/lib/apt/lists/* /root/.cache && \
    chown -R sentinel:sentinel /home/sentinel
# bbot installs git as one of its core dependencies during the checks above, and the image must not carry git. bbot records in its cache
# (~/.bbot/cache) that its core dependencies were installed and does not look again, so git goes once that is written: then a start as the run-time
# user, as the client makes it (--no-deps), must neither try to install anything nor fail. The client's own command is checked the same way
# after the client is copied in, below.
RUN apt-get purge -y git git-man && rm -rf /var/lib/apt/lists/* && \
    ! command -v git && \
    runuser -u sentinel -- env HOME=/home/sentinel bbot -t example.com -p subdomain-enum -rf safe --dry-run -y --no-deps > /tmp/bbot-user.txt 2>&1; \
    status=$?; cat /tmp/bbot-user.txt | tail -n 20; \
    [ "$status" = 0 ] && ! grep -qi 'Installing core BBOT dependencies' /tmp/bbot-user.txt && rm -f /tmp/bbot-user.txt

# The scanner library (pyproject.toml, cvengine_scanner/: flags, parsers, scope floor, result contract), installed from a build directory that is
# removed again so nothing beside the client can shadow it. It has no dependencies. The build context carries no git tag, so its version is the
# fallback in pyproject.toml; the Sentinel's own version is still the commit stamped below.
COPY pyproject.toml /tmp/cvengine-scanner/pyproject.toml
COPY cvengine_scanner /tmp/cvengine-scanner/cvengine_scanner
RUN pip install --no-cache-dir --no-build-isolation /tmp/cvengine-scanner && rm -rf /tmp/cvengine-scanner

COPY client /opt/sentinel/client
COPY docker-entrypoint.sh /opt/sentinel/docker-entrypoint.sh
# The OpenVAS login bootstrap check (README.md, "Testing OpenVAS"): docker compose exec sentinel python3 scripts/ci_openvas_bootstrap.py
COPY scripts/ci_openvas_bootstrap.py /opt/sentinel/scripts/ci_openvas_bootstrap.py
# The bbot start check (client/bbot.py's own command, --dry-run), as the run-time user: run here at build and again by CI under another hostname.
COPY scripts/ci_bbot_start.py /opt/sentinel/scripts/ci_bbot_start.py
COPY scripts/ci_bbot_deep_start.py /opt/sentinel/scripts/ci_bbot_deep_start.py
RUN chmod +x /opt/sentinel/docker-entrypoint.sh && \
    runuser -u sentinel -- env HOME=/home/sentinel python3 /opt/sentinel/scripts/ci_bbot_start.py

# The commit this image is built from, so the Sentinels page always knows the build; scripts/update.sh checks it after a swap. Only git's HEAD, packed-refs and refs are copied, and when the build context has no .git (a zip download) requirements.txt is the
# only source that matches and VERSION is left empty, which the client reports as unknown. The refs directory's contents land directly in
# /tmp/gitmeta, so refs/heads/main is /tmp/gitmeta/heads/main.
COPY requirements.txt .gi[t]/HEAD .gi[t]/packed-refs .gi[t]/refs /tmp/gitmeta/
RUN h="$(cat /tmp/gitmeta/HEAD 2>/dev/null || true)"; v=""; \
    case "$h" in \
      "ref: "*) r="${h#ref: }"; v="$(cat "/tmp/gitmeta/${r#refs/}" 2>/dev/null || true)"; \
                [ -n "$v" ] || v="$(grep " ${r}\$" /tmp/gitmeta/packed-refs 2>/dev/null | cut -c1-40 || true)" ;; \
      *) v="$h" ;; \
    esac; \
    printf '%s' "$v" | tr -cd '0-9a-f' | cut -c1-12 > /opt/sentinel/VERSION; rm -rf /tmp/gitmeta

# Raw sockets for an unprivileged user: file capabilities on exactly the two tools that send raw packets (nmap's SYN scan, OS detection and ARP
# discovery, naabu's SYN scan). They only take effect because the container is given NET_RAW (docker-compose.yml drops every other capability, NET_ADMIN
# included: a file capability the container's bounding set lacks makes the program fail to start, so the file asks for NET_RAW alone); no other
# process in the image holds any capability. NMAP_PRIVILEGED tells nmap to use them although it does not run as root.
RUN apt-get update -y && apt-get install -y --no-install-recommends libcap2-bin && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw+eip /usr/local/bin/nmap \
    && setcap cap_net_raw+eip /usr/local/bin/naabu \
    && getcap /usr/local/bin/nmap /usr/local/bin/naabu
ENV NMAP_PRIVILEGED=1 \
    HOME=/home/sentinel

# Last on purpose: a label change must not invalidate the build layers above it.
LABEL \
    name="CVEngine Sentinel" \
    description="Downloadable scan-stage agent for CVEngine: runs nmap, naabu, nuclei, testssl.sh, WPScan, wafw00f, Kingfisher, sshamble and OpenVAS work on your own network and reports typed results back." \
    org.opencontainers.image.source="https://github.com/hevnsnt/cvENGINE-sentinel" \
    org.opencontainers.image.licenses="GPL-3.0-only"

# Healthy while the daemon is running and (for the built-in scanner) its heartbeats reach the server: client/control.py health. The compose files
# repeat it with their own timings; this one is for a container started without them.
HEALTHCHECK --interval=60s --timeout=10s --start-period=10m --retries=3 CMD ["python3", "-m", "client.control", "health"]

USER sentinel
ENTRYPOINT ["/opt/sentinel/docker-entrypoint.sh"]
CMD ["python3", "-m", "client"]
