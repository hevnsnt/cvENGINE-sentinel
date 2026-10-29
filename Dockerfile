# The Sentinel client: a standalone image with nmap, naabu, nuclei, testssl.sh, WPScan and the client daemon, pinned
# to the exact same tool versions the cvENGINE server repository's web/Dockerfile pins (its scripts/check_tool_versions.py checks both; keep them equal on
# purpose, see docs/UPDATES.md "Pinned tools" in that repository), so a Sentinel's results are never skewed by running a different
# nmap/naabu/nuclei/testssl/wpscan than the instance it reports to would have run locally. The OpenVAS (GVM) stack
# itself is NOT in this image: it runs as the separate Greenbone services in docker-compose.yml, which this daemon
# talks GMP to over a shared unix socket (client/openvas.py), the same way cvENGINE's own server talks to its sidecar.
FROM ubuntu:26.04@sha256:0e73b71479e7bc5f006bca872e25c3cd680dc052a0116f90d63ae363537db0dd

ARG GOVERSION=1.27.3
ARG GO_SHA256_AMD64=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
ARG GO_SHA256_ARM64=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
ARG NMAPVERSION=7.993
ARG NUCLEI_VERSION=3.11.1
ARG NAABU_VERSION=2.6.1
# nmap: amd64 installs the project's own x86_64 release RPM (its libraries are linked in statically), arm64 builds the
# source tarball, because nmap.org publishes no arm64 binary. Both checksums are published beside the files at
# nmap.org/dist/sigs/ (identical to the server repository's web/Dockerfile pins).
ARG NMAP_SHA256=270e55f04915bfcecb5db8feb959d4c5ba86a48c094520a4f1c07571e1c79c59
ARG NMAP_RPM_SHA256_AMD64=997cb830c84a429aaa1d41708a1ebb9b1cc36e75d21801c9d359fe930a8c1f93
ARG WPSCAN_VERSION=4.1.0
# testssl.sh (GPLv2, run as a separate program) audits the TLS configuration of every TLS port, mirroring
# cveFeed/testssl_scan.py's own invocation. Pinned tarball with its checksum, never a branch.
ARG TESTSSL_VERSION=3.2.3
ARG TESTSSL_SHA256=1c4bb10185a67592164eb870c717b8bdd03f290c8d68f9a8c658335ff5ac8b91

ENV DEBIAN_FRONTEND="noninteractive" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOROOT="/usr/local/go" \
    GOPATH="/root/go"
ENV PATH="/opt/venv/bin:${PATH}:${GOROOT}/bin:${GOPATH}/bin"

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
# (GOPATH is /root/go): nothing at runtime runs go, only the two binaries in /root/go/bin.
ENV GO111MODULE=on
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then GO_SHA="${GO_SHA256_ARM64}"; else GO_SHA="${GO_SHA256_AMD64}"; fi \
    && curl -fsSLo /tmp/go.tgz https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz \
    && echo "${GO_SHA}  /tmp/go.tgz" | sha256sum -c - \
    && tar -xzC /usr/local -f /tmp/go.tgz \
    && rm /tmp/go.tgz \
    && printf "\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v${NUCLEI_VERSION}\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@v${NAABU_VERSION}\n" | \
    xargs -L1 go install -ldflags="-s -w" -v \
    && go clean -cache -modcache \
    && rm -rf "${GOROOT}" "${GOPATH}/pkg" /root/.cache/go-build

# Nuclei's templates are refreshed once at build time and again on every container start (see docker-entrypoint.sh),
# same as the server's own image: they are not pinned by design (docs/UPDATES.md in the server repository).
RUN nuclei -update-templates

# WPScan (GPLv3, run as a separate program, never linked): mirrors cveFeed/wpscan_scan.py's own invocation.
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ruby ruby-dev libcurl4-openssl-dev libxml2-dev libxslt1-dev libffi-dev zlib1g-dev && \
    gem install wpscan -v ${WPSCAN_VERSION} --no-document && \
    (wpscan --update --no-banner || echo "WPScan database not fetched at build time; it updates on first use") && \
    rm -rf /var/lib/apt/lists/* /root/.gem/cache

# testssl.sh: needs dig (--nodns none still checks for it), hexdump and ps; the x86_64 tarball bundles an openssl
# that still speaks SSLv2/SSLv3 and export ciphers (arm64 uses the system openssl).
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends bind9-dnsutils bsdextrautils procps && \
    curl -fsSL -o /tmp/testssl.tar.gz "https://testssl.sh/testssl.sh-${TESTSSL_VERSION}.tar.gz" && \
    echo "${TESTSSL_SHA256}  /tmp/testssl.tar.gz" | sha256sum -c - && \
    mkdir -p /opt/testssl && tar -xzf /tmp/testssl.tar.gz -C /opt/testssl --strip-components=1 && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh && \
    rm -f /tmp/testssl.tar.gz && rm -rf /var/lib/apt/lists/* && \
    testssl.sh --version 2>&1 | grep -q "${TESTSSL_VERSION}"

WORKDIR /opt/sentinel

RUN python3 -m venv /opt/venv
COPY requirements.txt /opt/sentinel/requirements.txt
# The bootstrap packages are pinned like everything else (requirements.txt pins the client's own).
RUN pip install --no-cache-dir pip==25.2 setuptools==80.9.0 wheel==0.45.1 && \
    pip install --no-cache-dir -r /opt/sentinel/requirements.txt

COPY client /opt/sentinel/client
COPY docker-entrypoint.sh /opt/sentinel/docker-entrypoint.sh
# The OpenVAS login bootstrap check (README.md, "Testing OpenVAS"): docker compose exec sentinel python3 scripts/ci_openvas_bootstrap.py
COPY scripts/ci_openvas_bootstrap.py /opt/sentinel/scripts/ci_openvas_bootstrap.py
RUN chmod +x /opt/sentinel/docker-entrypoint.sh

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

# Last on purpose: a label change must not invalidate the build layers above it.
LABEL \
    name="CVEngine Sentinel" \
    description="Downloadable scan-stage agent for CVEngine: runs nmap, naabu, nuclei, testssl.sh, WPScan and OpenVAS work on your own network and reports typed results back." \
    org.opencontainers.image.source="https://github.com/hevnsnt/cvENGINE-sentinel" \
    org.opencontainers.image.licenses="GPL-3.0-only"

ENTRYPOINT ["/opt/sentinel/docker-entrypoint.sh"]
CMD ["python3", "-m", "client"]
