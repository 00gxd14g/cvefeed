# Build stage. The vendor directory is used when present, which is what makes
# an image build possible on a machine with no access to a module proxy.
# The toolchain is pinned to a supported release rather than to the module's
# `go` directive. go1.22 left support in 2025 and a binary built with it ships
# every unpatched standard-library flaw of the intervening year — 20 of them at
# the last count, in crypto/x509, crypto/tls, net/http and net/url. That is a
# poor thing to be true of a vulnerability scanner. The module still declares
# go 1.22, so nothing here depends on newer language features.
FROM docker.io/library/golang:1.26.8-alpine AS build

# Only the CA bundle: the module proxy is reached over HTTPS, and nothing in
# the build shells out to git — the dependencies are two published modules.
RUN apk add --no-cache ca-certificates

WORKDIR /src

# Module files first, on their own layer. The download below is then cached
# across source edits, and a one-line change no longer re-fetches every
# dependency — which, with the full tree copied first, it did on every build.
COPY go.mod go.sum ./

# A vendor directory short-circuits the network entirely; `go build` selects
# -mod=vendor on its own when one is present, so nothing else is needed once
# the sources are in. The download is skipped for that build (VENDORED=1, which
# `make image` and `make up` pass when ./vendor exists), because it would need
# exactly the proxy the vendoring is there to avoid. The optional-source COPY
# this replaced ("COPY vendo[r] ./vendor") fails outright on a builder without
# BuildKit.
ARG VENDORED=0
RUN if [ "$VENDORED" != "1" ]; then go mod download; fi

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/cvefeed ./cmd/cvefeed

# Runtime stage.
FROM docker.io/library/alpine:3.24

# nmap carries the service-probe and CPE databases that make `scan -target`
# accurate; masscan does the fast discovery pass ahead of it. Both are optional
# at runtime — the scanner falls back to its own connect-and-read prober when
# they are absent — but a container that cannot do version detection is a poor
# default for a vulnerability scanner. masscan needs CAP_NET_RAW to run at all,
# which this image does not grant; without it the discovery pass reports its
# failure and every requested port is examined directly instead.
RUN apk add --no-cache ca-certificates tzdata nmap nmap-scripts masscan libpcap \
    # masscan dlopens the unversioned soname, which Alpine ships only in
    # libpcap-dev; the link is a few bytes against that package's weight.
    && ln -sf /usr/lib/libpcap.so.1 /usr/lib/libpcap.so \
    && adduser -D -u 10001 -h /var/lib/cvefeed cvefeed \
    && mkdir -p /var/lib/cvefeed/bundle \
    && chown -R cvefeed:cvefeed /var/lib/cvefeed

COPY --from=build /out/cvefeed /usr/local/bin/cvefeed

USER cvefeed
WORKDIR /var/lib/cvefeed

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/readyz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/cvefeed"]
CMD ["serve"]
