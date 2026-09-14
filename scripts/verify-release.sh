#!/usr/bin/env bash
set -Eeuo pipefail

# The release gate. It is deliberately a script and not a hosted CI job: hosted
# minutes are a billing relationship, and whether this code is fit to publish
# must not depend on one. Everything here runs on a developer machine.
#
#   make verify                                  the full gate
#   CVEFEED_VERIFY_PG_DSN=... make verify        use a PostgreSQL you already run
#   CVEFEED_VERIFY_SKIP_IMAGE=1 make verify      no container image build
#   CVEFEED_VERIFY_SKIP_ANALYZERS=1 make verify  no staticcheck/govulncheck
#
# Docker is needed for two things only — a disposable database and the image
# build — so supplying your own DSN and skipping the image removes the
# dependency entirely.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PG_CONTAINER="${CVEFEED_VERIFY_PG_CONTAINER:-cvefeed-verify-postgres}"
PG_PORT="${CVEFEED_VERIFY_PG_PORT:-55432}"
# An externally supplied database is used as it is: it is not created, not
# migrated and not removed. The integration tests build and drop their own
# schema objects, so it must be a database you are willing to have written to.
EXTERNAL_DSN="${CVEFEED_VERIFY_PG_DSN:-}"
PG_DSN="${EXTERNAL_DSN:-postgres://cvefeed:test@127.0.0.1:${PG_PORT}/cvefeed?sslmode=disable}"
KEEP_POSTGRES="${CVEFEED_VERIFY_KEEP_POSTGRES:-0}"
SKIP_ANALYZERS="${CVEFEED_VERIFY_SKIP_ANALYZERS:-0}"
SKIP_IMAGE="${CVEFEED_VERIFY_SKIP_IMAGE:-0}"

STARTED_POSTGRES=0

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'verify-release: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

cleanup() {
  if [[ "$STARTED_POSTGRES" == "1" && "$KEEP_POSTGRES" != "1" ]]; then
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

need go

if [[ -n "$EXTERNAL_DSN" ]]; then
  log "using the PostgreSQL named by CVEFEED_VERIFY_PG_DSN"
else
  need docker
  docker info >/dev/null 2>&1 || die "Docker daemon is not reachable (or set CVEFEED_VERIFY_PG_DSN to a PostgreSQL you already run)"

  log "cleaning a stale verification database, if any"
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true

  log "starting PostgreSQL 16 on 127.0.0.1:${PG_PORT}"
  docker run -d --rm \
    --name "$PG_CONTAINER" \
    -e POSTGRES_USER=cvefeed \
    -e POSTGRES_PASSWORD=test \
    -e POSTGRES_DB=cvefeed \
    -p "127.0.0.1:${PG_PORT}:5432" \
    docker.io/library/postgres:16-alpine >/dev/null
  STARTED_POSTGRES=1

  ready=0
  for _ in $(seq 1 60); do
    if docker exec "$PG_CONTAINER" pg_isready -U cvefeed -d cvefeed >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  [[ "$ready" == "1" ]] || die "PostgreSQL did not become ready within 60 seconds"
fi

if [[ "$SKIP_IMAGE" != "1" ]]; then
  need docker
  docker info >/dev/null 2>&1 || die "Docker daemon is not reachable; set CVEFEED_VERIFY_SKIP_IMAGE=1 to skip the image build"
fi

log "checking formatting"
unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
  printf '%s\n' "$unformatted" >&2
  die "gofmt changes are required"
fi

log "running go vet"
go vet ./...

# One invocation covers every tier the gate can reach: the hermetic unit tests,
# the database-backed integration tests (enabled by the variable below), and the
# seed corpus of each Fuzz target, which `go test` runs without -fuzz.
log "running race-enabled unit and PostgreSQL integration tests"
CVEFEED_TEST_DATABASE_URL="$PG_DSN" go test -race -count=1 ./...

log "building release binary"
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/cvefeed ./cmd/cvefeed

log "checking cross-platform compilation"
mkdir -p .verify-build
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o .verify-build/cvefeed-linux-amd64 ./cmd/cvefeed
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o .verify-build/cvefeed-windows-amd64.exe ./cmd/cvefeed
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o .verify-build/cvefeed-darwin-amd64 ./cmd/cvefeed
rm -rf .verify-build

if [[ "$SKIP_ANALYZERS" != "1" ]]; then
  # Both analysers are pinned. @latest made every run depend on whatever was
  # published that morning. Bump them deliberately, with the toolchain.
  log "running pinned staticcheck"
  go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

  # The tool is pinned; the vulnerability database it consults is not, which is
  # the point. Not reaching that database is a different outcome from a clean
  # run, and saying so is the difference between "no known vulnerable
  # dependency" and "nobody asked".
  log "running pinned govulncheck against the current vulnerability database"
  vulnlog="$(mktemp)"
  if go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./... 2>&1 | tee "$vulnlog"; then
    :
  elif grep -qiE 'fetching vulnerabilities|vuln\.go\.dev|no such host|connection refused|forbidden|timeout' "$vulnlog"; then
    rm -f "$vulnlog"
    die "govulncheck could not reach the vulnerability database; this run proves nothing about dependency vulnerabilities. Restore network access, or re-run with CVEFEED_VERIFY_SKIP_ANALYZERS=1 and record that the check was not performed."
  else
    rm -f "$vulnlog"
    die "govulncheck reported findings"
  fi
  rm -f "$vulnlog"
else
  log "skipping staticcheck and govulncheck (CVEFEED_VERIFY_SKIP_ANALYZERS=1)"
fi

if [[ "$SKIP_IMAGE" != "1" ]]; then
  log "building the runtime image"
  docker build -f deploy/Dockerfile \
    --build-arg VERSION=local-verify \
    --build-arg VENDORED="$(if [[ -f vendor/modules.txt ]]; then printf 1; else printf 0; fi)" \
    -t cvefeed:local-verify .
else
  log "skipping Docker image build (CVEFEED_VERIFY_SKIP_IMAGE=1)"
fi

log "release verification passed"
printf 'PostgreSQL integration: PASS%s\n' "$(if [[ -n "$EXTERNAL_DSN" ]]; then printf ' (supplied database)'; fi)"
printf 'go test -race:          PASS\n'
printf 'go vet/gofmt:           PASS\n'
printf 'cross-platform build:   PASS\n'
if [[ "$SKIP_ANALYZERS" != "1" ]]; then
  printf 'staticcheck/govulncheck: PASS\n'
else
  printf 'staticcheck/govulncheck: NOT RUN\n'
fi
if [[ "$SKIP_IMAGE" != "1" ]]; then
  printf 'Docker image:            PASS\n'
else
  printf 'Docker image:            NOT RUN\n'
fi
