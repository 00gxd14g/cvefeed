# cvefeed

[![ci](https://github.com/00gxd14g/cvefeed/actions/workflows/ci.yml/badge.svg)](https://github.com/00gxd14g/cvefeed/actions/workflows/ci.yml)

`cvefeed` is a Go-based vulnerability intelligence mirror and exposure-matching service. It aggregates public vulnerability data from eleven upstream sources, resolves equivalent identifiers into one canonical record, enriches the result with exploitation and scoring data, and exposes the corpus through a CLI and HTTP API.

It can run online or from a recorded, content-addressed bundle inside an isolated network.

> **Scope:** cvefeed aggregates the public vulnerability ecosystem; it does not claim that every vulnerability in existence is publicly documented. Network target scanning is reconnaissance based on observable service/version evidence. SBOM or local package inventory is the stronger exposure signal.

**Contents:** [Sources](#what-it-combines) · [Architecture](#architecture) · [Quick start](#quick-start) · [Without Docker](#without-docker) · [Configuration](#configuration-reference) · [CLI](#cli-reference) · [Scanning](#scanning-inventory) · [HTTP API](#http-api) · [Air gap](#air-gapped-operation) · [Verification](#release-verification) · [Limitations](#limitations) · [Contributing](#contributing) · [Licence](#attribution-and-licence)

## What it combines

| Collector | Upstream | Main contribution |
|---|---|---|
| `cvelist` | CVE Program CVE List v5 | Authoritative CNA records and CVE JSON 5.x |
| `vulnrichment` | CISA ADP repository | SSVC, CISA CVSS and CWE enrichment |
| `nvd` | NVD CVE API 2.0 | CPE applicability statements |
| `fkie` | Fraunhofer FKIE NVD mirror | Whole-history backfill and modified delta |
| `osv` | OSV.dev | Distribution and language-ecosystem advisories |
| `ghsa` | GitHub Advisory Database | Reviewed ecosystem advisories and GHSA-only findings |
| `euvd` | ENISA EU Vulnerability Database | EU coordinated advisories and consolidated exploited data |
| `gcve` | GCVE registry + Vulnerability-Lookup | Decentralised identifiers and GNA data |
| `csaf` | Vendor CSAF 2.0 providers | Vendor/OT/ICS advisories and VEX product status |
| `kev` | CISA Known Exploited Vulnerabilities | Confirmed in-the-wild exploitation |
| `epss` | FIRST EPSS | Daily exploitation probability |

The canonical merge precedence is:

```text
cvelist > vulnrichment > nvd > fkie > csaf > euvd > gcve > ghsa > osv
```

A higher-authority source can replace a populated canonical field; a lower-authority source fills gaps. Competing CVSS statements remain available rather than being discarded. Publication dates take the earliest observed value and modification dates the latest.

## Architecture

```text
                      ┌──────────────┐
    upstreams ───────▶│   Fetcher    │◀──── air-gap bundle
                      └──────┬───────┘
                             │
                      ┌──────▼───────┐
                      │  Collectors  │   source-specific cursors
                      └──────┬───────┘
                      ┌──────▼───────┐
                      │   Parsers    │   CVE 5.x · NVD · OSV · CSAF
                      └──────┬───────┘
                      ┌──────▼───────┐
                      │    Store     │   PostgreSQL · alias graph · history
                      └──────┬───────┘
                      ┌──────▼───────┐
                      │ CLI / HTTP   │   query · export · scan · feed
                      └──────────────┘
```

### Identifier resolution

Identifiers that assert **sameness** enter the alias graph. A CVE, GHSA and EUVD identifier describing the same flaw resolve to one canonical record. Fields such as OSV `related`, which mean “related but not equivalent”, are deliberately not used as identity edges.

### Conservative matching

The matcher prefers an explicit “cannot prove this” result over a confident guess:

- package URL or exact CPE identity is stronger than vendor/product or a bare name;
- Debian, RPM, APK, Maven, PEP 440, Go module and SemVer ordering are handled by their own schemes;
- unknown/custom bounds are returned as **undecidable**, not guessed;
- VEX `not_affected`/`fixed` evidence only suppresses a positive finding when its evidence is at least as strong;
- NVD/CVE CPE applicability that depends on a cross-component `AND` condition — "this application **and** that platform" — is kept on its own row with status `conditional` rather than flattened into a false positive. A package inventory cannot answer the second half, so the finding is reported as undecidable, and the explanation says the condition is unprovable rather than pretending the upstream is still investigating;
- CVE 5.x `versions[].changes` boundaries are preserved as separate status intervals;
- a distribution package (`pkg:deb`, `pkg:rpm`, `pkg:apk`) matched only by bare product name against an upstream statement with no ecosystem is reported as **undecidable**, never as a finding: a distro build's version does not show backported fixes, and names collide across ecosystems (the Debian package `bolt` is a Thunderbolt daemon, the product `bolt` a CMS). The distribution's own advisories (OSV Ubuntu/Debian/Alpine, CSAF) decide those packages, and they match on ecosystem and name.

## Quick start

Requirements: Docker with Compose (the stack is PostgreSQL 16 plus the `cvefeed` image). For the host-side CLI, use Go 1.26.8 or a newer patched toolchain and build the binary with `make build`. The module's `toolchain` directive names Go 1.26.8, which Go selects automatically with the default `GOTOOLCHAIN=auto`; an offline build needs that toolchain installed beforehand.

```bash
cp .env.example .env
# set POSTGRES_PASSWORD at minimum
make up            # builds the image, runs `migrate`, then starts `serve` on :8080
make delta
curl --fail localhost:8080/readyz
curl --fail localhost:8080/v1/stats
```

`make up` publishes the API on `CVEFEED_PORT` (default 8080) and the database on loopback only at `POSTGRES_PORT` (default 5432). The `serve` process runs the collectors on their own schedule unless `CVEFEED_SCHEDULE_ENABLED=false`; the scheduler runs every collector in delta mode, and on an empty database several sources fall back to their baseline artefacts, so expect sustained network traffic until the first pass settles. Run `make backfill` once for a deliberate full load.

For a full historical load:

```bash
make backfill
```

An NVD API key and GitHub token are strongly recommended for backfills; unauthenticated upstream limits make a complete load much slower.

### Without Docker

The binary is static and needs only a PostgreSQL database (16 is what the Compose stack, the CI job and the release gate use).

```bash
# 1. Go 1.26.8 or newer, then build
make build                       # ./bin/cvefeed

# 2. A database and a role that owns it
sudo -u postgres psql -c "CREATE USER cvefeed PASSWORD 'change-me';"
sudo -u postgres psql -c "CREATE DATABASE cvefeed OWNER cvefeed;"

# 3. Point the binary at it: either POSTGRES_* in ./.env (host is always
#    localhost, port from POSTGRES_PORT) or an explicit DSN in the environment
cp .env.example .env             # set POSTGRES_PASSWORD
# or: export CVEFEED_DATABASE_URL='postgres://cvefeed:change-me@localhost:5432/cvefeed?sslmode=disable'

# 4. Schema, then serve (API + scheduled collectors) or a one-shot ingest
./bin/cvefeed migrate
./bin/cvefeed serve              # listens on CVEFEED_LISTEN_ADDR, default :8080
./bin/cvefeed ingest -mode delta # or: -mode backfill
```

`.env` is read from the working directory or up to four parents, without overriding variables already set in the environment. `serve` stops cleanly on `SIGINT`/`SIGTERM`: in-flight requests get 30 seconds, and a collector mid-run is cancelled and its cursor left where the last completed run put it.

### Install the CLI

```bash
make install
```

The CLI talks directly to PostgreSQL. When run from the repository it reads the same `.env` used by Compose and targets the database published on loopback. For an external database set the DSN explicitly:

```bash
export CVEFEED_DATABASE_URL='postgres://cvefeed:PASSWORD@db.example.org:5432/cvefeed?sslmode=require'
```

Do not duplicate that DSN in `.env` alongside `POSTGRES_*`; an explicit DSN wins and can make later password changes appear ineffective.

## Configuration reference

Everything is read from the environment (and `.env`) by `internal/config`. Empty values mean the default. `.env.example` carries the same list with commentary.

| Variable | Default | Purpose |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` / `POSTGRES_PORT` | `cvefeed` / – / `cvefeed` / `5432` | Consumed by Compose for the database container; the CLI builds a loopback DSN from them |
| `CVEFEED_DATABASE_URL` | built from `POSTGRES_*` | Explicit DSN; wins over `POSTGRES_*` when set |
| `CVEFEED_LISTEN_ADDR` | `:8080` | API listen address (`serve -addr` overrides) |
| `CVEFEED_PORT` | `8080` | Host port Compose publishes the API on |
| `CVEFEED_API_TOKEN` | empty (open) | Bearer token required on `/v1` when set |
| `CVEFEED_LOG_LEVEL` | `info` | `debug` · `info` · `warn` · `error` |
| `CVEFEED_NVD_API_KEY` | empty | Raises the NVD limit from 5 to 50 requests / 30 s |
| `CVEFEED_GITHUB_TOKEN` | empty | Raises the GitHub API limit (CVE List, Vulnrichment, GHSA) |
| `CVEFEED_VULNCHECK_TOKEN` | empty | Attached as a bearer token to requests for `api.vulncheck.com`; no bundled collector calls that host today |
| `CVEFEED_SCHEDULE_ENABLED` | `true` | Run collectors inside `serve` (`-no-schedule` overrides) |
| `CVEFEED_INTERVAL_<SOURCE>` | per source | Cadence override as a Go duration, e.g. `CVEFEED_INTERVAL_NVD=30m`; defaults: cvelist/kev/vulnrichment 1h, nvd 2h, fkie/euvd/osv/ghsa 6h, csaf 12h, epss/gcve 24h |
| `CVEFEED_CSAF_PROVIDERS` | empty (collector idle) | Comma-separated CSAF provider base or `provider-metadata.json` URLs |
| `CVEFEED_TARGET_SCAN_ENABLED` | `false` | Opens `POST /v1/scan/target` |
| `CVEFEED_BUNDLE_PATH` | empty | Serve every upstream request from a recorded bundle |
| `CVEFEED_RECORD_PATH` | empty | Record every upstream response into a bundle |
| `CVEFEED_OFFLINE_ONLY` | `false` | Refuse the network when no bundle is configured |
| `CVEFEED_HTTP_TIMEOUT` | `120s` | Response-header deadline for upstream requests |
| `CVEFEED_HTTP_MAX_RETRIES` | `5` | Upstream retry budget |
| `CVEFEED_INGEST_BATCH_SIZE` | `500` | Records buffered between collectors and writers |
| `CVEFEED_USER_AGENT` | placeholder | Set it: several upstreams filter on it or require a `mailto` |
| `CVEFEED_VULNLOOKUP_URL` | `https://vulnerability.circl.lu` | Vulnerability-Lookup instance used by the `gcve` collector |
| `CVEFEED_NO_PROGRESS` | unset | Any value disables the terminal progress display |

Booleans are parsed strictly: a value that is not a boolean is a startup error, not a silent default.

## CLI reference

```text
cvefeed migrate
cvefeed ingest [-sources a,b,c] [-mode delta|backfill] [-record DIR] [-bundle DIR] [-since RFC3339|YYYY-MM-DD]
cvefeed serve  [-addr :8080] [-no-schedule]
cvefeed scan   [-sbom FILE | -purls FILE | -local | -target HOST] [-ports SPEC] [-engine auto|builtin|nmap|masscan]
               [-min-confidence confirmed|probable|possible] [-undecidable] [-explain] [-format text|json] [-v]
cvefeed sources
cvefeed bundle pack <dir> <file.tar.gz> | unpack <file.tar.gz> <dir> | info <dir>
cvefeed version
```

`cvefeed -h` prints the same summary together with the exit-status contract; `cvefeed scan -h` lists the sweep tuning flags (`-max-hosts`, `-host-concurrency`, `-probe-timeout`, `-rate`).

## Scanning inventory

```bash
# CycloneDX/SPDX-style SBOM produced by syft, trivy, cdxgen, etc.
cvefeed scan -sbom bom.cdx.json

# Packages installed on this host (dpkg / rpm / apk)
cvefeed scan -local

# Plain package-URL list
cvefeed scan -purls components.txt
```

Every finding includes a confidence level and the evidence that produced it. The default minimum is `probable`.

| Confidence | Identity | Version evidence |
|---|---|---|
| `confirmed` | exact package URL or CPE | ordered under a declared scheme |
| `probable` | vendor/product or ecosystem/name | ordered under a declared scheme |
| `possible` | bare product or incomplete identity | generic/demoted evidence |

For distribution packages (`scan -local`, or an SBOM with `pkg:deb`, `pkg:rpm`, `pkg:apk` identities) the levels carry one more distinction. The Ubuntu and Debian trackers export "needs-triage", "needed", "pending", "deferred" and "ignored" alike as an open-ended affected range, and the triage state is not in the record. So:

- `confirmed` means the distribution has released a fix and the installed build predates it. That claim is checkable from the outside (`apt`, Launchpad, the tracker), and on a test host every confirmed finding was a missing security update.
- `probable` means the distribution lists the package as affected with no fix released. Some of those are confirmed-and-unfixed, some are untriaged, and the tracker's web view can already say not-affected while the export still says affected. Review them; do not page on them.

`cvefeed scan -local -min-confidence confirmed` is the setting for a pipeline that must not raise a false positive.

Statements that cannot be decided are kept out of the positive finding count. Pass `-undecidable` to list them, and `-explain` to print the evidence sentence behind every row:

```bash
cvefeed scan -sbom bom.cdx.json -undecidable -explain -min-confidence possible
```

### Pipeline exit status

| Status | Meaning |
|---|---|
| `0` | scan completed and no vulnerability in the corpus applies |
| `1` | scan could not be completed: bad input, an unreachable corpus, or a `-target` sweep that examined nothing (declined engine, or no address answered) |
| `2` | scan completed and at least one vulnerability applies |

Text and JSON output use the same status semantics. A `-target` sweep whose open ports answered but could not be identified as a versioned product completes with zero components and exits `0`; the report names those ports so the result is not mistaken for a clean host.

## Network reconnaissance

For hosts you can reach but cannot inventory directly:

```bash
cvefeed scan -target 10.0.0.7
cvefeed scan -target 10.0.0.0/24
cvefeed scan -target 10.0.0.7 -ports 22,80,443,8000-8100
```

`auto` uses the tools available on the host. Where usable, masscan performs discovery and nmap `-sV` confirms and identifies services. Otherwise the scanner degrades explicitly to nmap or the built-in connect/read prober; it reports the method and any coverage limitation rather than silently calling an unexamined host clean.

```text
-engine auto|builtin|nmap|masscan
```

Nothing in the network scanner exploits a vulnerability to prove it. Banners and remote version detection can be stale or affected by backported fixes, so treat `-target` as reconnaissance. Prefer `-local` or an SBOM for authoritative package state.

The HTTP target-scanning endpoint is disabled unless `CVEFEED_TARGET_SCAN_ENABLED=true`; enabling it allows authenticated API callers to make the service connect to hosts reachable from the server.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | process liveness |
| `GET /readyz` | database readiness |
| `GET /v1/vulns` | filtered, paginated vulnerability query |
| `GET /v1/vulns/{id}` | canonical record; aliases resolve |
| `GET /v1/vulns/{id}/history` | change history |
| `GET /v1/export?format=ndjson\|csv` | streaming export |
| `GET /v1/stats` | corpus counters |
| `GET /v1/sources` | collector cursors/state/last error |
| `GET /v1/attribution` | upstream licences and required notices |
| `POST /v1/scan` | scan an uploaded inventory |
| `POST /v1/scan/target` | probe a reachable target; disabled by default |
| `GET /v1/feed.atom` | recent-change Atom feed |

Common filters include:

```text
modified_since  published_since  score_min  score_max  epss_min
kev  rating  state  source  cwe  q  cpe  purl  product  vendor
ecosystem  limit  offset  order_by
```

`limit` defaults to 100 and is capped at 1000. Invalid enum/filter values, out-of-range thresholds and unknown query parameter names are rejected with `400` and a JSON `{"error": "..."}` body rather than silently ignored. List items carry the record without its `affected` and `references` arrays; `GET /v1/vulns/{id}` and `/v1/export` return the full document.

`POST /v1/scan` takes the same inventory the CLI accepts (CycloneDX or SPDX JSON, or a newline-separated package-URL list) as the request body, with the query options `min_confidence=confirmed|probable|possible` and `undecidable=true|false`. Bodies are capped at 64 MB.

`POST /v1/scan/target` is enabled only when `CVEFEED_TARGET_SCAN_ENABLED=true` and takes a JSON body:

```json
{"host": "10.0.0.7", "ports": "22,80,443,8000-8100", "engine": "auto", "timeout_seconds": 5, "rate": 1000}
```

`host` may be an address, a hostname or a CIDR of at most 256 addresses; `ports` is capped at 1024 ports, `timeout_seconds` at 30 and `rate` (masscan packets per second) at 20000. Larger values are rejected with `400`.

Set `CVEFEED_API_TOKEN` to require a bearer token on `/v1`. Health/readiness endpoints remain open for probes.

## Air-gapped operation

The same collector code runs online and offline through the `Fetcher` interface; air-gap support is not a second parser path.

### Direct CLI flow

```bash
# internet-connected side
cvefeed ingest -mode backfill -record /data/bundle
cvefeed bundle pack /data/bundle /media/transfer.tar.gz

# isolated side
cvefeed bundle unpack /media/transfer.tar.gz /data/bundle
cvefeed bundle info /data/bundle
CVEFEED_OFFLINE_ONLY=true \
  cvefeed ingest -mode backfill -bundle /data/bundle
```

### Compose flow

```bash
make harvest
make pack

# transfer cvefeed-bundle.tar.gz

make unpack
make offline
```

Bundle responses are content-addressed and verified by SHA-256 when read. A paginated offline walk is pinned to one recorded time window so pages from different harvest windows cannot be silently spliced together.

`CVEFEED_OFFLINE_ONLY=true` makes a missing bundle a hard error rather than falling back to the network.

## Collector progress and failure isolation

Each source has its own cursor. The runner drains asynchronous database writes before committing progress.

If a queued vulnerability record fails to persist:

1. the source run is marked failed;
2. the effective cursor from the start of that run is retained;
3. the failed range is retried on the next run;
4. records that already landed are skipped efficiently by the unchanged-content check.

A cursor therefore does not move past a record merely because it entered the writer queue. This intentionally trades some replay work for protection against silent vulnerability-data loss.

Collectors fail independently: one unavailable upstream does not stop the others. Complete catalogue sources such as CISA KEV use replace semantics so entries that genuinely leave the authoritative catalogue are retired rather than remaining permanently flagged.

## CSAF / VEX

CSAF collection is opt-in because the useful provider set depends on the estate being protected:

```text
CVEFEED_CSAF_PROVIDERS=https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json,https://security.access.redhat.com/data/csaf/v2/provider-metadata.json
```

Entries may be vendor base URLs or full `provider-metadata.json` URLs. Both ROLIE and directory distributions are supported, and SHA-256 sidecars are checked when a provider publishes them.

## Release verification

The release gate runs locally and on GitHub Actions; both execute the same steps.

Linux/macOS/WSL:

```bash
make verify
```

Windows PowerShell:

```powershell
.\scripts\verify-release.ps1
```

`.github/workflows/ci.yml` runs the gate on every push to `master` and every pull request, and can also be started by hand from the Actions tab. `.github/workflows/release.yml` builds static binaries for Linux, macOS and Windows on a `v*` tag and attaches them, with a `SHA256SUMS` manifest, to a GitHub Release.

The gate starts a disposable PostgreSQL 16 container and performs:

- `gofmt` check;
- `go vet ./...`;
- `go test -race -count=1 ./...` with database-backed integration tests enabled;
- Linux, Windows and macOS build checks;
- pinned `staticcheck`;
- pinned `govulncheck` against the current Go vulnerability database;
- Docker runtime-image build.

Docker is used for exactly two of those — the database and the image — so a machine without it can still run the rest:

```bash
# use a PostgreSQL you already have, and skip the image build
CVEFEED_VERIFY_PG_DSN='postgres://cvefeed:test@127.0.0.1:5432/cvefeed?sslmode=disable' \
CVEFEED_VERIFY_SKIP_IMAGE=1 make verify
```

`govulncheck` distinguishes the two ways it can fail: finding a vulnerable dependency, and not reaching the vulnerability database at all. The second is not a pass, and the gate says so rather than letting an offline run look clean.

Real upstream response shapes require a separate networked tier:

```bash
make verify-live
make verify-live-heavy   # slower / bandwidth-heavy
```

## Development

```bash
make test          # hermetic unit tests
make lint          # go vet + gofmt check
make build         # ./bin/cvefeed
make verify        # full local release gate
make vendor        # vendor dependencies for offline image builds
```

The module intentionally has a small direct dependency set; most of the implementation uses the Go standard library. The container and manual CI builds use Go 1.26.8 even though the module language floor remains older for compatibility. The `toolchain` recommendation does not prevent an explicit `GOTOOLCHAIN=local` override; run `govulncheck` with the toolchain used for the release binary.

## Limitations

- Coverage is the public ecosystem: a flaw nobody has published is not in the corpus, and a CNA record without version data yields no match.
- A first backfill takes hours and pulls several gigabytes; without an NVD key and a GitHub token it takes much longer.
- `-target` reconnaissance identifies services from banners and nmap version probes. Backported fixes and stale banners produce findings that need human review; it never exploits anything to confirm.
- CSAF collection is off until `CVEFEED_CSAF_PROVIDERS` names providers; there is no built-in provider list.
- PostgreSQL is the only supported store, and the schema is managed by `cvefeed migrate` only.
- The container image runs as an unprivileged user, so masscan cannot open raw sockets there; `scan -target` falls back to nmap or the built-in prober and says so.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the checks to run before a pull request and [`SECURITY.md`](SECURITY.md) for how to report a vulnerability in cvefeed itself.

## Attribution and licence

The **cvefeed source code** is distributed under the source-available terms in [`LICENSE`](LICENSE): free to view, run and evaluate for personal, educational, research and internal non-commercial use; redistribution, modified releases, hosted offerings and other commercial use need written permission. It is not an OSI-approved open-source licence.

The vulnerability/advisory data retrieved by the service is not relicensed by that file. Upstream terms continue to apply. `GET /v1/attribution` exposes the required notices, including NVD/NIST and advisory-database attribution requirements.
