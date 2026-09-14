BINARY   := cvefeed
PREFIX ?= /usr/local

# Compose reads this so a built image can name the commit it came from.
export CVEFEED_VERSION = $(VERSION)
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# A vendored tree means the image build must not touch a module proxy; the
# Dockerfile skips `go mod download` when told so, and `go build` picks
# -mod=vendor on its own once the sources are copied in.
VENDORED := $(if $(wildcard vendor/modules.txt),1,0)
export CVEFEED_VENDORED = $(VENDORED)
# --env-file points at the repository root: docker compose otherwise resolves
# .env relative to the compose file's directory, so the .env the README tells
# you to create at the root was silently ignored and the stack came up with the
# default password and no API token.
#
# Only --env-file, deliberately. Adding --project-directory would also move the
# base for the compose file's relative build context, which resolves against the
# compose file's own directory.
ENV_FILE := $(if $(wildcard .env),--env-file .env,)
COMPOSE  := docker compose $(ENV_FILE) -f deploy/docker-compose.yml

# The air-gap paths inside the api container. All of them live under the one
# named volume, because every target below runs in a `--rm` container and
# anything written elsewhere is gone when it exits — which is how `make pack`
# used to write its tarball to /var/lib/cvefeed and delete it in the same
# breath. The recording goes to bundle/data; the tarball goes to bundle/ beside
# it, not inside it, so a pack never captures its own output; unpack expands
# into the same bundle/data that `offline` reads.
BUNDLE_DIR  := /var/lib/cvefeed/bundle
BUNDLE_DATA := $(BUNDLE_DIR)/data
BUNDLE_TAR  := $(BUNDLE_DIR)/cvefeed-bundle.tar.gz
# The tarball on this machine: what `pack` produces and `unpack` consumes.
# Override it to write straight onto the transfer medium:
#   make pack BUNDLE_FILE=/media/transfer/cvefeed-bundle.tar.gz
BUNDLE_FILE ?= cvefeed-bundle.tar.gz

.PHONY: help build install test lint verify verify-windows verify-live verify-live-heavy \
        vendor image up down logs migrate backfill delta harvest pack unpack \
        offline clean

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Compile the binary into ./bin
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/$(BINARY)

install: build ## Install the binary onto PATH (PREFIX=/usr/local by default)
	@install -d $(PREFIX)/bin
	install -m 0755 bin/$(BINARY) $(PREFIX)/bin/$(BINARY)
	@echo "installed $(PREFIX)/bin/$(BINARY)"

test: ## Run the hermetic unit-test tier
	go test ./...

lint: ## Vet and formatting check
	go vet ./...
	@test -z "$$(gofmt -l . )" || (echo "gofmt needed:"; gofmt -l .; exit 1)

verify: ## Full local release gate: PostgreSQL, race tests, analyzers, builds, image
	bash scripts/verify-release.sh

verify-windows: ## Same release gate from Windows PowerShell
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify-release.ps1

verify-live: ## Probe real upstreams for schema/shape drift (network required)
	CVEFEED_TEST_LIVE=1 go test ./internal/collect/ -run Live -count=1

verify-live-heavy: ## Live probes plus the large baseline source (slow/network heavy)
	CVEFEED_TEST_LIVE=1 CVEFEED_TEST_LIVE_HEAVY=1 go test ./internal/collect/ -run Live -count=1 -timeout 30m

vendor: ## Vendor dependencies for offline image builds
	go mod tidy
	go mod vendor

image: ## Build the container image
	docker build -f deploy/Dockerfile -t cvefeed:$(VERSION) \
		--build-arg VERSION=$(VERSION) --build-arg VENDORED=$(VENDORED) .

up: ## Start the stack
	$(COMPOSE) up -d --build

down: ## Stop the stack
	$(COMPOSE) down

logs: ## Follow the API logs
	$(COMPOSE) logs -f api

migrate: ## Apply the schema
	$(COMPOSE) run --rm migrate

backfill: ## Full historical load (hours; run once)
	$(COMPOSE) run --rm api ingest -mode backfill

delta: ## Incremental refresh of every source
	$(COMPOSE) run --rm api ingest -mode delta

harvest: ## Internet side: ingest and record an air-gap bundle
	$(COMPOSE) run --rm api ingest -mode backfill -record $(BUNDLE_DATA)

# Two steps: pack inside the volume, where the result survives the container,
# then stream it out through the container's stdout. `docker compose cp` needs
# a running service container and these are one-shot `run`s. --no-deps keeps
# a copy from starting the database; -T keeps the byte stream free of a
# pseudo-terminal.
pack: ## Wrap the recorded bundle and copy it out to ./$(BUNDLE_FILE)
	$(COMPOSE) run --rm --no-deps api bundle pack $(BUNDLE_DATA) $(BUNDLE_TAR)
	$(COMPOSE) run --rm --no-deps -T --entrypoint cat api $(BUNDLE_TAR) > $(BUNDLE_FILE)
	@ls -l $(BUNDLE_FILE)

unpack: ## Air-gapped side: copy $(BUNDLE_FILE) into the volume and expand it
	$(COMPOSE) run --rm --no-deps -T --entrypoint sh api -c 'cat > $(BUNDLE_TAR)' < $(BUNDLE_FILE)
	$(COMPOSE) run --rm --no-deps api bundle unpack $(BUNDLE_TAR) $(BUNDLE_DATA)

offline: ## Air-gapped side: ingest from the bundle, no network
	$(COMPOSE) run --rm api ingest -mode backfill -bundle $(BUNDLE_DATA)

clean: ## Remove build artefacts and volumes
	rm -rf bin .verify-build
	$(COMPOSE) down -v
