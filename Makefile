# Central — developer entry points. Run `make help` for a summary.
#
# Tools are installed into ./bin at pinned versions so every contributor (and CI) generates
# and lints with exactly the same binaries.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

ROOT      := $(abspath .)
BIN       := $(ROOT)/bin
WEB       := $(ROOT)/web
SERVER    := $(ROOT)/server
WEBUI_DST := $(SERVER)/internal/webui/dist

export GOTOOLCHAIN ?= go1.27.1
export GOBIN := $(BIN)
export PATH := $(BIN):$(PATH)

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

# Pinned tool versions (bump deliberately; Dependabot does not track these).
BUF_VERSION                  := v1.73.0
PROTOC_GEN_GO_VERSION        := v1.36.12
PROTOC_GEN_CONNECT_GO_VERSION := v1.21.0
GOLANGCI_LINT_VERSION        := v2.14.0
GOVULNCHECK_VERSION          := v1.8.0

GO_MODULES := ./gen/go/... ./server/...

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------------------------
# Tooling
# ---------------------------------------------------------------------------------------------

.PHONY: tools
tools: tools-gen ## Install pinned code-generation, lint and security tools into ./bin
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: tools-gen
tools-gen: ## Install only the pinned Protobuf tools (buf + code generators) into ./bin
	go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@$(PROTOC_GEN_CONNECT_GO_VERSION)

NODE_MAJOR := $(shell cat $(ROOT)/.nvmrc)

.PHONY: check-node
check-node: # Fail early (and helpfully) when Node.js is missing or too old
	@command -v node >/dev/null || { \
		echo "error: 'node' is not on PATH. Central needs Node.js $(NODE_MAJOR) (see .nvmrc)." >&2; \
		echo "  Install it with nvm from the repo root: nvm install && nvm use" >&2; \
		echo "  then install the web dependencies:    cd web && npm ci" >&2; \
		exit 1; }
	@node -e 'process.exit(+process.versions.node.split(".")[0] >= $(NODE_MAJOR) ? 0 : 1)' || { \
		echo "error: Node.js $$(node --version) is too old; Central needs $(NODE_MAJOR) (see .nvmrc): nvm install && nvm use" >&2; \
		exit 1; }

web/node_modules: web/package-lock.json | check-node
	cd $(WEB) && npm ci --no-audit --no-fund
	@touch $@

# ---------------------------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------------------------

GEN_TOOLS := $(BIN)/buf $(BIN)/protoc-gen-go $(BIN)/protoc-gen-connect-go

.PHONY: check-gen-tools
check-gen-tools: check-node web/node_modules
	@for t in $(GEN_TOOLS) $(WEB)/node_modules/.bin/protoc-gen-es; do \
		test -x "$$t" || { echo "error: $$t is missing: run 'make tools-gen' and 'cd web && npm ci'" >&2; exit 1; }; \
	done

# Generation writes into a scratch directory first, so a failed run never leaves the tree
# without the committed generated code.
.PHONY: gen
gen: check-gen-tools ## Regenerate Go and TypeScript code from /proto
	@tmp=$$(mktemp -d "$(ROOT)/.gen.XXXXXX"); trap 'rm -rf "$$tmp"' EXIT; \
	buf generate --output "$$tmp"; \
	rm -rf gen/go/central web/src/gen; \
	mv "$$tmp/gen/go/central" gen/go/central; \
	mv "$$tmp/web/src/gen" web/src/gen
	cd gen/go && go mod tidy

.PHONY: gen-check
gen-check: gen ## Fail if generated code is out of date (used in CI)
	@git diff --exit-code -- gen web/src/gen || (echo "Generated code is stale: run 'make gen'" && exit 1)
	@test -z "$$(git status --porcelain -- gen web/src/gen)" || (git status --porcelain -- gen web/src/gen; echo "Untracked generated files: run 'make gen'"; exit 1)

# ---------------------------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------------------------

.PHONY: web
web: check-node web/node_modules ## Build the Angular UI and stage it for embedding into the server binary
	cd $(WEB) && npm run build
	find $(WEBUI_DST) -mindepth 1 ! -name .gitkeep -delete
	cp -R $(WEB)/dist/browser/. $(WEBUI_DST)/

.PHONY: build
build: web ## Build the central binary (with the UI embedded) into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/central ./server/cmd/central
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/central-sim ./server/cmd/central-sim

.PHONY: build-server
build-server: ## Build only the Go binaries (uses whatever UI is already staged)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/central ./server/cmd/central
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/central-sim ./server/cmd/central-sim

# ---------------------------------------------------------------------------------------------
# Development
# ---------------------------------------------------------------------------------------------

.PHONY: dev-server
dev-server: ## Run the server in dev mode (in-memory store, self-signed TLS) on :8080
	go run ./server/cmd/central serve --dev

.PHONY: dev-web
dev-web: check-node web/node_modules ## Run the Angular dev server on :4200 (proxies /api and /ws to :8080)
	cd $(WEB) && npm start

.PHONY: sim
sim: ## Run simulated agents against a local dev server (KEY_FILE=enrollment key file, AGENTS=25)
	go run ./server/cmd/central-sim --agents $(or $(AGENTS),25) $(if $(KEY_FILE),--key-file $(KEY_FILE))

# ---------------------------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------------------------

.PHONY: test
test: test-go test-web ## Run all unit tests

.PHONY: test-go
test-go: ## Go unit tests with the race detector
	go test -race -shuffle=on -count=1 $(GO_MODULES)

.PHONY: test-web
test-web: check-node web/node_modules ## Angular unit tests (Vitest)
	cd $(WEB) && npm run test:ci

.PHONY: lint
lint: lint-proto lint-go lint-web ## Run all linters

.PHONY: lint-proto
lint-proto: ## Lint Protobuf contracts
	buf lint
	buf format --diff --exit-code

.PHONY: lint-go
lint-go: ## Lint Go code (golangci-lint, including gosec)
	golangci-lint run $(GO_MODULES)

.PHONY: lint-web
lint-web: check-node web/node_modules ## Lint and format-check the Angular code
	cd $(WEB) && npm run lint && npm run format:check

.PHONY: vuln
vuln: ## Scan Go dependencies for known vulnerabilities
	@for m in gen/go server; do (cd $$m && govulncheck ./...) || exit 1; done

.PHONY: breaking
breaking: ## Check the Protobuf contracts for breaking changes against master
	buf breaking --against '.git#branch=origin/master'

.PHONY: check
check: lint test vuln ## Everything CI runs, locally

# ---------------------------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------------------------

.PHONY: docker
docker: ## Build the container image (requires a Docker daemon)
	docker build -f deploy/docker/Dockerfile -t central:$(VERSION) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) .

.PHONY: clean
clean: ## Remove build output
	rm -rf $(WEB)/dist $(BIN)/central $(BIN)/central-sim
	find $(WEBUI_DST) -mindepth 1 ! -name .gitkeep -delete
