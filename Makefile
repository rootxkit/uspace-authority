# uspace-authority developer targets. CI (.github/workflows/ci.yml) runs the
# same commands. On Windows set GOROOT and GO, for example:
#   make test GO=/c/Users/<you>/AppData/Local/anaconda3/bin/go
GO      ?= go
PKGS    ?= ./...
CORE    ?= github.com/rootxkit/uspace-core
COMPOSE ?= docker compose -f deploy/compose.dev.yaml
IMAGE   ?= ghcr.io/rootxkit/uspace-authority
TAG     ?= dev

# Linter versions pinned to the ones uspace-core pins and
# .github/workflows/ci.yml runs. Change all three places together.
GOLANGCI_LINT_VERSION ?= v2.14.0
STATICCHECK_VERSION   ?= v0.8.1
GITLEAKS_VERSION      ?= v8.24.3
GOVULNCHECK_VERSION   ?= v1.8.0

# The development stack's URLs (deploy/compose.dev.yaml); test-only
# credentials of a throwaway local container.
DEV_PG_URL ?= postgres://authority:authority@localhost:56432/authority?sslmode=disable
DEV_TS_URL ?= postgres://postgres:authority@localhost:56433/authority_ts?sslmode=disable
DEV_NATS_URL ?= nats://127.0.0.1:56422

.PHONY: all build vet fmt fmt-check tools staticcheck lint test race cover vectors \
        generate verify-generated integration migrate up down image tidy secrets \
        vulncheck ci clean

all: ci

build:
	$(GO) build $(PKGS)

vet:
	$(GO) vet $(PKGS)

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tools:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	$(GO) install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) $(PKGS)

# Refuses to run a golangci-lint other than the pinned one: a different
# version enables different checks and would pass locally but fail in CI.
lint: fmt-check vet staticcheck
	@v="v$$(golangci-lint version --short 2>/dev/null)"; \
	if [ "$$v" != "$(GOLANGCI_LINT_VERSION)" ]; then \
	  echo "golangci-lint $$v found, CI runs $(GOLANGCI_LINT_VERSION): run 'make tools'"; exit 1; fi
	golangci-lint run $(PKGS)

tidy:
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum

test:
	$(GO) test -count=1 -shuffle=on $(PKGS)

# The race detector needs cgo (CGO_ENABLED=1 and a C toolchain) for the
# test binary only; the shipped binaries stay CGO_ENABLED=0.
race:
	CGO_ENABLED=1 $(GO) test -race -count=1 -shuffle=on $(PKGS)

cover:
	$(GO) test -count=1 -coverprofile=coverage.out -covermode=atomic $(PKGS)
	$(GO) tool cover -func=coverage.out | tail -n 1

# uspace-core's own vector tests, run from the module cache at the pinned
# version, then this repository's RunOwned tests.
vectors:
	$(GO) test -count=1 -run 'Vector|Manifest|Version' $(CORE)/...
	$(GO) test -count=1 -run 'Vector|Manifest|Version' $(PKGS)

generate:
	scripts/generate.sh

verify-generated:
	scripts/verify-generated.sh

# Tests that need the development stack (make up).
integration:
	INTEGRATION=1 PG_URL='$(DEV_PG_URL)' TS_URL='$(DEV_TS_URL)' NATS_URL='$(DEV_NATS_URL)' $(GO) test -count=1 -run Integration $(PKGS)

# Both trees against the development stack, as the one-shot service does.
migrate:
	PG_URL='$(DEV_PG_URL)' TS_URL='$(DEV_TS_URL)' $(GO) run ./cmd/uspace-authority migrate

up:
	$(COMPOSE) up -d --wait

down:
	$(COMPOSE) down -v

image:
	docker build --build-arg VERSION=$(TAG) -t $(IMAGE):$(TAG) .

secrets:
	gitleaks detect --no-banner --redact
	gitleaks detect --no-banner --redact --no-git --source .

vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(PKGS)

ci: build lint race vectors verify-generated vulncheck

clean:
	rm -f coverage.out
