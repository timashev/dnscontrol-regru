# Build and check tasks for the out-of-tree REGRU DNSControl provider.

BINARY ?= dnscontrol
CMD    ?= ./cmd/dnscontrol

# Version reported by the wrapper binary. The +regru suffix marks this as the
# REGRU-enabled build; the base tracks the dnscontrol release it is built
# against. Injecting it here makes `dnscontrol version` (the subcommand) report
# it too, not just the --version banner.
DNSCONTROL_VERSION ?= v4.42.0
VERSION            ?= $(DNSCONTROL_VERSION)+regru
VERSION_PKG        := github.com/DNSControl/dnscontrol/v4/pkg/version
LDFLAGS            := -X $(VERSION_PKG).version=$(VERSION)

.PHONY: build test lint vet fmt check clean

build: ## Build the dnscontrol binary with REGRU compiled in.
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

test: ## Run unit tests (the live test is skipped unless REGRU_LIVE=1).
	go test ./...

vet: ## Run go vet.
	go vet ./...

lint: ## Run golangci-lint.
	golangci-lint run ./...

fmt: ## Fail if any Go file is not gofmt-clean.
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

check: fmt vet lint test build ## Run the full set of checks (mirrors CI).

clean: ## Remove build artifacts.
	rm -f $(BINARY)
