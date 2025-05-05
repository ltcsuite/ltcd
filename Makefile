PKG := github.com/ltcsuite/ltcd

LINT_PKG := github.com/golangci/golangci-lint/cmd/golangci-lint
GOACC_PKG := github.com/ory/go-acc
GOIMPORTS_PKG := golang.org/x/tools/cmd/goimports

GOPATH ?= $(shell go env GOPATH)
GO_BIN := $(GOPATH)/bin
LINT_BIN := $(GO_BIN)/golangci-lint
GOACC_BIN := $(GO_BIN)/go-acc

LINT_COMMIT := v1.18.0
GOACC_COMMIT := 80342ae2e0fcf265e99e76bcc4efd022c7c3811b

GOINSTALL := GO111MODULE=on go install -v
GOBUILD := GO111MODULE=on go build -v
DEV_TAGS := rpctest
GOTEST_DEV = GO111MODULE=on go test -v -tags=$(DEV_TAGS)
GOTEST := GO111MODULE=on go test -v

GOFILES_NOVENDOR = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

RM := rm -f
CP := cp
MAKE := make
XARGS := xargs -L 1

# Linting uses a lot of memory, so keep it under control by limiting the number
# of workers if requested.
ifneq ($(workers),)
LINT_WORKERS = --concurrency=$(workers)
endif

LINT = $(LINT_BIN) run -v $(LINT_WORKERS)

GREEN := "\\033[0;32m"
NC := "\\033[0m"
define print
	echo $(GREEN)$1$(NC)
endef

default: build

all: build check

# ============
# DEPENDENCIES
# ============

$(LINT_BIN):
	@$(call print, "Fetching linter")
	$(GOINSTALL) $(LINT_PKG)@$(LINT_COMMIT)

$(GOACC_BIN):
	@$(call print, "Fetching go-acc")
	$(GOINSTALL) $(GOACC_PKG)@$(GOACC_COMMIT)

goimports:
	@$(call print, "Installing goimports.")
	$(GOINSTALL) $(GOIMPORTS_PKG)

# ============
# INSTALLATION
# ============

build:
	@$(call print, "Building all binaries")
	$(GOBUILD) $(PKG)
	$(GOBUILD) $(PKG)/cmd/ltcctl
	$(GOBUILD) $(PKG)/cmd/gencerts
	$(GOBUILD) $(PKG)/cmd/findcheckpoint
	$(GOBUILD) $(PKG)/cmd/addblock

# =======
# TESTING
# =======

check: unit

unit:
	@$(call print, "Running unit tests.")
	$(GOTEST_DEV) ./... -test.timeout=20m
	cd btcec; $(GOTEST_DEV) ./... -test.timeout=20m
	cd ltcutil; $(GOTEST_DEV) ./... -test.timeout=20m
	cd ltcutil/psbt; $(GOTEST_DEV) ./... -test.timeout=20m

unit-cover:
	@$(call print, "Running unit coverage tests.")
	$(GOINSTALL) $(GOACC_PKG)@$(GOACC_COMMIT)
	$(GO_BIN)/go-acc ./...

	cd btcec; $(GO_BIN)/go-acc ./...; sed -i.bak 's/v2\///g' coverage.txt
	cd ltcutil; $(GO_BIN)/go-acc ./...
	cd ltcutil/psbt; $(GO_BIN)/go-acc ./...

unit-race:
	@$(call print, "Running unit race tests.")
	env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(GOTEST) -race -test.timeout=20m ./...
	cd btcec; env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(GOTEST) -race -test.timeout=20m ./...
	cd ltcutil; env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(GOTEST) -race -test.timeout=20m ./...
	cd ltcutil/psbt; env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(GOTEST) -race -test.timeout=20m ./...

# =========
# UTILITIES
# =========

fmt: goimports
	@$(call print, "Fixing imports.")
	goimports -w $(GOFILES_NOVENDOR)
	@$(call print, "Formatting source.")
	gofmt -l -w -s $(GOFILES_NOVENDOR)

lint: $(LINT_BIN)
	@$(call print, "Linting source.")
	$(LINT)

clean:
	@$(call print, "Cleaning source.$(NC)")
	$(RM) coverage.txt btcec/coverage.txt ltcutil/coverage.txt ltcutil/psbt/coverage.txt

.PHONY: all \
	default \
	build \
	check \
	unit \
	unit-cover \
	unit-race \
	fmt \
	lint \
	clean
