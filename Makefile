.PHONY: build clean test coverage lint lint-mulint format vendor tidy

BINARY := shadowgate
BUILD_DIR := .
GO := go
GOFLAGS := -mod=vendor
CGO_ENABLED := 0

VERSION ?= $(shell git describe --tags 2>/dev/null || echo 0.1.0)
COMMIT ?= $(shell git describe --match=NeVeRmAtCh --always --abbrev=40 --dirty)
LDFLAGS := -s -w \
	-X github.com/ziyan/shadowgate/internal/version.version=$(VERSION) \
	-X github.com/ziyan/shadowgate/internal/version.commit=$(COMMIT)

build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(BINARY) ./command/

clean:
	rm -f $(BUILD_DIR)/$(BINARY)
	rm -rf coverage/

test:
	$(GO) test $(GOFLAGS) ./... -count=1 -timeout=2m

coverage:
	@mkdir -p coverage
	$(GO) test $(GOFLAGS) -coverprofile=coverage/coverage.out -covermode=atomic -count=1 -timeout=2m ./...
	$(GO) tool cover -html=coverage/coverage.out -o coverage/coverage.html
	$(GO) tool cover -func=coverage/coverage.out

lint: lint-mulint
	golangci-lint run ./...

# run mulint (mujin naming/convention linter); config lives at ./mulint.yaml.
# mulint is an internal tool, so skip with a note when it is not installed.
lint-mulint:
	@set -e; \
	if ! hash mulint >/dev/null 2>&1; then \
		echo "mulint not found on PATH; skipping (install from dev/mulint)"; \
		exit 0; \
	fi; \
	MULINT_CONFIG=$(CURDIR)/mulint.yaml GOFLAGS=$(GOFLAGS) mulint ./...

format:
	gofmt -s -w .
	goimports -w .

vendor:
	$(GO) mod tidy
	$(GO) mod vendor

tidy:
	$(GO) mod tidy
