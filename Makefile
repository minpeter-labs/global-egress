BINARY  := global-egress
PKG     := ./cmd/global-egress
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

# Local development config; ignored by git.
LOCAL_CONFIG ?= config.local.yaml

GOBIN := $(shell go env GOPATH)/bin
GOFILES := $(shell find cmd internal -name '*.go')

.PHONY: all build build-static install test race vet fmt fmtcheck lint tools tidy check run probe inspect relays clean

all: check build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

# Static build for copying into a container or LXC guest.
build-static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
		-ldflags "$(LDFLAGS) -s -w" -o dist/$(BINARY)-linux-amd64 $(PKG)

install: build
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

# gofumpt is a strict superset of gofmt, and goimports keeps the standard /
# external / local import groups tidy. Formatting is therefore checked with these
# rather than with gofmt directly.
fmt: tools
	$(GOBIN)/gofumpt -w $(GOFILES)
	$(GOBIN)/goimports -local github.com/minpeter-labs/global-egress -w $(GOFILES)

fmtcheck: tools
	@out="$$($(GOBIN)/gofumpt -l $(GOFILES); $(GOBIN)/goimports -local github.com/minpeter-labs/global-egress -l $(GOFILES))"; \
	if [ -n "$$out" ]; then \
		echo "formatting needed (run 'make fmt'):"; echo "$$out" | sort -u; exit 1; \
	fi

lint: tools
	$(GOBIN)/golangci-lint run ./...

# Pinned so CI and local runs agree.
tools:
	@command -v $(GOBIN)/gofumpt >/dev/null || go install mvdan.cc/gofumpt@v0.11.0
	@command -v $(GOBIN)/goimports >/dev/null || go install golang.org/x/tools/cmd/goimports@latest
	@command -v $(GOBIN)/golangci-lint >/dev/null || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2

tidy:
	go mod tidy

check: fmtcheck vet lint test

run: build
	./bin/$(BINARY) serve -config $(LOCAL_CONFIG)

inspect: build
	./bin/$(BINARY) inspect -catalog $(CATALOG)

relays: build
	./bin/$(BINARY) relays -cache .local-state/relays.json

probe: build
	./bin/$(BINARY) probe -catalog $(CATALOG) -limit $(or $(LIMIT),25) -concurrency $(or $(CONCURRENCY),8)

clean:
	rm -rf bin dist
