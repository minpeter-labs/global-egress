BINARY  := global-egress
PKG     := ./cmd/global-egress
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

# Local development config; ignored by git.
LOCAL_CONFIG ?= config.local.yaml

.PHONY: all build install test check fmt vet tidy clean run probe inspect

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

fmt:
	gofmt -w $(shell find cmd internal -name '*.go')

fmtcheck:
	@unformatted="$$(gofmt -l $$(find cmd internal -name '*.go'))"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; echo "$$unformatted"; exit 1; \
	fi

tidy:
	go mod tidy

check: fmtcheck vet test

run: build
	./bin/$(BINARY) serve -config $(LOCAL_CONFIG)

inspect: build
	./bin/$(BINARY) inspect -catalog $(CATALOG)

probe: build
	./bin/$(BINARY) probe -catalog $(CATALOG) -limit $(or $(LIMIT),25) -concurrency $(or $(CONCURRENCY),8)

clean:
	rm -rf bin dist
