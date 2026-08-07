# syntax=docker/dockerfile:1

# Multi-stage build: static binary into a distroless image.
# Userspace WireGuard needs no /dev/net/tun, NET_ADMIN, or root.

ARG GO_VERSION=1.25.12

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath \
	-ldflags "-X main.version=${VERSION} -s -w" \
	-o /out/global-egress ./cmd/global-egress

# CA certs for Mullvad relay list and IP measurement; no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="global-egress" \
	org.opencontainers.image.description="Rotating WireGuard egress proxy (SOCKS5 + HTTP)" \
	org.opencontainers.image.source="https://github.com/minpeter/global-egress" \
	org.opencontainers.image.licenses="MIT"

USER nonroot:nonroot

# Paths match deploy/docker/config.example.yaml and the compose mounts.
VOLUME ["/var/lib/global-egress", "/catalog"]

EXPOSE 1080 3128 8080

COPY --from=build --chown=nonroot:nonroot /out/global-egress /usr/local/bin/global-egress

ENTRYPOINT ["/usr/local/bin/global-egress"]
CMD ["serve", "-config", "/etc/global-egress/config.yaml"]
