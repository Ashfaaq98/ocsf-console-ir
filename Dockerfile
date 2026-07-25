FROM golang:1.23-alpine AS builder

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN apk add --no-cache git make

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
  -trimpath \
  -ldflags "-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_DATE}" \
  -o /bin/console-ir \
  ./main.go

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/Ashfaaq98/ocsf-console-ir"
LABEL org.opencontainers.image.description="Terminal-first OCSF-native incident response manager for security analysts"
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"

COPY --from=builder /bin/console-ir /console-ir

VOLUME ["/data"]
WORKDIR /data

# Console-IR is a terminal-first (TUI) tool. Headless/containerized serving is
# EXPERIMENTAL: folder ingestion and enrichment currently run only with the TUI
# active, so a headless `serve` does not yet process events. The default command
# therefore shows help rather than silently starting a server that does nothing.
#
# To experiment with headless HTTP ingest (writes payloads to /data/incoming for
# a future headless pipeline), a bearer token is required on a non-loopback bind:
#   docker run -e INGEST_TOKEN=secret -p 8080:8080 <image> \
#     serve --no-tui --http-ingest-enable --http-ingest-bind 0.0.0.0:8080
ENTRYPOINT ["/console-ir"]
CMD ["--help"]
