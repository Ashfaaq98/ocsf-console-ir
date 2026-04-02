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
EXPOSE 8080

# VULN-9: When binding to 0.0.0.0, a bearer token is now required.
# Set INGEST_TOKEN when running: docker run -e INGEST_TOKEN=your-secret ...
ENV INGEST_TOKEN=""

ENTRYPOINT ["/console-ir"]
CMD ["serve", "--no-tui", "--http-ingest-enable", "--http-ingest-bind", "0.0.0.0:8080"]
