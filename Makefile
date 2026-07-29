# Console-IR Makefile
.PHONY: help build build-plugins build-all clean test check run-dev run-prod run-headless install deps lint fmt vet security setup-dev demo

# Default target
help: ## Show this help message
	@echo "Console-IR - Terminal-first OCSF-based incident response manager"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build configuration
BINARY_NAME=console-ir
BUILD_DIR=./bin
PLUGINS_DIR=./plugins
GO_FILES=$(shell find . -name "*.go" -type f -not -path "./vendor/*")
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Go configuration
export CGO_ENABLED=1
export GOOS=$(shell go env GOOS)
export GOARCH=$(shell go env GOARCH)

## Development targets

setup-dev: ## Set up development environment
	@echo "Setting up development environment..."
	go mod download
	go mod tidy
	mkdir -p $(BUILD_DIR)
	mkdir -p $(PLUGINS_DIR)
	@echo "Development environment ready!"

deps: ## Download and verify dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod verify
	go mod tidy

build: deps ## Build the main application
	@echo "Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)"

build-plugins: ## Build all plugins
	@echo "Building plugins..."
	@for plugin in $(shell find $(PLUGINS_DIR) -name "main.go" -exec dirname {} \;); do \
		plugin_name=$$(basename $$plugin); \
		echo "Building plugin: $$plugin_name"; \
		cd $$plugin && go build -o ../../$(BUILD_DIR)/$$plugin_name . && cd ../..; \
	done
	@echo "Plugins built successfully"

build-all: build build-plugins ## Build application and all plugins

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	go clean -cache
	go clean -testcache
	@echo "Clean complete"

## Testing targets

test: ## Run tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests with coverage report
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-integration: ## Run integration tests (requires Redis)
	@echo "Running integration tests..."
	go test -v -tags=integration ./...

## Code quality targets

lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run ./...

fmt: ## Format code
	@echo "Formatting code..."
	gofmt -s -w $(GO_FILES)
	goimports -w $(GO_FILES)

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

security: ## Run security checks
	@echo "Running security checks..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

check: fmt vet lint test ## Run all code quality checks

GORELEASER_VERSION ?= v2.17.1

release-check: ## Validate the whole release pipeline without pushing a tag (SKIP=docker to skip images)
	@command -v goreleaser >/dev/null 2>&1 || { \
		echo "goreleaser not found. Install the pinned version with:"; \
		echo "  go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)"; \
		exit 1; \
	}
	@command -v syft >/dev/null 2>&1 || { \
		echo "syft not found (the SBOM step needs it). Install with:"; \
		echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b $$(go env GOPATH)/bin"; \
		exit 1; \
	}
	@echo "== Config lint =="
	@# Reported separately because 'check' exits non-zero on deprecation notices
	@# alone. The known deprecations (brews, dockers) are tracked in the roadmap;
	@# the snapshot below is the gate, and it parses the same config, so a genuine
	@# config error still fails this target.
	-@goreleaser check
	@echo "== Full snapshot (nothing is published) =="
	@echo "   Docker images need a running daemon; use 'make release-check SKIP=docker' without one."
	goreleaser release --snapshot --clean $(if $(SKIP),--skip=$(SKIP),)

## Runtime targets

run-dev: ## Run in development mode (standalone, no Redis)
	@echo "Starting Console-IR in development mode..."
	go run . serve --log-level debug

run-prod: build ## Build and run
	@echo "Starting Console-IR..."
	$(BUILD_DIR)/$(BINARY_NAME) serve

run-headless: build ## Run without the TUI (experimental: does not ingest yet)
	@echo "Starting Console-IR in headless mode..."
	$(BUILD_DIR)/$(BINARY_NAME) serve --no-tui

## Plugin targets
## Note: GeoIP and WHOIS enrichment are now built in (in-process, no Redis);
## see internal/enrich/. The remaining external plugins are threat-intel
## integrations that still run as separate Redis-based processes.

plugin-opencti: ## Build and run OpenCTI plugin
	@echo "Building OpenCTI plugin..."
	cd $(PLUGINS_DIR)/opencti && go build -o ../../$(BUILD_DIR)/opencti-plugin .
	@echo "OpenCTI plugin built successfully!"
	@echo ""
	@echo "Usage examples:"
	@echo "  Production: $(BUILD_DIR)/opencti-plugin --opencti-url https://opencti.company.com --token YOUR_TOKEN"
	@echo "  Development: $(BUILD_DIR)/opencti-plugin --opencti-url http://localhost:8080 --token dev-token"
	@echo "  Dry Run: $(BUILD_DIR)/opencti-plugin --dry-run"
	@echo ""
	@echo "Environment variables:"
	@echo "  export OPENCTI_URL=https://opencti.example.com"
	@echo "  export OPENCTI_TOKEN=your-api-token-here"
	@echo ""
	@echo "Configuration: See plugins/opencti/config.yaml for examples"

plugin-misp: ## Build and run MISP plugin
	@echo "Building MISP plugin..."
	cd $(PLUGINS_DIR)/misp && go build -o ../../$(BUILD_DIR)/misp-plugin .
	@echo "MISP plugin built successfully!"
	@echo ""
	@echo "Usage examples:"
	@echo "  Production: $(BUILD_DIR)/misp-plugin --misp-url https://misp.company.com --api-key YOUR_KEY"
	@echo "  Development: $(BUILD_DIR)/misp-plugin --misp-url http://localhost:8080 --api-key dev-key"
	@echo "  Dry Run: $(BUILD_DIR)/misp-plugin --dry-run"
	@echo ""
	@echo "Environment variables:"
	@echo "  export MISP_URL=https://misp.example.com"
	@echo "  export MISP_API_KEY=your-api-key-here"
	@echo ""
	@echo "Configuration: See plugins/misp/config.yaml for examples"

## Sample data / demo targets

ingest-sample: build ## Pre-load the shipped sample events into the store (no enrichment)
	@echo "Ingesting sample events..."
	$(BUILD_DIR)/$(BINARY_NAME) ingest ./examples/sample-events.jsonl

demo: build ## Stage the sample for the TUI, then show how to explore it
	@mkdir -p data/incoming
	@cp examples/sample-events.jsonl data/incoming/
	@echo "Sample staged in data/incoming/."
	@echo "Now run:  $(BUILD_DIR)/$(BINARY_NAME) serve"
	@echo "Open an event to see GeoIP/WHOIS enrichment (press 'r' to refresh)."

## Installation targets

install: build ## Install binary to system
	@echo "Installing $(BINARY_NAME)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "$(BINARY_NAME) installed to /usr/local/bin/"

uninstall: ## Uninstall binary from system
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "$(BINARY_NAME) uninstalled"

## Release targets

release-build: ## Build release binaries for multiple platforms
	@echo "Building release binaries..."
	@mkdir -p $(BUILD_DIR)/release
	
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-amd64 .
	
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-arm64 .
	
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-amd64 .
	
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-arm64 .
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-windows-amd64.exe .
	
	@echo "Release binaries built in $(BUILD_DIR)/release/"

## Utility targets

version: ## Show version information
	@echo "Console-IR Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Go Version: $(shell go version)"

status: ## Show build status
	@echo "=== Build Status ==="
	@if [ -f "$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		echo "Binary: $(BUILD_DIR)/$(BINARY_NAME) (built)"; \
		$(BUILD_DIR)/$(BINARY_NAME) --version 2>/dev/null || echo "Binary exists but version check failed"; \
	else \
		echo "Binary: Not built"; \
	fi

logs: ## Show application logs (if running in background)
	@echo "Showing recent logs..."
	@tail -f console-ir.log 2>/dev/null || echo "No log file found"

# Development workflow shortcuts
dev: setup-dev build-all ## Complete development setup
quick: build run-dev ## Quick build and run
reset: clean setup-dev ## Reset everything and start fresh
