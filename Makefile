# Console-IR Makefile
.PHONY: help build clean test run-dev run-prod install deps lint fmt vet security plugins docker-up docker-down setup-dev

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
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Go configuration
export CGO_ENABLED=1
export GOOS=$(shell go env GOOS)
export GOARCH=$(shell go env GOARCH)

# Docker Compose detection - prefer v2 (docker compose) over v1 (docker-compose)
DOCKER_COMPOSE := $(shell if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then echo "docker compose"; elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; else echo ""; fi)

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

## Runtime targets

run-dev: docker-up ## Run in development mode
	@echo "Starting Console-IR in development mode..."
	@sleep 2  # Wait for Redis to be ready
	go run . serve --log-level debug

run-prod: build docker-up ## Run in production mode
	@echo "Starting Console-IR in production mode..."
	@sleep 2  # Wait for Redis to be ready
	$(BUILD_DIR)/$(BINARY_NAME) serve

run-headless: build docker-up ## Run in headless mode (no TUI)
	@echo "Starting Console-IR in headless mode..."
	@sleep 2  # Wait for Redis to be ready
	$(BUILD_DIR)/$(BINARY_NAME) serve --no-tui

## Docker targets

docker-up: ## Start Redis and supporting services
	@if [ -z "$(DOCKER_COMPOSE)" ]; then \
		echo "Error: Neither 'docker compose' nor 'docker-compose' found. Please install Docker Compose."; \
		exit 1; \
	fi
	@echo "Starting Docker services using: $(DOCKER_COMPOSE)"
	$(DOCKER_COMPOSE) up -d redis
	@echo "Waiting for Redis to be ready..."
	@for i in $$(seq 1 30); do \
		if $(DOCKER_COMPOSE) exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then \
			echo "Redis is ready!"; \
			break; \
		fi; \
		if [ $$i -eq 30 ]; then \
			echo "Timeout waiting for Redis to be ready"; \
			exit 1; \
		fi; \
		echo "Waiting for Redis... ($$i/30)"; \
		sleep 1; \
	done

docker-down: ## Stop Docker services
	@if [ -z "$(DOCKER_COMPOSE)" ]; then \
		echo "Error: Neither 'docker compose' nor 'docker-compose' found. Please install Docker Compose."; \
		exit 1; \
	fi
	@echo "Stopping Docker services..."
	$(DOCKER_COMPOSE) down

docker-logs: ## Show Docker service logs
	@if [ -z "$(DOCKER_COMPOSE)" ]; then \
		echo "Error: Neither 'docker compose' nor 'docker-compose' found. Please install Docker Compose."; \
		exit 1; \
	fi
	$(DOCKER_COMPOSE) logs -f

docker-clean: docker-down ## Clean Docker resources
	@echo "Cleaning Docker resources..."
	$(DOCKER_COMPOSE) down -v --remove-orphans
	docker system prune -f

## Plugin targets

plugin-geoip: ## Build and run GeoIP plugin
	@echo "Building GeoIP plugin..."
	cd $(PLUGINS_DIR)/geoip && go build -o ../../$(BUILD_DIR)/geoip .
	@echo "Starting GeoIP plugin..."
	$(BUILD_DIR)/geoip --redis redis://localhost:6379

plugin-llm: ## Build and run LLM plugin
	@echo "Building LLM plugin..."
	cd $(PLUGINS_DIR)/llm && go build -o ../../$(BUILD_DIR)/llm .
	@echo "LLM plugin built successfully!"
	@echo ""
	@echo "Usage examples:"
	@echo "  OpenAI:  $(BUILD_DIR)/llm --api-key YOUR_OPENAI_KEY --provider openai --model gpt-3.5-turbo"
	@echo "  Claude:  $(BUILD_DIR)/llm --api-key YOUR_CLAUDE_KEY --provider claude --model claude-3-sonnet-20240229"
	@echo ""
	@echo "Environment variable: export LLM_API_KEY=your-key-here"
	@echo "Redis URL: --redis redis://localhost:6379 (default)"

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

plugin-whois: ## Build and run Whois plugin
	@echo "Building Whois plugin..."
	cd $(PLUGINS_DIR)/whois && go build -o ../../$(BUILD_DIR)/whois .
	@echo "Starting Whois plugin..."
	$(BUILD_DIR)/whois --redis redis://localhost:6379

## Sample data targets

sample-events: ## Generate sample OCSF events
	@echo "Generating sample events..."
	@mkdir -p ./testdata
	@echo '{"time": "2024-01-15T10:30:00Z", "class_uid": 4001, "category_uid": 4, "activity_id": 1, "type_uid": 400101, "severity_id": 2, "message": "Network connection established", "src_endpoint": {"ip": "192.168.1.100", "port": 54321}, "dst_endpoint": {"ip": "8.8.8.8", "port": 53}, "device": {"hostname": "workstation-01", "ip": "192.168.1.100"}, "metadata": {"product": {"name": "Console-IR", "vendor": "OCSF"}}}' > ./testdata/sample-events.jsonl
	@echo '{"time": "2024-01-15T10:31:00Z", "class_uid": 1001, "category_uid": 1, "activity_id": 1, "type_uid": 100101, "severity_id": 3, "message": "Process execution detected", "process": {"name": "powershell.exe", "pid": 1234, "cmd_line": "powershell.exe -ExecutionPolicy Bypass"}, "device": {"hostname": "workstation-01"}, "user": {"name": "john.doe"}, "metadata": {"product": {"name": "Console-IR", "vendor": "OCSF"}}}' >> ./testdata/sample-events.jsonl
	@echo '{"time": "2024-01-15T10:32:00Z", "class_uid": 2001, "category_uid": 2, "activity_id": 2, "type_uid": 200102, "severity_id": 4, "message": "Suspicious file created", "file": {"name": "malware.exe", "path": "C:\\temp\\malware.exe", "hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}, "device": {"hostname": "workstation-01"}, "metadata": {"product": {"name": "Console-IR", "vendor": "OCSF"}}}' >> ./testdata/sample-events.jsonl
	@echo '{"time": "2024-01-15T10:33:00Z", "class_uid": 3001, "category_uid": 3, "activity_id": 1, "type_uid": 300101, "severity_id": 2, "message": "User authentication successful", "user": {"name": "jane.smith", "domain": "corporate.com"}, "device": {"hostname": "server-01", "ip": "192.168.1.200"}, "src_endpoint": {"ip": "192.168.1.150"}, "metadata": {"product": {"name": "Console-IR", "vendor": "OCSF"}}}' >> ./testdata/sample-events.jsonl
	@echo "Sample events created in ./testdata/sample-events.jsonl"

ingest-sample: sample-events build ## Ingest sample events
	@echo "Ingesting sample events..."
	$(BUILD_DIR)/$(BINARY_NAME) ingest ./testdata/sample-events.jsonl

demo: build-all docker-up ingest-sample ## Run full demo (build, start services, ingest data)
	@echo "Demo setup complete!"
	@echo "You can now run: make run-dev"

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

status: ## Show service status
	@echo "=== Docker Services ==="
	@if [ -n "$(DOCKER_COMPOSE)" ]; then \
		$(DOCKER_COMPOSE) ps 2>/dev/null || echo "Docker Compose not running"; \
	else \
		echo "Docker Compose not found"; \
	fi
	@echo ""
	@echo "=== Redis Status ==="
	@if [ -n "$(DOCKER_COMPOSE)" ]; then \
		$(DOCKER_COMPOSE) exec redis redis-cli ping 2>/dev/null || echo "Redis not accessible"; \
	else \
		echo "Docker Compose not found"; \
	fi
	@echo ""
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
dev: setup-dev build-all docker-up ## Complete development setup
quick: build run-dev ## Quick build and run
reset: clean docker-clean setup-dev ## Reset everything and start fresh