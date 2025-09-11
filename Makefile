# StreamDeploy Agent - Go Implementation
# Makefile for building agent and installer

.PHONY: all build clean test agent installer deps build-linux-arm64 build-linux-arm build-linux-riscv64 build-linux-amd64

# Go build settings
GO := go
BUILD_DIR := bin
AGENT_BINARY := streamdeploy-agent
INSTALLER_BINARY := streamdeploy-installer

# Build flags
GO_BUILD_FLAGS := -ldflags="-s -w"

# Default target
all: build

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Build all binaries for all architectures
build: $(BUILD_DIR) build-linux-arm64 build-linux-arm build-linux-riscv64 build-linux-amd64

# Build for Linux ARM64 (AArch64) - Jetson Orin, RK3588, Pi 4/5 64-bit, most modern SBCs
build-linux-arm64: $(BUILD_DIR)
	@echo "Building for Linux ARM64 (AArch64)..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(AGENT_BINARY)-linux-arm64 ./cmd/agent
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(INSTALLER_BINARY)-linux-arm64 ./cmd/installer

# Build for Linux ARM 32-bit - Pi Zero/2W, older Pi/ARMv7 boards
build-linux-arm: $(BUILD_DIR)
	@echo "Building for Linux ARM 32-bit (ARMv6)..."
	GOOS=linux GOARCH=arm GOARM=6 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(AGENT_BINARY)-linux-armv6 ./cmd/agent
	GOOS=linux GOARCH=arm GOARM=6 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(INSTALLER_BINARY)-linux-armv6 ./cmd/installer
	@echo "Building for Linux ARM 32-bit (ARMv7)..."
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(AGENT_BINARY)-linux-armv7 ./cmd/agent
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(INSTALLER_BINARY)-linux-armv7 ./cmd/installer

# Build for Linux RISC-V 64-bit - newer RISC-V SBCs (Milk-V, Lichee, etc.)
build-linux-riscv64: $(BUILD_DIR)
	@echo "Building for Linux RISC-V 64-bit..."
	GOOS=linux GOARCH=riscv64 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(AGENT_BINARY)-linux-riscv64 ./cmd/agent
	GOOS=linux GOARCH=riscv64 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(INSTALLER_BINARY)-linux-riscv64 ./cmd/installer

# Build for Linux AMD64 - x86_64 gateways/NVRs
build-linux-amd64: $(BUILD_DIR)
	@echo "Building for Linux AMD64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(AGENT_BINARY)-linux-amd64 ./cmd/agent
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(INSTALLER_BINARY)-linux-amd64 ./cmd/installer

# Build the full Go agent (for local development)
agent: $(BUILD_DIR)
	@echo "Building StreamDeploy Agent (local architecture)..."
	$(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(AGENT_BINARY) ./cmd/agent

# Build the installer (for local development)
installer: $(BUILD_DIR)
	@echo "Building StreamDeploy Installer (local architecture)..."
	$(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(INSTALLER_BINARY) ./cmd/installer


# Run tests
test:
	@echo "Running tests..."
	$(GO) test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Lint code (requires golangci-lint)
lint:
	@echo "Linting code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping lint"; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install binaries to system (requires sudo)
install: build
	@echo "Installing binaries to system..."
	sudo cp $(BUILD_DIR)/$(AGENT_BINARY) /usr/local/bin/
	sudo cp $(BUILD_DIR)/$(INSTALLER_BINARY) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(AGENT_BINARY)
	sudo chmod +x /usr/local/bin/$(INSTALLER_BINARY)
	@echo "Installation complete"

# Uninstall binaries from system (requires sudo)
uninstall:
	@echo "Uninstalling binaries from system..."
	sudo rm -f /usr/local/bin/$(AGENT_BINARY)
	sudo rm -f /usr/local/bin/$(INSTALLER_BINARY)
	@echo "Uninstallation complete"

# Development targets
dev-build: deps fmt test build

# Release build with all targets
release: clean deps fmt test build
	@echo "Release build complete"
	@echo "Binaries available in $(BUILD_DIR)/"
	@ls -la $(BUILD_DIR)/

# Docker build (if Dockerfile exists)
docker-build:
	@if [ -f Dockerfile ]; then \
		echo "Building Docker image..."; \
		docker build -t streamdeploy-agent:latest .; \
	else \
		echo "Dockerfile not found, skipping Docker build"; \
	fi

# Help target
help:
	@echo "StreamDeploy Agent Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all                 - Build all binaries for all architectures (default)"
	@echo "  build               - Build agent and installer for all architectures"
	@echo "  agent               - Build full Go agent only (local architecture)"
	@echo "  installer           - Build installer only (local architecture)"
	@echo ""
	@echo "Architecture-specific builds:"
	@echo "  build-linux-arm64   - Build for Linux ARM64 (AArch64) - Jetson, Pi 4/5, modern SBCs"
	@echo "  build-linux-arm     - Build for Linux ARM 32-bit (ARMv6/v7) - Pi Zero/2W, older Pi"
	@echo "  build-linux-riscv64 - Build for Linux RISC-V 64-bit - Milk-V, Lichee SBCs"
	@echo "  build-linux-amd64   - Build for Linux AMD64 - x86_64 gateways/NVRs"
	@echo ""
	@echo "Development targets:"
	@echo "  test                - Run tests"
	@echo "  test-coverage       - Run tests with coverage report"
	@echo "  fmt                 - Format code"
	@echo "  lint                - Lint code (requires golangci-lint)"
	@echo "  clean               - Clean build artifacts"
	@echo "  install             - Install binaries to system (requires sudo)"
	@echo "  uninstall           - Uninstall binaries from system (requires sudo)"
	@echo "  dev-build           - Development build (deps + fmt + test + build)"
	@echo "  release             - Release build (all targets)"
	@echo "  docker-build        - Build Docker image"
	@echo "  deps                - Install Go dependencies"
	@echo "  help                - Show this help message"
