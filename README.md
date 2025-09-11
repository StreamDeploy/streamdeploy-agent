# StreamDeploy Agent - Go Implementation

The Go implementation provides better maintainability, cross-platform compatibility, and modular architecture.

## Architecture

The Go implementation follows a modular architecture with clear separation between:

- **Core functionality** (`pkg/core/`) - Core components and interfaces
- **Full Go implementations** (`pkg/agent/`) - Feature implementations
- **Command-line tools** (`cmd/`) - Agent and installer executables

### Core Components

Located in `pkg/core/`, these components provide the foundation:

- **`types/`** - Interface definitions and data structures
- **`config/`** - Configuration management with file parsing
- **`utils/`** - Logging and utility functions
- **`agent/`** - Core agent logic and orchestration

### Full Go Components

Located in `pkg/agent/`, these require the full Go runtime:

- **`https/`** - HTTPS client with mTLS support
- **`metrics/`** - System metrics collection
- **`mqtt/`** - MQTT client (planned)
- **`container/`** - Docker container management (planned)
- **`package/`** - System package management (planned)

## Building

### Prerequisites

- Go 1.21 or later
- Docker (for containerized builds)

### Using Make

```bash
# Build all binaries
make build

# Build only the agent
make agent

# Build only the installer
make installer


# Run tests
make test

# Clean build artifacts
make clean
```

### Manual Build

```bash
# Build agent
go build -o bin/streamdeploy-agent ./cmd/agent

# Build installer
go build -o bin/streamdeploy-installer ./cmd/installer

```

### Docker Build

```bash
# Using the provided Makefile
make docker-build

# Or manually
docker build -t streamdeploy-agent:latest .
```

## Installation

### Using the Installer

```bash
# Download and run the installer with a bootstrap token
sudo ./streamdeploy-installer <bootstrap-token>

# Or set the token as an environment variable
export SD_BOOTSTRAP_TOKEN="your-bootstrap-token"
sudo ./streamdeploy-installer
```

### Manual Installation

```bash
# Install binaries
sudo make install

# Create configuration directories
sudo mkdir -p /etc/streamdeploy/pki
sudo mkdir -p /var/lib/streamdeploy

# Copy configuration files
sudo cp config/agent.json /etc/streamdeploy/
sudo cp config/state.json /etc/streamdeploy/
```

## Configuration

### Device Configuration (`/etc/streamdeploy/agent.json`)

```json
{
  "device_id": "your-device-id",
  "enroll_base_url": "https://api.streamdeploy.com",
  "https_mtls_endpoint": "https://device.streamdeploy.com",
  "mqtt_ws_mtls_endpoint": "https://mqtt.streamdeploy.com",
  "pki_dir": "/etc/streamdeploy/pki",
  "os_name": "ubuntu",
  "os_version": "22.04",
  "architecture": "x86_64"
}
```

### State Configuration (`/etc/streamdeploy/state.json`)

```json
{
  "schemaVersion": "1.0",
  "agent_setting": {
    "heartbeat_frequency": "15s",
    "update_frequency": "30s",
    "mode": "http",
    "agent_ver": "1"
  },
  "containers": [],
  "packages": [],
  "custom_metrics": {},
  "env": {}
}
```

## Running

### As a Service (Recommended)

```bash
# Start the service
sudo systemctl start streamdeploy-agent

# Enable auto-start
sudo systemctl enable streamdeploy-agent

# Check status
sudo systemctl status streamdeploy-agent

# View logs
sudo journalctl -u streamdeploy-agent -f
```

### Manual Execution

```bash
# Run with default config
sudo ./streamdeploy-agent

# Run with custom config
sudo ./streamdeploy-agent /path/to/config.json
```

## Development

### Project Structure

```
streamdeploy-agent/
├── cmd/                    # Command-line applications
│   ├── agent/             # Main agent executable
│   └── installer/         # Installation tool
├── pkg/                   # Go packages
│   ├── core/             # Core components
│   │   ├── agent/        # Core agent logic
│   │   ├── config/       # Configuration management
│   │   ├── types/        # Interface definitions
│   │   └── utils/        # Utilities and logging
│   └── agent/            # Full Go implementations
│       ├── https/        # HTTPS client
│       ├── metrics/      # Metrics collection
│       └── ...           # Other components
├── config/               # Sample configurations
├── Makefile             # Build automation
├── go.mod               # Go module definition
└── README-GO.md         # This file
```

### Development Environment

The project includes a VS Code devcontainer configuration for Go development:

```bash
# Open in VS Code with devcontainer
code .
# Then: "Reopen in Container"
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Adding New Components

1. **Core Components**: Add to `pkg/core/`
2. **Feature Implementations**: Add to `pkg/agent/`
3. **Define interfaces** in `pkg/core/types/`
4. **Update the core agent** to use new components

## Migration from C++

The Go implementation maintains compatibility with the C++ version:

- **Configuration files** are identical
- **API endpoints** and protocols remain the same
- **Certificate management** follows the same patterns
- **System integration** (systemd, etc.) is preserved

### Key Improvements

- **Better error handling** with Go's error system
- **Improved logging** with structured logging
- **Enhanced testing** with Go's testing framework
- **Cross-platform builds** without complex build systems
- **Memory safety** with Go's garbage collector
- **Concurrent operations** with goroutines

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure running as root/sudo
2. **Config not found**: Check file paths and permissions
3. **Certificate errors**: Verify PKI directory and certificates
4. **Network issues**: Check firewall and endpoint connectivity

### Debug Mode

```bash
# Enable verbose logging
export LOG_LEVEL=debug
sudo ./streamdeploy-agent
```

### Log Locations

- **Systemd service**: `journalctl -u streamdeploy-agent`
- **Manual execution**: stdout/stderr
- **Syslog**: `/var/log/syslog` (if configured)

## Contributing

1. Follow Go conventions and best practices
2. Maintain clean architecture and interfaces
3. Add tests for new functionality
4. Update documentation as needed
5. Ensure cross-platform compatibility

## License

This project maintains the same license as the original C++ implementation.
