# StreamDeploy Agent - Go Implementation

The Go implementation provides better maintainability, cross-platform compatibility, and modular architecture.

## Architecture

The Go implementation follows a modular architecture with clear separation between:

- **Core functionality** (`pkg/core/`) - Core components and interfaces
- **Full Go implementations** (`pkg/agent/`) - Feature implementations
- **Integrated installer** (`pkg/installer/`) - Self-installation and systemd registration
- **Command-line tools** (`cmd/`) - Combined agent with integrated installer

### Self-Installation Capabilities

The agent now includes integrated self-installation functionality:

- **Automatic detection** - Checks if installation is needed based on missing certificates
- **Self-copying** - Moves itself to secure location (`/usr/local/bin/`)
- **Systemd integration** - Automatically creates and registers systemd service
- **Certificate management** - Handles mTLS certificate exchange and storage
- **Dependency installation** - Installs required system packages
- **Secure cleanup** - Removes installer binary after successful installation

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

# Build only the agent (with integrated installer)
make agent

# Run tests
make test

# Clean build artifacts
make clean
```

### Manual Build

```bash
# Build agent (with integrated installer)
go build -o bin/streamdeploy-agent ./cmd/agent

# Build with musl for static linking (recommended for production)
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/streamdeploy-agent ./cmd/agent
```

### Docker Build

```bash
# Using the provided Makefile
make docker-build

# Or manually
docker build -t streamdeploy-agent:latest .
```

## Installation

### Self-Installation (Recommended)

The agent now includes integrated self-installation capabilities. Simply run the agent binary with a bootstrap token, and it will automatically:

1. **Detect system requirements** - Identifies OS, architecture, and package manager
2. **Install dependencies** - Installs required system packages (curl, ca-certificates, systemd, docker.io)
3. **Self-install** - Copies itself to `/usr/local/bin/streamdeploy-agent`
4. **Create configuration** - Generates device and state configuration files
5. **Exchange certificates** - Performs mTLS certificate enrollment with StreamDeploy servers
6. **Register systemd service** - Creates and enables systemd service for automatic startup
7. **Clean up** - Removes the installer binary after successful installation

```bash
# Download the appropriate binary for your architecture
# Then run with bootstrap token:
sudo ./streamdeploy-agent <bootstrap-token>

# Or set the token as an environment variable
export SD_BOOTSTRAP_TOKEN="your-bootstrap-token"
sudo ./streamdeploy-agent
```

The agent will automatically detect if it needs to run the installer flow based on missing certificates or configuration files.

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

### Automatic Service Management

The agent automatically manages its own systemd service:

- **Self-registration** - If not running under systemctl, the agent automatically registers itself as a systemd service
- **Secure installation** - Copies itself to `/usr/local/bin/streamdeploy-agent` with proper permissions
- **Service creation** - Creates systemd service file with security settings and proper dependencies
- **Auto-start** - Enables and starts the service for automatic startup on boot

### Service Management Commands

Once installed, you can manage the service using standard systemctl commands:

```bash
# Check service status
sudo systemctl status streamdeploy-agent

# Start the service
sudo systemctl start streamdeploy-agent

# Stop the service
sudo systemctl stop streamdeploy-agent

# Restart the service
sudo systemctl restart streamdeploy-agent

# Enable auto-start on boot
sudo systemctl enable streamdeploy-agent

# Disable auto-start on boot
sudo systemctl disable streamdeploy-agent

# View logs
sudo journalctl -u streamdeploy-agent -f

# View recent logs
sudo journalctl -u streamdeploy-agent --since "1 hour ago"
```

### Manual Execution (Development/Testing)

For development or testing purposes, you can run the agent manually:

```bash
# Run with default config (will auto-install if needed)
sudo ./streamdeploy-agent

# Run with custom config
sudo ./streamdeploy-agent /path/to/config.json

# Run with bootstrap token for installation
sudo ./streamdeploy-agent <bootstrap-token>
```

**Note**: Manual execution will trigger the installer flow if certificates are missing, and the agent will automatically register itself as a systemd service.

## Security

### Secure Installation Process

The agent implements a secure self-installation process with multiple security layers:

#### 1. **Secure Binary Placement**
- Agent copies itself to `/usr/local/bin/streamdeploy-agent` with proper permissions (755)
- Ensures the binary is in a standard, secure system location
- Removes the original installer binary after successful installation

#### 2. **Certificate Management**
- **mTLS Authentication** - Uses mutual TLS for secure communication with StreamDeploy servers
- **SPIFFE Identity** - Implements SPIFFE (Secure Production Identity Framework for Everyone) for device identity
- **Certificate Storage** - Stores certificates in `/etc/streamdeploy/pki/` with restricted permissions (600 for private keys, 644 for certificates)
- **Automatic Renewal** - Built-in certificate renewal before expiration

#### 3. **Systemd Security Settings**
The systemd service includes security hardening:
```ini
# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/streamdeploy /var/lib/streamdeploy /var/log
```

#### 4. **Bootstrap Token Security**
- **JWT-based** - Uses JSON Web Tokens for secure bootstrap authentication
- **Device ID Extraction** - Extracts device ID from JWT claims for secure enrollment
- **One-time Use** - Bootstrap tokens are designed for single-use enrollment

#### 5. **File System Security**
- **Restricted Permissions** - Private keys stored with 600 permissions (owner read/write only)
- **Directory Isolation** - Configuration and certificates stored in dedicated directories
- **Root Execution** - Requires root privileges for installation and systemd registration

#### 6. **Network Security**
- **HTTPS Only** - All communication uses HTTPS with certificate validation
- **Certificate Pinning** - Uses CA certificates for server validation
- **Timeout Protection** - Implements request timeouts to prevent hanging connections

### Security Best Practices

1. **Always use HTTPS** - Ensure all endpoints use valid SSL/TLS certificates
2. **Secure bootstrap tokens** - Keep bootstrap tokens confidential and use them only once
3. **Regular updates** - Keep the agent updated to the latest version
4. **Monitor logs** - Regularly check systemd logs for any security issues
5. **Network isolation** - Consider network-level security for additional protection

## Development

### Project Structure

```
streamdeploy-agent/
├── cmd/                    # Command-line applications
│   └── agent/             # Main agent executable (with integrated installer)
├── pkg/                   # Go packages
│   ├── core/             # Core components
│   │   ├── agent/        # Core agent logic
│   │   ├── config/       # Configuration management
│   │   ├── types/        # Interface definitions
│   │   └── utils/        # Utilities and logging
│   ├── agent/            # Full Go implementations
│   │   ├── https/        # HTTPS client
│   │   ├── metrics/      # Metrics collection
│   │   └── ...           # Other components
│   └── installer/        # Self-installation and systemd registration
├── config/               # Sample configurations
├── Makefile             # Build automation
├── go.mod               # Go module definition
└── README.md            # This file
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



## Troubleshooting

### Common Issues

#### Installation Issues

1. **Permission denied**: Ensure running as root/sudo
   ```bash
   sudo ./streamdeploy-agent <bootstrap-token>
   ```

2. **Bootstrap token invalid**: Verify token format and expiration
   - Token should be a valid JWT
   - Check if token has expired
   - Ensure token contains `device_id` claim

3. **Network connectivity**: Check firewall and endpoint connectivity
   ```bash
   # Test connectivity to StreamDeploy servers
   curl -I https://api.streamdeploy.com
   curl -I https://device.streamdeploy.com
   ```

4. **Package installation fails**: Check package manager availability
   ```bash
   # Check if package manager is available
   which apt-get yum apk pacman
   ```

#### Runtime Issues

1. **Service not starting**: Check systemd service status
   ```bash
   sudo systemctl status streamdeploy-agent
   sudo journalctl -u streamdeploy-agent -f
   ```

2. **Certificate errors**: Verify PKI directory and certificates
   ```bash
   # Check certificate files exist
   ls -la /etc/streamdeploy/pki/
   
   # Check certificate validity
   openssl x509 -in /etc/streamdeploy/pki/device.crt -text -noout
   ```

3. **Config not found**: Check file paths and permissions
   ```bash
   # Verify config files exist
   ls -la /etc/streamdeploy/
   
   # Check file permissions
   ls -la /etc/streamdeploy/agent.json
   ```

4. **Agent not auto-installing**: Check if already installed
   ```bash
   # Check if agent is already installed
   systemctl is-active streamdeploy-agent
   ls -la /usr/local/bin/streamdeploy-agent
   ```

### Debug Mode

```bash
# Enable verbose logging
export LOG_LEVEL=debug
sudo ./streamdeploy-agent

# Or with bootstrap token
sudo ./streamdeploy-agent <bootstrap-token>
```

### Log Locations

- **Systemd service**: `journalctl -u streamdeploy-agent`
- **Installation logs**: `journalctl -u streamdeploy-agent --since "1 hour ago"`
- **Manual execution**: stdout/stderr
- **Syslog**: `/var/log/syslog` (if configured)

### Service Management

```bash
# Check service status
sudo systemctl status streamdeploy-agent

# View recent logs
sudo journalctl -u streamdeploy-agent --since "1 hour ago"

# Restart service
sudo systemctl restart streamdeploy-agent

# Stop service
sudo systemctl stop streamdeploy-agent

# Start service
sudo systemctl start streamdeploy-agent
```

### Reinstallation

If you need to reinstall the agent:

```bash
# Stop and disable service
sudo systemctl stop streamdeploy-agent
sudo systemctl disable streamdeploy-agent

# Remove service file
sudo rm /etc/systemd/system/streamdeploy-agent.service

# Remove agent binary
sudo rm /usr/local/bin/streamdeploy-agent

# Remove configuration (optional - this will require new bootstrap token)
sudo rm -rf /etc/streamdeploy/

# Reload systemd
sudo systemctl daemon-reload

# Run installer again
sudo ./streamdeploy-agent <bootstrap-token>
```

## Contributing

1. Follow Go conventions and best practices
2. Maintain clean architecture and interfaces
3. Add tests for new functionality
4. Update documentation as needed
5. Ensure cross-platform compatibility

## License

This project maintains the same license as the original C++ implementation.
