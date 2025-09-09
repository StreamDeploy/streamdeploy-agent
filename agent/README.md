# StreamDeploy Agent

The StreamDeploy Agent is a lightweight, event-driven system monitoring and container management service that provides real-time device telemetry and remote management capabilities.

## Architecture

The agent uses a modular, multi-threaded architecture with the following core components:

### Core Components

- **ConfigManager**: Handles configuration file monitoring with inotify for real-time updates
- **MetricsCollector**: Collects system metrics (CPU, memory, disk) and custom metrics
- **ContainerManager**: Manages Docker containers with health checks and retry logic
- **PackageManager**: Handles system and custom package installation/verification
- **HttpsClient**: mTLS-enabled HTTPS communication client
- **CertificateManager**: Automatic certificate renewal and management
- **MqttClient**: MQTT WebSocket client (structure implemented, full implementation pending)

### Threading Model

The agent runs three separate threads:

1. **Heartbeat Thread**: Sends system metrics and health status at configurable intervals
2. **Update Thread**: Performs system updates, package management, and certificate renewal
3. **Config Monitor Thread**: Handles real-time configuration changes via inotify

## Configuration

### Device Configuration (`device.json`)

Contains static device information and endpoints:

```json
{
    "device_id": "orin01",
    "enroll_base_url": "https://api.streamdeploy.com",
    "https_mtls_endpoint": "https://device.streamdeploy.com",
    "mqtt_ws_mtls_endpoint": "https://mqtt.streamdeploy.com",
    "pki_dir": "/etc/streamdeploy/pki",
    "os_name": "ubuntu",
    "os_version": "22.04",
    "architecture": "x86_64",
    "package_manager": {
        "type": "apt",
        "install_cmd": "apt-get install -y",
        "check_cmd": "dpkg -l",
        "remove_cmd": "apt-get remove -y",
        "update_cmd": "apt-get update"
    }
}
```

### State Configuration (`state.json`)

Contains dynamic state and operational parameters:

```json
{
    "schemaVersion": "1.0",
    "agent_setting": {
        "heartbeat_frequency": "15s",
        "update_frequency": "30s",
        "mode": "http",
        "agent_ver": "1"
    },
    "containers": [
        {
            "name": "sd-app",
            "image": "ghcr.io/streamdeploy/streamdeploy-app:latest",
            "port": 80,
            "health_path": "/health",
            "env": {}
        }
    ],
    "packages": [
        "curl", 
        "openssl",
        "ca-certificates",
        "systemd",
        "docker"
    ],
    "custom_metrics": {
        "temperature": "cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{print $1/1000}' || echo '0'",
        "disk_usage": "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'",
        "uptime": "uptime | awk '{print $3}' | sed 's/,//'"
    },
    "custom_packages": {
        "whatever-v1.2": {
            "install": "curl -fsSL https://whatever.com/install.sh | sudo sh",
            "check": "whatever --version",
            "uninstall": "sudo whatever --uninstall"
        }
    }
}
```

## Frequency Format

The agent supports flexible frequency specifications:

- `s` - seconds
- `m` - minutes  
- `h` - hours
- `d` - days
- `w` - weeks
- `M` - months (30 days)
- `y` - years (365 days)

Examples: `15s`, `5m`, `1h`, `7d`

## Communication Modes

### HTTPS Mode (Implemented)

Uses mTLS for secure communication with the following endpoints:

- **Heartbeat**: `POST /v1-device/heartbeat`
  ```json
  {
    "status": "normal|degraded",
    "agent_setting": { ... },
    "metrics": {
      "cpu_pct": 25.5,
      "mem_pct": 60.2,
      "disk_pct": 45.0,
      "custom_metric": "value"
    }
  }
  ```

- **Status Update**: `POST /v1-device/status-update`
  ```json
  {
    "update_type": "update_check",
    "current_state": { ... }
  }
  ```

- **Certificate Renewal**: `POST /v1-device/enroll/renew`
  ```json
  {
    "csr_base64": "base64-encoded-csr"
  }
  ```

### MQTT Mode (Structure Only)

MQTT WebSocket communication with topics:
- `device/{device_id}/heartbeat`
- `device/{device_id}/status-update`
- `device/{device_id}/commands`

## System Monitoring

### Health Status Determination

The agent determines system status as "normal" or "degraded" based on:

- **CPU Usage** > 90%
- **Memory Usage** > 90%
- **Disk Usage** > 90%
- **Container Health** - Any container failing health checks

### Container Health Checks

For containers with `health_path` configured, the agent performs HTTP health checks:
- Timeout: 5 seconds
- Success: HTTP 2xx response
- Retry logic: 2 attempts for failed operations

## Package Management

### System Packages

Uses package manager commands from `device.json` to:
- Check if packages are installed
- Install missing packages
- Remove unwanted packages

### Custom Packages

Supports custom installation scripts with:
- `install`: Command to install the package
- `check`: Command to verify installation
- `uninstall`: Command to remove the package

## Certificate Management

Automatic certificate renewal when certificates are within 30 days of expiration:

1. Generate new private key and CSR
2. Submit CSR to renewal endpoint
3. Save new certificate and chain
4. Update HTTPS client configuration

## File Monitoring

Uses Linux inotify to monitor configuration files for changes:
- `device.json` - Reloads device configuration
- `state.json` - Reloads operational state
- Automatic client reconfiguration on changes

## Dependencies

### Build Dependencies
- CMake 3.16+
- GCC 9+ or Clang 10+
- pkg-config

### Runtime Dependencies
- libcurl4-openssl-dev
- nlohmann-json3-dev
- libssl-dev
- Docker (for container management)

## Installation

1. Build the agent:
   ```bash
   cd agent
   ./build.sh
   ```

2. Install systemd service:
   ```bash
   sudo cp streamdeploy-agent /usr/local/bin/
   sudo systemctl enable streamdeploy-agent
   sudo systemctl start streamdeploy-agent
   ```

3. Check status:
   ```bash
   systemctl status streamdeploy-agent
   journalctl -u streamdeploy-agent -f
   ```

## Usage

```bash
# Run with default config
./streamdeploy-agent

# Run with custom config
./streamdeploy-agent /path/to/agent.json

# Run in foreground for debugging
./streamdeploy-agent /etc/streamdeploy/agent.json
```

## Logging

The agent logs to:
- **stdout/stderr**: Real-time console output
- **systemd journal**: When run as service

Log levels:
- `[INFO]`: Normal operations
- `[ERROR]`: Error conditions
- `[ConfigManager]`: Configuration changes
- `[MetricsCollector]`: Metrics collection
- `[ContainerManager]`: Container operations

## Troubleshooting

### Common Issues

1. **Certificate errors**: Check PKI directory permissions and certificate validity
2. **Container failures**: Verify Docker daemon is running and images are accessible
3. **Config monitoring**: Ensure inotify limits are sufficient (`fs.inotify.max_user_watches`)
4. **Network issues**: Verify endpoints are reachable and certificates are valid

### Debug Mode

Run the agent in foreground to see detailed logging:
```bash
sudo ./streamdeploy-agent /etc/streamdeploy/agent.json
```

## Development

### Building from Source

```bash
git clone https://github.com/StreamDeploy/streamdeploy-agent.git
cd streamdeploy-agent/agent
./build.sh
```

### Testing

The agent can be tested with local configuration files:

```bash
# Create test config
mkdir -p test-config
cp config/agent.json test-config/
cp config/state.json test-config/

# Run with test config
./streamdeploy-agent test-config/agent.json
```

## License

See LICENSE file in the repository root.
