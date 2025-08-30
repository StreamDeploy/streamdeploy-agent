# StreamDeploy Agent

The StreamDeploy Agent is an open-source device agent that enables secure, automated deployment and management of containerized applications on edge devices. It provides secure enrollment, health monitoring, and remote management capabilities for IoT and edge computing deployments.

## Features

- 🔐 **Secure Enrollment** - mTLS-based device authentication and enrollment
- 📊 **Health Monitoring** - Real-time device metrics and status reporting
- 🚀 **Container Management** - Automated deployment and lifecycle management
- 🔄 **Auto-Updates** - Self-updating agent with rollback capabilities
- 🌐 **Multi-Architecture** - Supports x86_64, ARM64, and ARM32 devices
- 📱 **Remote Management** - Centralized device management through StreamDeploy platform

## Quick Start


### Installation

The easiest way to install the StreamDeploy agent is using our one-line installer:

```bash
# Set your bootstrap token (get this from the StreamDeploy dashboard)
export SD_BOOTSTRAP_TOKEN="your-bootstrap-token-here"

# Install and enroll the agent
curl -fsSL https://github.com/StreamDeploy/streamdeploy-agent/releases/latest/download/install.sh | sudo bash
```

### Manual Installation

1. **Download the latest release** for your architecture:
   ```bash
   # For x86_64
   wget https://github.com/StreamDeploy/streamdeploy-agent/releases/latest/download/streamdeploy-agent-linux-amd64
   
   # For ARM64 (Jetson, Raspberry Pi 4+)
   wget https://github.com/StreamDeploy/streamdeploy-agent/releases/latest/download/streamdeploy-agent-linux-arm64
   ```

2. **Install the binary**:
   ```bash
   chmod +x streamdeploy-agent-linux-*
   sudo mv streamdeploy-agent-linux-* /usr/local/bin/streamdeploy-agent
   ```

3. **Create configuration**:
   ```bash
   sudo mkdir -p /etc/streamdeploy
   echo '{"pki_dir":"/etc/streamdeploy/pki"}' | sudo tee /etc/streamdeploy/agent.json
   ```

4. **Install systemd service**:
   ```bash
   sudo curl -fsSL https://raw.githubusercontent.com/StreamDeploy/streamdeploy-agent/main/systemd/streamdeploy-agent.service \
     -o /etc/systemd/system/streamdeploy-agent.service
   sudo systemctl daemon-reload
   sudo systemctl enable streamdeploy-agent
   ```

5. **Enroll the device** (requires bootstrap token from StreamDeploy dashboard):
   ```bash
   # Get enrollment script and run it
   curl -fsSL https://api.streamdeploy.com/v1-app/enroll/enroll-device.sh | \
     sudo bash -s -- --token "your-bootstrap-token"
   ```

## Supported Platforms

### Hardware Architectures
- **x86_64** - Intel/AMD 64-bit processors
- **ARM64** - 64-bit ARM processors (Jetson, Raspberry Pi 4+, Apple Silicon)
- **ARM32** - 32-bit ARM processors (older Raspberry Pi models)

### Operating Systems
- **Ubuntu** 18.04+ (recommended)
- **Debian** 10+ 
- **Raspberry Pi OS**
- **NVIDIA Jetson Linux** (L4T)
- **Other Linux distributions** (manual build required)

### Tested Devices
- NVIDIA Jetson Orin Nano/NX/AGX
- NVIDIA Jetson Xavier NX/AGX
- NVIDIA Jetson Thor
- Raspberry Pi 4/5
- Rockchip RK3588 boards
- Generic x86_64 Linux systems

## Building from Source

### Prerequisites
- CMake 3.16+
- C++17 compatible compiler (GCC 7+, Clang 6+)
- libcurl development headers
- OpenSSL development headers

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libcurl4-openssl-dev libssl-dev
```

### Build Steps
```bash
git clone https://github.com/StreamDeploy/streamdeploy-agent.git
cd streamdeploy-agent
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

### Cross-Compilation
See [docs/cross-compilation.md](docs/cross-compilation.md) for cross-compilation instructions.

## Configuration

The agent uses a JSON configuration file located at `/etc/streamdeploy/agent.json`:

```json
{
  "pki_dir": "/etc/streamdeploy/pki",
  "api_base": "https://api.streamdeploy.com",
  "device_base": "https://device.streamdeploy.com",
  "heartbeat_interval": "30s",
  "update_check_interval": "5m",
  "log_level": "info",
  "ssh_tunnel_enabled": true,
  "ssh_bastion_host": "34.170.221.16"
}
```

### Secret Management

The agent supports secure secret management through provisioning-time injection from Google Cloud Secret Manager. Secrets can be provided via secure files with automatic fallback to configuration values:

```json
{
  "ssh_bastion_host": "34.170.221.16",
  "ssh_bastion_host_file": "/etc/streamdeploy/secrets/ssh_bastion_host",
  "bootstrap_token": "",
  "bootstrap_token_file": "/etc/streamdeploy/secrets/bootstrap_token"
}
```

See [Secret Management Documentation](docs/SECRET-MANAGEMENT.md) for detailed setup instructions.

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `pki_dir` | `/etc/streamdeploy/pki` | Directory for certificates and keys |
| `api_base` | `https://api.streamdeploy.com` | StreamDeploy API endpoint |
| `device_base` | `https://device.streamdeploy.com` | Device API endpoint |
| `heartbeat_interval` | `30s` | How often to send heartbeat |
| `update_check_interval` | `5m` | How often to check for updates |
| `log_level` | `info` | Logging level (debug, info, warn, error) |

## Management Commands

### Service Management
```bash
# Check agent status
sudo systemctl status streamdeploy-agent

# Start/stop/restart agent
sudo systemctl start streamdeploy-agent
sudo systemctl stop streamdeploy-agent
sudo systemctl restart streamdeploy-agent

# View logs
sudo journalctl -u streamdeploy-agent -f
```

### Agent Information
```bash
# Check agent version
streamdeploy-agent --version

# Test configuration
streamdeploy-agent --test-config

# Manual enrollment (with token)
streamdeploy-agent --enroll --token "your-bootstrap-token"
```

## Troubleshooting

### Common Issues

**Agent won't start**
```bash
# Check logs for errors
sudo journalctl -u streamdeploy-agent -n 50

# Verify configuration
streamdeploy-agent --test-config

# Check file permissions
ls -la /etc/streamdeploy/
```

**Enrollment fails**
```bash
# Verify network connectivity
curl -I https://api.streamdeploy.com/health

# Check token validity (tokens expire after 1 hour)
# Generate a new token from the StreamDeploy dashboard

# Verify system time is correct
timedatectl status
```

**Certificate issues**
```bash
# Remove old certificates and re-enroll
sudo rm -rf /etc/streamdeploy/pki
sudo systemctl restart streamdeploy-agent
```

### Getting Help

- 📖 **Documentation**: [docs.streamdeploy.com](https://docs.streamdeploy.com)
- 🐛 **Issues**: [GitHub Issues](https://github.com/StreamDeploy/streamdeploy-agent/issues)
- 💬 **Community**: [StreamDeploy Community](https://community.streamdeploy.com)
- 📧 **Support**: support@streamdeploy.com

## Development

### Project Structure
```
streamdeploy-agent/
├── src/                    # Source code
│   ├── main.cpp           # Entry point
│   ├── agent.cpp          # Main agent logic
│   ├── http_client.cpp    # HTTP client implementation
│   └── hal_*.cpp          # Hardware abstraction layers
├── config/                # Configuration examples
├── scripts/               # Build and utility scripts
├── systemd/               # Systemd service files
├── third_party/           # Vendored dependencies
└── docs/                  # Additional documentation
```

### Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Style
- Follow C++17 best practices
- Use clang-format for formatting
- Include unit tests for new features
- Update documentation as needed

## Security

### Reporting Security Issues
Please report security vulnerabilities to security@streamdeploy.com. Do not create public GitHub issues for security problems.

### Security Features
- mTLS authentication for all communications
- Certificate-based device identity
- Encrypted configuration storage
- Secure update mechanism with signature verification

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

**StreamDeploy Agent** - Secure, scalable edge device management  
Made with ❤️ by the StreamDeploy team
