# StreamDeploy Agent Installer

This directory contains the standalone installer for the StreamDeploy Agent, designed to work across different Linux distributions with musl static compilation for maximum portability.

## Files

- `streamdeploy-installer` - Main installer executable (created after build)
- `installer.cpp` - Installer source code
- `CMakeLists.txt` - Build configuration for musl static compilation
- `uninstall.sh` - Uninstaller script
- `README.md` - This documentation

## Building the Installer

The installer is built automatically when you run the main build script:

```bash
cd /path/to/streamdeploy-agent
./scripts/build.sh
```

This will:
1. Build the main StreamDeploy agent
2. Build the installer with musl static linking
3. Create the `streamdeploy-installer` executable in this directory

## Using the Installer

### Prerequisites

1. **Bootstrap Token**: Obtain a bootstrap token from the StreamDeploy platform
2. **Root Access**: The installer must be run as root (using sudo)
3. **Network Access**: Internet connection required for certificate exchange

### Installation

The installer supports two methods for providing the bootstrap token:

#### Method 1: Command Line Argument (Recommended)

```bash
# Run the installer with token as argument
sudo ./streamdeploy-installer "your-bootstrap-token-here"
```

#### Method 2: Environment Variable

```bash
# Set the bootstrap token as environment variable
export SD_BOOTSTRAP_TOKEN="your-bootstrap-token-here"

# Run the installer
sudo ./streamdeploy-installer
```

**Note**: If both methods are provided, the command line argument takes precedence.

### What the Installer Does

1. **System Detection**: Detects OS, architecture, and package manager
2. **Dependency Installation**: Installs required system packages
3. **JWT Processing**: Extracts device ID from the bootstrap token
4. **Agent Installation**: Downloads or builds the StreamDeploy agent
5. **Configuration**: Creates `/etc/streamdeploy/agent.json` with system info
6. **Certificate Exchange**: Performs PKI enrollment with the platform
7. **Service Setup**: Creates and starts the systemd service

### Generated Configuration

The installer creates `/etc/streamdeploy/agent.json` with the following structure:

```json
{
  "device_id": "extracted-from-jwt-token",
  "enroll_base_url": "https://api.streamdeploy.com",
  "device_base_url": "https://device.streamdeploy.com",
  "mqtt_base": "https://mqtt.streamdeploy.com",
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

### Certificate Management

The installer performs automatic certificate enrollment:

1. **Enrollment Start**: Contacts the API to get nonce and CA bundle
2. **Key Generation**: Creates EC P-256 private key
3. **CSR Creation**: Generates Certificate Signing Request with SPIFFE SAN
4. **Certificate Retrieval**: Submits CSR and receives signed certificate
5. **Certificate Storage**: Saves certificates to `/etc/streamdeploy/pki/`

## Uninstallation

To completely remove the StreamDeploy agent:

```bash
sudo ./uninstall.sh
```

This will:
- Stop and disable the systemd service
- Remove the agent binary
- Delete all configuration and data files
- Clean up certificates and logs

## Supported Distributions

The installer supports the following Linux distributions:

- **Debian/Ubuntu** (apt package manager)
- **RHEL/CentOS/Fedora** (yum/dnf package manager)
- **Alpine Linux** (apk package manager)
- **Arch Linux** (pacman package manager)

## Architecture Support

- **x86_64** (Intel/AMD 64-bit)
- **aarch64** (ARM 64-bit)
- **arm** (ARM 32-bit)

## Troubleshooting

### Check Installation Status

```bash
# Check service status
systemctl status streamdeploy-agent

# View logs
journalctl -u streamdeploy-agent -f

# Check configuration
cat /etc/streamdeploy/agent.json

# Verify certificates
openssl x509 -in /etc/streamdeploy/pki/device.crt -noout -text
```

### Common Issues

1. **Bootstrap Token Invalid**: Ensure the token is valid and not expired
2. **Network Issues**: Check internet connectivity and firewall settings
3. **Permission Errors**: Ensure running as root with sudo
4. **Certificate Problems**: Check that the device ID matches the token

### Manual Cleanup

If the uninstaller fails, manually remove:

```bash
sudo systemctl stop streamdeploy-agent
sudo systemctl disable streamdeploy-agent
sudo rm -f /etc/systemd/system/streamdeploy-agent.service
sudo rm -f /usr/local/bin/streamdeploy-agent
sudo rm -rf /etc/streamdeploy
sudo rm -rf /var/lib/streamdeploy
sudo systemctl daemon-reload
```

## Development

### Building from Source

To build the installer manually:

```bash
cd install
mkdir -p build && cd build

# Set up musl environment
export CC=musl-gcc
export CXX=musl-g++

# Configure and build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=musl-gcc \
      -DCMAKE_CXX_COMPILER=musl-g++ \
      -DCMAKE_EXE_LINKER_FLAGS="-static" \
      ..

make -j$(nproc)
```

### Dependencies

Build dependencies:
- `musl-tools` and `musl-dev`
- `libcurl4-openssl-dev`
- `libjsoncpp-dev`
- `libssl-dev`
- `cmake` and `build-essential`

## Security Notes

- The installer requires root privileges for system-level operations
- Bootstrap tokens should be kept secure and not logged
- Private keys are stored with 600 permissions (owner read/write only)
- All network communication uses HTTPS with certificate validation

## Support

For issues with the installer, check:
1. System logs: `journalctl -u streamdeploy-agent`
2. Installation logs from the installer output
3. Network connectivity to StreamDeploy endpoints
4. Bootstrap token validity and permissions
