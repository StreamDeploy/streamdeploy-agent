#!/bin/sh
# StreamDeploy Agent Installation Script
# POSIX-compliant for maximum compatibility across devices

set -e

# Configuration
API_BASE="${API_BASE:-https://api.streamdeploy.com}"
DEVICE_BASE="${DEVICE_BASE:-https://device.streamdeploy.com}"
GITHUB_REPO="StreamDeploy/streamdeploy-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/streamdeploy"
SERVICE_FILE="/etc/systemd/system/streamdeploy-agent.service"

# Colors for output (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Logging functions
log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Get bootstrap token from environment
get_bootstrap_token() {
    if [ -z "${SD_BOOTSTRAP_TOKEN:-}" ]; then
        log_error "SD_BOOTSTRAP_TOKEN environment variable is required"
        log_info "Usage: export SD_BOOTSTRAP_TOKEN=\"your-token\" && curl -fsSL https://api.streamdeploy.com/v1-app/enroll/install.sh | sudo sh"
        exit 1
    fi
    log_info "Bootstrap token found"
}

# Detect system architecture
detect_arch() {
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            # Force source build for ARM64 embedded systems for optimal compatibility
            log_info "ARM64 detected - building from source for optimal compatibility with embedded systems"
            ARCH=""
            ;;
        armv7l|armv6l)
            ARCH="arm"
            # Force source build for ARM systems
            log_info "ARM detected - building from source for optimal compatibility"
            ARCH=""
            ;;
        *)
            log_warn "Unknown architecture: $ARCH, will build from source"
            ARCH=""
            ;;
    esac
}


# Detect operating system and package manager
detect_os() {
    if command -v apt-get >/dev/null 2>&1; then
        OS_TYPE="debian"
        PKG_MANAGER="apt-get"
    elif command -v yum >/dev/null 2>&1; then
        OS_TYPE="rhel"
        PKG_MANAGER="yum"
    elif command -v apk >/dev/null 2>&1; then
        OS_TYPE="alpine"
        PKG_MANAGER="apk"
    elif command -v pacman >/dev/null 2>&1; then
        OS_TYPE="arch"
        PKG_MANAGER="pacman"
    else
        OS_TYPE="unknown"
        PKG_MANAGER=""
        log_warn "Unknown package manager, will attempt manual installation"
    fi
    log_info "Detected OS: $OS_TYPE"
}

# Check GLIBC version compatibility
check_glibc_compatibility() {
    log_info "Checking GLIBC compatibility..."
    
    # Get GLIBC version using multiple methods
    GLIBC_VERSION=""
    
    # Method 1: ldd --version
    if command -v ldd >/dev/null 2>&1; then
        GLIBC_VERSION="$(ldd --version 2>/dev/null | head -n1 | grep -o '[0-9]\+\.[0-9]\+' | head -n1)"
    fi
    
    # Method 2: getconf GNU_LIBC_VERSION
    if [ -z "$GLIBC_VERSION" ] && command -v getconf >/dev/null 2>&1; then
        GLIBC_VERSION="$(getconf GNU_LIBC_VERSION 2>/dev/null | grep -o '[0-9]\+\.[0-9]\+' || echo '')"
    fi
    
    # Method 3: strings on libc.so.6
    if [ -z "$GLIBC_VERSION" ]; then
        for libc_path in "/lib/x86_64-linux-gnu/libc.so.6" "/lib/aarch64-linux-gnu/libc.so.6" "/lib/libc.so.6" "/usr/lib/libc.so.6"; do
            if [ -f "$libc_path" ]; then
                GLIBC_VERSION="$(strings "$libc_path" 2>/dev/null | grep '^GLIBC_' | sort -V | tail -n1 | cut -d'_' -f2 || echo '')"
                [ -n "$GLIBC_VERSION" ] && break
            fi
        done
    fi
    
    if [ -n "$GLIBC_VERSION" ]; then
        log_info "Detected GLIBC version: $GLIBC_VERSION"
        
        # Parse version components more robustly
        GLIBC_MAJOR="$(echo "$GLIBC_VERSION" | cut -d'.' -f1)"
        GLIBC_MINOR="$(echo "$GLIBC_VERSION" | cut -d'.' -f2)"
        
        # Ensure we have numeric values
        if ! echo "$GLIBC_MAJOR" | grep -q '^[0-9]\+$' || ! echo "$GLIBC_MINOR" | grep -q '^[0-9]\+$'; then
            log_warn "Could not parse GLIBC version properly - will build from source for safety"
            return 1
        fi
        
        # Check if GLIBC version is less than 2.38 (required by prebuilt binaries)
        # Also force source build for known problematic versions
        if [ "$GLIBC_MAJOR" -lt 2 ] || \
           ([ "$GLIBC_MAJOR" -eq 2 ] && [ "$GLIBC_MINOR" -lt 38 ]); then
            log_warn "GLIBC version $GLIBC_VERSION is older than required 2.38 - will build from source"
            return 1
        fi
        
        # Additional check: Ubuntu 22.04 and older should build from source regardless
        if [ -f "/etc/os-release" ]; then
            OS_VERSION="$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')"
            if echo "$OS_VERSION" | grep -q '^22\.04\|^20\.04\|^18\.04'; then
                log_warn "Ubuntu $OS_VERSION detected - building from source for optimal compatibility"
                return 1
            fi
        fi
        
        log_info "GLIBC version $GLIBC_VERSION is compatible with prebuilt binaries"
        return 0
    else
        log_warn "Could not determine GLIBC version - will build from source for safety"
        return 1
    fi
}

# Test if a binary can actually run on this system
test_binary_compatibility() {
    BINARY_PATH="$1"
    
    if [ ! -f "$BINARY_PATH" ]; then
        return 1
    fi
    
    log_info "Testing binary compatibility..."
    
    # Create a minimal test config for the agent
    TEST_CONFIG="$(mktemp)"
    cat > "$TEST_CONFIG" << 'EOF'
{
  "device_id": "test-device",
  "device_class": "sbc",
  "enroll_base_url": "https://api.streamdeploy.com",
  "device_base_url": "https://device.streamdeploy.com",
  "base_url": "https://api.streamdeploy.com",
  "status_path": "/v1-device/status-update",
  "heartbeat_path": "/v1-device/heartbeat",
  "pki_dir": "/tmp/test-pki",
  "auto_enroll": false,
  "max_log_buffer": 200,
  "app_port": 80,
  "next_port": 8081,
  "health_path": "/healthz",
  "health_wait_seconds": 25,
  "heartbeat_interval_seconds": 15,
  "bootstrap_token": "",
  "container_name": "sd-app",
  "extra_docker_args": "",
  "state_file": "/tmp/test-state.json",
  "ssh_bastion_host": "",
  "ssh_bastion_user": "",
  "ssh_bastion_port": 22,
  "ssh_tunnel_enabled": false,
  "ssh_tunnel_port": 0,
  "bootstrap_token_file": "/tmp/test-bootstrap"
}
EOF
    
    # Create test bootstrap token file
    echo "test-token" > "/tmp/test-bootstrap"
    mkdir -p "/tmp/test-pki"
    
    # Try to run the binary with test config and capture any library errors
    # Use timeout and expect it to fail quickly due to network/auth, but not due to library issues
    ERROR_OUTPUT="$(timeout 5s "$BINARY_PATH" "$TEST_CONFIG" 2>&1 || true)"
    
    # Clean up test files
    rm -f "$TEST_CONFIG" "/tmp/test-bootstrap"
    rm -rf "/tmp/test-pki"
    
    # Check if it's a library error specifically
    if echo "$ERROR_OUTPUT" | grep -q "GLIBC\|GLIBCXX\|not found\|symbol lookup error"; then
        log_warn "Binary compatibility test failed due to library version mismatch"
        log_info "Error details: $(echo "$ERROR_OUTPUT" | head -n2)"
        return 1
    elif echo "$ERROR_OUTPUT" | grep -q "cannot open config\|No such file"; then
        log_warn "Binary compatibility test failed - config file issue"
        return 1
    else
        # If we get here, the binary at least started without library errors
        # It may have failed due to network/auth issues, but that's expected in a test
        log_success "Binary compatibility test passed - no library errors detected"
        return 0
    fi
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    case "$PKG_MANAGER" in
        apt-get)
            apt-get update -qq >/dev/null 2>&1 || true
            apt-get install -y curl openssl ca-certificates systemd >/dev/null 2>&1
            # Optional: docker, build tools for source compilation
            apt-get install -y docker.io build-essential cmake >/dev/null 2>&1 || true
            ;;
        yum)
            yum install -y curl openssl ca-certificates systemd >/dev/null 2>&1
            yum install -y docker gcc gcc-c++ make cmake >/dev/null 2>&1 || true
            ;;
        apk)
            apk update >/dev/null 2>&1
            apk add curl openssl ca-certificates openrc >/dev/null 2>&1
            apk add docker gcc g++ make cmake >/dev/null 2>&1 || true
            ;;
        pacman)
            pacman -Sy --noconfirm curl openssl ca-certificates systemd >/dev/null 2>&1
            pacman -S --noconfirm docker gcc make cmake >/dev/null 2>&1 || true
            ;;
        *)
            log_warn "Cannot install dependencies automatically"
            ;;
    esac
    
    # Enable and start docker if available
    if command -v systemctl >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
        systemctl enable docker >/dev/null 2>&1 || true
        systemctl start docker >/dev/null 2>&1 || true
    fi
}

# Download prebuilt binary
download_binary() {
    if [ -z "$ARCH" ]; then
        log_info "Unknown architecture - will build from source"
        return 1
    fi
    
    # Check GLIBC compatibility first
    if ! check_glibc_compatibility; then
        log_info "System libraries incompatible with prebuilt binaries - will build from source"
        return 1
    fi
    
    BINARY_NAME="streamdeploy-agent-linux-$ARCH"
    DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/latest/download/$BINARY_NAME"
    
    log_info "Attempting to download prebuilt binary: $BINARY_NAME"
    
    TEMP_DIR="$(mktemp -d)"
    cd "$TEMP_DIR"
    
    if curl -fsSL -o "$BINARY_NAME" "$DOWNLOAD_URL"; then
        chmod +x "$BINARY_NAME"
        
        # Test binary compatibility before installing
        if test_binary_compatibility "./$BINARY_NAME"; then
            install -m 755 "$BINARY_NAME" "$INSTALL_DIR/streamdeploy-agent"
            cd /
            rm -rf "$TEMP_DIR"
            log_success "Downloaded and installed prebuilt binary"
            return 0
        else
            log_warn "Downloaded binary failed compatibility test - will build from source"
            cd /
            rm -rf "$TEMP_DIR"
            return 1
        fi
    else
        cd /
        rm -rf "$TEMP_DIR"
        log_warn "Prebuilt binary not available, will build from source"
        return 1
    fi
}

# Build from source
build_from_source() {
    log_info "Building StreamDeploy agent from source..."
    
    # Check for required build tools
    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    TEMP_DIR="$(mktemp -d)"
    cd "$TEMP_DIR"
    
    # Download source with retries
    ATTEMPTS=0
    MAX_ATTEMPTS=3
    SUCCESS=0
    
    while [ $ATTEMPTS -lt $MAX_ATTEMPTS ] && [ $SUCCESS -eq 0 ]; do
        ATTEMPTS=$((ATTEMPTS + 1))
        log_info "Download attempt $ATTEMPTS/$MAX_ATTEMPTS..."
        
        if curl -fsSL --connect-timeout 30 --max-time 300 \
           "https://codeload.github.com/$GITHUB_REPO/tar.gz/refs/heads/main" | tar xz; then
            SUCCESS=1
            break
        fi
        
        if [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; then
            log_warn "Download failed, retrying in 5 seconds..."
            sleep 5
        fi
    done
    
    if [ $SUCCESS -eq 0 ]; then
        log_error "Failed to download source code after $MAX_ATTEMPTS attempts"
        cd /
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    # Verify extraction
    if [ ! -d "streamdeploy-agent-main" ]; then
        log_error "Source extraction failed - directory not found"
        cd /
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    log_success "Source downloaded and extracted successfully"
    cd streamdeploy-agent-main
    
    # Build using CMake if available, otherwise use build script
    if command -v cmake >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
        log_info "Building with CMake..."
        mkdir -p build
        cd build
        cmake .. >/dev/null 2>&1
        make >/dev/null 2>&1
        install -m 755 streamdeploy-agent "$INSTALL_DIR/streamdeploy-agent"
    elif [ -f "scripts/build.sh" ]; then
        log_info "Building with build script..."
        cd scripts
        sh ./build.sh >/dev/null 2>&1
    else
        log_error "No build method available"
        cd /
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    cd /
    rm -rf "$TEMP_DIR"
    log_success "Built and installed from source"
}

# Decode JWT token to extract device ID
decode_jwt_device_id() {
    TOKEN="$1"
    
    # JWT has 3 parts separated by dots: header.payload.signature
    # We need the payload (middle part)
    PAYLOAD="$(echo "$TOKEN" | cut -d'.' -f2)"
    
    # Add padding if needed for base64 decoding
    case $((${#PAYLOAD} % 4)) in
        2) PAYLOAD="${PAYLOAD}==" ;;
        3) PAYLOAD="${PAYLOAD}=" ;;
    esac
    
    # Decode base64 payload
    if command -v base64 >/dev/null 2>&1; then
        DECODED="$(echo "$PAYLOAD" | base64 -d 2>/dev/null || echo '')"
    else
        log_error "base64 command not available for JWT decoding"
        return 1
    fi
    
    if [ -z "$DECODED" ]; then
        log_error "Failed to decode JWT token payload"
        return 1
    fi
    
    # Extract device_id from JSON payload
    # Use multiple methods to extract device_id
    if command -v jq >/dev/null 2>&1; then
        EXTRACTED_DEVICE_ID="$(echo "$DECODED" | jq -r '.device_id' 2>/dev/null || echo '')"
    elif command -v python3 >/dev/null 2>&1; then
        EXTRACTED_DEVICE_ID="$(echo "$DECODED" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('device_id', ''))
except:
    pass
" 2>/dev/null || echo '')"
    else
        # Fallback: simple grep/sed extraction
        EXTRACTED_DEVICE_ID="$(echo "$DECODED" | grep -o '"device_id":"[^"]*"' | cut -d'"' -f4 || echo '')"
    fi
    
    if [ -z "$EXTRACTED_DEVICE_ID" ] || [ "$EXTRACTED_DEVICE_ID" = "null" ]; then
        log_error "Could not extract device_id from bootstrap token"
        return 1
    fi
    
    echo "$EXTRACTED_DEVICE_ID"
    return 0
}

# Generate device ID
generate_device_id() {
    # First try to extract device ID from bootstrap token
    if [ -n "$SD_BOOTSTRAP_TOKEN" ]; then
        log_info "Extracting device ID from bootstrap token..."
        EXTRACTED_ID="$(decode_jwt_device_id "$SD_BOOTSTRAP_TOKEN")"
        if [ $? -eq 0 ] && [ -n "$EXTRACTED_ID" ]; then
            DEVICE_ID="$EXTRACTED_ID"
            log_info "Using device ID from bootstrap token: $DEVICE_ID"
            # Save the extracted device ID
            mkdir -p "$CONFIG_DIR"
            echo "$DEVICE_ID" > "$CONFIG_DIR/device_id"
            return
        else
            log_warn "Failed to extract device ID from bootstrap token, falling back to generated ID"
        fi
    fi
    
    # Fallback: Try to use existing device ID or generate a new one
    if [ -f "$CONFIG_DIR/device_id" ]; then
        DEVICE_ID="$(cat "$CONFIG_DIR/device_id")"
    else
        # Generate device ID from hostname and MAC address
        HOSTNAME="$(hostname)"
        MAC_ADDR="$(ip link show | awk '/ether/ {print $2; exit}' 2>/dev/null || echo 'unknown')"
        DEVICE_ID="${HOSTNAME}-$(echo "$MAC_ADDR" | tr ':' '-')"
        
        # Fallback to random ID if above fails
        if [ "$DEVICE_ID" = "-unknown" ] || [ -z "$DEVICE_ID" ]; then
            DEVICE_ID="device-$(date +%s)-$(od -An -N4 -tx4 /dev/urandom 2>/dev/null | tr -d ' ' || echo 'rand')"
        fi
        
        mkdir -p "$CONFIG_DIR"
        echo "$DEVICE_ID" > "$CONFIG_DIR/device_id"
    fi
    log_info "Device ID: $DEVICE_ID"
}

# Create agent configuration
create_config() {
    log_info "Creating agent configuration..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$CONFIG_DIR/secrets"
    mkdir -p "$CONFIG_DIR/pki"
    mkdir -p "/var/lib/streamdeploy"
    
    # Set proper permissions
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR/pki"
    chmod 755 "/var/lib/streamdeploy"
    chmod 700 "$CONFIG_DIR/secrets"
    
    # Save bootstrap token to secrets file
    echo "$SD_BOOTSTRAP_TOKEN" > "$CONFIG_DIR/secrets/bootstrap_token"
    chmod 600 "$CONFIG_DIR/secrets/bootstrap_token"
    
    # Create main configuration file with validation
    CONFIG_TEMP="$(mktemp)"
    cat > "$CONFIG_TEMP" << EOF
{
  "device_id": "$DEVICE_ID",
  "device_class": "sbc",
  "enroll_base_url": "$API_BASE",
  "device_base_url": "$DEVICE_BASE",
  "base_url": "$API_BASE",
  "status_path": "/v1-device/status-update",
  "heartbeat_path": "/v1-device/heartbeat",
  "pki_dir": "$CONFIG_DIR/pki",
  "ca_cert_path": "",
  "client_cert_path": "",
  "client_key_path": "",
  "client_key_pass": "",
  "auto_enroll": true,
  "max_log_buffer": 200,
  "app_port": 80,
  "next_port": 8081,
  "health_path": "/healthz",
  "health_wait_seconds": 25,
  "heartbeat_interval_seconds": 15,
  "bootstrap_token": "",
  "container_name": "sd-app",
  "extra_docker_args": "",
  "state_file": "/var/lib/streamdeploy/state.json",
  "ssh_bastion_host": "",
  "ssh_bastion_user": "",
  "ssh_bastion_port": 22,
  "ssh_tunnel_enabled": false,
  "ssh_tunnel_port": 0,
  "bootstrap_token_file": "$CONFIG_DIR/secrets/bootstrap_token"
}
EOF
    
    # Validate JSON syntax
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 -m json.tool "$CONFIG_TEMP" >/dev/null 2>&1; then
            log_error "Generated configuration file has invalid JSON syntax"
            rm -f "$CONFIG_TEMP"
            exit 1
        fi
    elif command -v jq >/dev/null 2>&1; then
        if ! jq . "$CONFIG_TEMP" >/dev/null 2>&1; then
            log_error "Generated configuration file has invalid JSON syntax"
            rm -f "$CONFIG_TEMP"
            exit 1
        fi
    fi
    
    # Move validated config to final location
    mv "$CONFIG_TEMP" "$CONFIG_DIR/agent.json"
    chmod 644 "$CONFIG_DIR/agent.json"
    
    log_success "Configuration created and validated"
}

# Create systemd service
create_service() {
    log_info "Creating systemd service..."
    
    # Pre-create all required directories with proper permissions
    mkdir -p /var/lib/streamdeploy
    mkdir -p /var/log/streamdeploy-agent
    mkdir -p /etc/streamdeploy/pki
    chmod 755 /var/lib/streamdeploy
    chmod 755 /var/log/streamdeploy-agent
    chmod 755 /etc/streamdeploy/pki
    
    # Remove any existing problematic service first
    systemctl stop streamdeploy-agent 2>/dev/null || true
    systemctl disable streamdeploy-agent 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=StreamDeploy Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/streamdeploy-agent /etc/streamdeploy/agent.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 "$SERVICE_FILE"
    log_success "Ultra-simple systemd service created for maximum embedded device compatibility"
}

# Start and enable service
start_service() {
    log_info "Starting StreamDeploy agent service..."
    
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable streamdeploy-agent
        systemctl start streamdeploy-agent
        
        # Wait a moment and check status
        sleep 2
        if systemctl is-active --quiet streamdeploy-agent; then
            log_success "StreamDeploy agent is running"
        else
            log_warn "Service may have issues, check: systemctl status streamdeploy-agent"
        fi
    else
        log_warn "systemctl not available, please start the agent manually"
    fi
}

# Main installation flow
main() {
    log_info "StreamDeploy Agent Installation Starting..."
    
    check_root
    get_bootstrap_token
    detect_arch
    detect_os
    install_dependencies
    
    # Try prebuilt binary first, fallback to source build
    if ! download_binary; then
        build_from_source
    fi
    
    # Verify installation
    if [ ! -f "$INSTALL_DIR/streamdeploy-agent" ]; then
        log_error "Installation failed - binary not found"
        exit 1
    fi
    
    generate_device_id
    create_config
    create_service
    start_service
    
    log_success "StreamDeploy agent installation completed!"
    log_info "The agent will automatically enroll with the platform and start sending heartbeats."
    log_info "Check status with: systemctl status streamdeploy-agent"
    log_info "View logs with: journalctl -u streamdeploy-agent -f"
}

# Run main function
main "$@"
