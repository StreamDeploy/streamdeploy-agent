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
            ;;
        armv7l|armv6l)
            ARCH="arm"
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
        return 1
    fi
    
    BINARY_NAME="streamdeploy-agent-linux-$ARCH"
    DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/latest/download/$BINARY_NAME"
    
    log_info "Attempting to download prebuilt binary: $BINARY_NAME"
    
    TEMP_DIR="$(mktemp -d)"
    cd "$TEMP_DIR"
    
    if curl -fsSL -o "$BINARY_NAME" "$DOWNLOAD_URL"; then
        chmod +x "$BINARY_NAME"
        install -m 755 "$BINARY_NAME" "$INSTALL_DIR/streamdeploy-agent"
        cd /
        rm -rf "$TEMP_DIR"
        log_success "Downloaded and installed prebuilt binary"
        return 0
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

# Generate device ID
generate_device_id() {
    # Try to use existing device ID or generate a new one
    if [ -f "$CONFIG_DIR/device_id" ]; then
        DEVICE_ID="$(cat "$CONFIG_DIR/device_id")"
    else
        # Generate device ID from hostname and MAC address
        HOSTNAME="$(hostname)"
        MAC_ADDR="$(ip link show | awk '/ether/ {print $2; exit}' 2>/dev/null || echo 'unknown')"
        DEVICE_ID="${HOSTNAME}-$(echo "$MAC_ADDR" | tr ':' '-')"
        
        # Fallback to random ID if above fails
        if [ "$DEVICE_ID" = "-
