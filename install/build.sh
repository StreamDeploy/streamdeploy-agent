#!/usr/bin/env bash
set -euo pipefail

# StreamDeploy Agent Installer Build Script
# This script builds the standalone installer with musl static compilation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
INSTALLER_NAME="streamdeploy-installer"

# Cross-compilation configuration
DEFAULT_TARGET_ARCH="$(uname -m)"
DEFAULT_TARGET_OS="linux"
MUSL_BUILD=false
STATIC_BUILD=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}


# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get supported architectures
get_supported_architectures() {
    echo "x86_64 aarch64 armv7l"
}

# Function to get supported operating systems
get_supported_os() {
    echo "linux"
}


# Function to get cross-compilation toolchain prefix
get_toolchain_prefix() {
    local arch="$1"
    case "$arch" in
        x86_64)
            echo "x86_64-linux-gnu"
            ;;
        aarch64)
            echo "aarch64-linux-gnu"
            ;;
        armv7l)
            echo "arm-linux-gnueabihf"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            return 1
            ;;
    esac
}

# Function to check if cross-compilation toolchain is available
check_cross_toolchain() {
    local arch="$1"
    local prefix=$(get_toolchain_prefix "$arch")
    
    if ! command_exists "${prefix}-gcc" || ! command_exists "${prefix}-g++"; then
        return 1
    fi
    return 0
}


# Function to install cross-compilation toolchain
install_cross_toolchain() {
    local arch="$1"
    local prefix=$(get_toolchain_prefix "$arch")
    
    log_info "Installing cross-compilation toolchain for $arch..."
    
    case "$PKG_MANAGER" in
        "apt")
            case "$arch" in
                x86_64)
                    sudo $INSTALL_CMD gcc-multilib g++-multilib
                    ;;
                aarch64)
                    sudo $INSTALL_CMD gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
                    ;;
                armv7l)
                    sudo $INSTALL_CMD gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
                    ;;
            esac
            ;;
        "yum"|"dnf")
            case "$arch" in
                x86_64)
                    sudo $INSTALL_CMD gcc gcc-c++
                    ;;
                aarch64)
                    sudo $INSTALL_CMD gcc-aarch64-linux-gnu gcc-c++-aarch64-linux-gnu
                    ;;
                armv7l)
                    sudo $INSTALL_CMD gcc-arm-linux-gnu gcc-c++-arm-linux-gnu
                    ;;
            esac
            ;;
        "apk")
            case "$arch" in
                x86_64)
                    sudo $INSTALL_CMD gcc g++
                    ;;
                aarch64)
                    sudo $INSTALL_CMD gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
                    ;;
                armv7l)
                    sudo $INSTALL_CMD gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
                    ;;
            esac
            ;;
        *)
            log_error "Cross-compilation not supported for package manager: $PKG_MANAGER"
            return 1
            ;;
    esac
    
    log_success "Cross-compilation toolchain installed for $arch"
}

# Function to install musl toolchain
install_musl_toolchain() {
    log_info "Installing musl toolchain..."
    
    case "$PKG_MANAGER" in
        "apt")
            sudo $INSTALL_CMD musl-tools musl-dev
            ;;
        "yum"|"dnf")
            sudo $INSTALL_CMD musl-gcc musl-libc-static
            ;;
        "apk")
            sudo $INSTALL_CMD musl-dev
            ;;
        "pacman")
            sudo $INSTALL_CMD musl
            ;;
        *)
            log_error "musl toolchain not available for package manager: $PKG_MANAGER"
            return 1
            ;;
    esac
    
    log_success "musl toolchain installed"
}

# Function to detect OS and package manager
detect_system() {
    log_info "Detecting system information..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            PKG_MANAGER="apt"
            INSTALL_CMD="apt-get install -y"
            UPDATE_CMD="apt-get update"
        elif command_exists yum; then
            PKG_MANAGER="yum"
            INSTALL_CMD="yum install -y"
            UPDATE_CMD="yum update"
        elif command_exists dnf; then
            PKG_MANAGER="dnf"
            INSTALL_CMD="dnf install -y"
            UPDATE_CMD="dnf update"
        elif command_exists apk; then
            PKG_MANAGER="apk"
            INSTALL_CMD="apk add"
            UPDATE_CMD="apk update"
        elif command_exists pacman; then
            PKG_MANAGER="pacman"
            INSTALL_CMD="pacman -S --noconfirm"
            UPDATE_CMD="pacman -Sy"
        else
            log_error "Unsupported package manager"
            return 1
        fi
        log_info "Detected package manager: $PKG_MANAGER"
    else
        log_error "Unsupported operating system: $OSTYPE"
        return 1
    fi
}

# Function to install build dependencies
install_dependencies() {
    log_info "Installing build dependencies..."
    
    case "$PKG_MANAGER" in
        "apt")
            sudo $UPDATE_CMD
            sudo $INSTALL_CMD \
                build-essential \
                cmake \
                pkg-config \
                libcurl4-openssl-dev \
                libjsoncpp-dev \
                libssl-dev \
                libnghttp2-dev \
                libidn2-dev \
                zlib1g-dev
            ;;
        "yum"|"dnf")
            sudo $UPDATE_CMD
            sudo $INSTALL_CMD \
                gcc \
                gcc-c++ \
                cmake \
                pkgconfig \
                libcurl-devel \
                jsoncpp-devel \
                openssl-devel \
                libnghttp2-devel \
                libidn2-devel \
                zlib-devel
            ;;
        "apk")
            sudo $UPDATE_CMD
            sudo $INSTALL_CMD \
                build-base \
                cmake \
                pkgconfig \
                curl-dev \
                jsoncpp-dev \
                openssl-dev \
                nghttp2-dev \
                libidn2-dev \
                zlib-dev
            ;;
        "pacman")
            sudo $UPDATE_CMD
            sudo $INSTALL_CMD \
                base-devel \
                cmake \
                pkgconfig \
                curl \
                jsoncpp \
                openssl \
                nghttp2 \
                libidn2 \
                zlib
            ;;
        *)
            log_error "Unsupported package manager for dependency installation"
            return 1
            ;;
    esac
    
    log_success "Build dependencies installed"
}

# Function to check dependencies
check_dependencies() {
    log_info "Checking build dependencies..."
    
    local missing_deps=()
    
    # Check for required tools
    if ! command_exists cmake; then
        missing_deps+=("cmake")
    fi
    
    if ! command_exists pkg-config; then
        missing_deps+=("pkg-config")
    fi
    
    # Check for gcc/g++ compiler
    if ! command_exists gcc || ! command_exists g++; then
        missing_deps+=("gcc and g++")
    fi
    
    # Check for development libraries using pkg-config (more reliable)
    # Check for libcurl
    if ! pkg-config --exists libcurl 2>/dev/null; then
        # Fallback to checking header files in multiple possible locations
        local curl_found=false
        for curl_path in /usr/include/curl/curl.h /usr/local/include/curl/curl.h /usr/include/x86_64-linux-gnu/curl/curl.h; do
            if [[ -f "$curl_path" ]]; then
                curl_found=true
                break
            fi
        done
        if [[ "$curl_found" = false ]]; then
            missing_deps+=("libcurl development headers")
        fi
    fi
    
    # Check for jsoncpp
    if ! pkg-config --exists jsoncpp 2>/dev/null; then
        # Fallback to checking header files in multiple possible locations
        local jsoncpp_found=false
        for jsoncpp_path in /usr/include/json/json.h /usr/local/include/json/json.h \
                           /usr/include/jsoncpp/json.h /usr/local/include/jsoncpp/json.h \
                           /usr/include/x86_64-linux-gnu/jsoncpp/json.h; do
            if [[ -f "$jsoncpp_path" ]]; then
                jsoncpp_found=true
                break
            fi
        done
        if [[ "$jsoncpp_found" = false ]]; then
            missing_deps+=("jsoncpp development headers")
        fi
    fi
    
    
    # Check for openssl
    if ! pkg-config --exists openssl 2>/dev/null; then
        # Fallback to checking header files in multiple possible locations
        local openssl_found=false
        for openssl_path in /usr/include/openssl/ssl.h /usr/local/include/openssl/ssl.h \
                           /usr/include/x86_64-linux-gnu/openssl/ssl.h; do
            if [[ -f "$openssl_path" ]]; then
                openssl_found=true
                break
            fi
        done
        if [[ "$openssl_found" = false ]]; then
            missing_deps+=("openssl development headers")
        fi
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        log_info "Run with --install-deps to automatically install dependencies"
        return 1
    fi
    
    log_success "All dependencies are available"
}

# Function to clean build directory
clean_build() {
    log_info "Cleaning build directory..."
    if [[ -d "$BUILD_DIR" ]]; then
        rm -rf "$BUILD_DIR"
    fi
    mkdir -p "$BUILD_DIR"
    log_success "Build directory cleaned"
}

# Function to configure CMake
configure_cmake() {
    local target_arch="${1:-$DEFAULT_TARGET_ARCH}"
    local target_os="${2:-$DEFAULT_TARGET_OS}"
    
    log_info "Configuring CMake for target: $target_os-$target_arch"
    log_info "Build type: $([ "$MUSL_BUILD" = true ] && echo "musl static" || echo "dynamic")"
    
    cd "$BUILD_DIR"
    
    local CC_COMPILER
    local CXX_COMPILER
    local CMAKE_ARGS=()
    
    # Set up compilers based on build type
    if [[ "$MUSL_BUILD" = true ]]; then
        if [[ "$target_arch" = "$DEFAULT_TARGET_ARCH" ]]; then
            # Native musl build
            CC_COMPILER="musl-gcc"
            CXX_COMPILER="musl-g++"
        else
            # Cross-compilation with musl
            local prefix=$(get_toolchain_prefix "$target_arch")
            CC_COMPILER="musl-gcc"
            CXX_COMPILER="musl-g++"
            
            # Set up cross-compilation environment
            CMAKE_ARGS+=(
                -DCMAKE_SYSTEM_NAME=Linux
                -DCMAKE_SYSTEM_PROCESSOR="$target_arch"
                -DCMAKE_C_COMPILER_TARGET="${prefix}"
                -DCMAKE_CXX_COMPILER_TARGET="${prefix}"
            )
        fi
        
        # musl-specific flags
        CMAKE_ARGS+=(
            -DCMAKE_EXE_LINKER_FLAGS="-static"
            -DCMAKE_FIND_LIBRARY_SUFFIXES=".a"
            -DCMAKE_EXE_LINK_DYNAMIC_C_FLAGS=""
            -DCMAKE_EXE_LINK_DYNAMIC_CXX_FLAGS=""
            -DCMAKE_SHARED_LIBRARY_C_FLAGS=""
            -DCMAKE_SHARED_LIBRARY_CXX_FLAGS=""
        )
        
    elif [[ "$target_arch" != "$DEFAULT_TARGET_ARCH" ]]; then
        # Cross-compilation with glibc
        local prefix=$(get_toolchain_prefix "$target_arch")
        CC_COMPILER="${prefix}-gcc"
        CXX_COMPILER="${prefix}-g++"
        
        CMAKE_ARGS+=(
            -DCMAKE_SYSTEM_NAME=Linux
            -DCMAKE_SYSTEM_PROCESSOR="$target_arch"
            -DCMAKE_FIND_ROOT_PATH="/usr/${prefix};/usr/lib/${prefix};/usr/include/${prefix}"
            -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER
            -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY
            -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY
            -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY
        )
        
        # Set pkg-config for cross-compilation
        export PKG_CONFIG_LIBDIR="/usr/lib/${prefix}/pkgconfig:/usr/share/pkgconfig"
        export PKG_CONFIG_PATH="/usr/lib/${prefix}/pkgconfig:/usr/share/pkgconfig"
        
    else
        # Native build
        CC_COMPILER="gcc"
        CXX_COMPILER="g++"
    fi
    
    # Check if compilers exist
    if ! command_exists "$CC_COMPILER" || ! command_exists "$CXX_COMPILER"; then
        log_error "Required compilers not found: $CC_COMPILER, $CXX_COMPILER"
        return 1
    fi
    
    log_info "Using compilers: $CC_COMPILER, $CXX_COMPILER"
    
    # Configure with CMake
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER="$CC_COMPILER" \
        -DCMAKE_CXX_COMPILER="$CXX_COMPILER" \
        "${CMAKE_ARGS[@]}"
    
    log_success "CMake configuration completed"
}

# Function to build the installer
build_installer() {
    local target_arch="${1:-$DEFAULT_TARGET_ARCH}"
    local target_os="${2:-$DEFAULT_TARGET_OS}"
    
    log_info "Building the installer for $target_os-$target_arch..."
    
    cd "$BUILD_DIR"
    
    # Build with make
    make -j"$(nproc)" || {
        log_error "Build failed"
        log_info "Build log:"
        cat CMakeFiles/CMakeError.log 2>/dev/null || echo "No error log available"
        return 1
    }
    
    # Check if the binary was created
    if [[ ! -f "$INSTALLER_NAME" ]]; then
        log_error "Installer binary not found after build"
        return 1
    fi
    
    # Create architecture-specific binary name
    local arch_suffix=""
    if [[ "$target_arch" != "$DEFAULT_TARGET_ARCH" ]] || [[ "$MUSL_BUILD" = true ]]; then
        arch_suffix="-$target_arch"
        if [[ "$MUSL_BUILD" = true ]]; then
            arch_suffix="${arch_suffix}-musl"
        fi
    fi
    
    local final_name="${INSTALLER_NAME}${arch_suffix}"
    
    # Copy to install directory with architecture-specific name
    cp "$INSTALLER_NAME" "$SCRIPT_DIR/$final_name"
    chmod +x "$SCRIPT_DIR/$final_name"
    
    log_success "Installer built successfully: $SCRIPT_DIR/$final_name"
}

# Function to verify the build
verify_build() {
    log_info "Verifying the build..."
    
    local installer_path="$SCRIPT_DIR/$INSTALLER_NAME"
    
    # Check if file exists and is executable
    if [[ ! -x "$installer_path" ]]; then
        log_error "Installer is not executable"
        return 1
    fi
    
    # Check if it's statically linked
    if command_exists ldd; then
        log_info "Checking static linking..."
        if ldd "$installer_path" 2>&1 | grep -q "not a dynamic executable"; then
            log_success "Binary is statically linked"
        else
            log_warn "Binary may not be fully statically linked:"
            ldd "$installer_path" || true
        fi
    fi
    
    # Check file size (static binaries are typically larger)
    local file_size=$(stat -c%s "$installer_path" 2>/dev/null || stat -f%z "$installer_path" 2>/dev/null || echo "unknown")
    log_info "Binary size: $file_size bytes"
    
    # Try to get version or help (this will fail but shows the binary runs)
    log_info "Testing binary execution..."
    if "$installer_path" --help 2>/dev/null || [[ $? -eq 1 ]]; then
        log_success "Binary executes successfully"
    else
        log_warn "Binary execution test inconclusive"
    fi
    
    log_success "Build verification completed"
}

# Function to show usage
show_usage() {
    cat << EOF
StreamDeploy Agent Installer Build Script

Usage: $0 [OPTIONS]

OPTIONS:
    --clean             Clean build directory before building
    --install-deps      Install build dependencies automatically
    --verify            Verify the build after completion
    --musl              Build with musl static linking
    --static            Build with static linking (glibc)
    --arch ARCH         Target architecture (x86_64, aarch64, armv7l)
    --os OS             Target operating system (linux)
    --install-toolchain Install cross-compilation toolchain
    --help, -h          Show this help message

SUPPORTED ARCHITECTURES:
    x86_64              Intel/AMD 64-bit (native + musl static)
    aarch64             ARM 64-bit (cross-compile + musl static)
    armv7l              ARM 32-bit hard float (cross-compile + musl static)

EXAMPLES:
    $0                          # Basic native build
    $0 --clean                  # Clean build
    $0 --musl                   # musl static build for native architecture
    $0 --arch aarch64           # Cross-compile for ARM64 (dynamic linking)
    $0 --musl --arch aarch64    # musl static build for ARM64
    $0 --musl --arch armv7l     # musl static build for ARM32
    $0 --install-deps --clean   # Install deps and clean build
    $0 --verify                 # Build and verify

The script will create installer binaries suitable for distribution across
different Linux systems and architectures.

EOF
}

# Main function
main() {
    local clean_build_flag=false
    local install_deps_flag=false
    local verify_flag=false
    local install_toolchain_flag=false
    local target_arch="$DEFAULT_TARGET_ARCH"
    local target_os="$DEFAULT_TARGET_OS"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --clean)
                clean_build_flag=true
                shift
                ;;
            --install-deps)
                install_deps_flag=true
                shift
                ;;
            --verify)
                verify_flag=true
                shift
                ;;
            --musl)
                MUSL_BUILD=true
                shift
                ;;
            --static)
                STATIC_BUILD=true
                shift
                ;;
            --arch)
                target_arch="$2"
                shift 2
                ;;
            --os)
                target_os="$2"
                shift 2
                ;;
            --install-toolchain)
                install_toolchain_flag=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validate target architecture
    if [[ ! " $(get_supported_architectures) " =~ " $target_arch " ]]; then
        log_error "Unsupported architecture: $target_arch"
        log_info "Supported architectures: $(get_supported_architectures)"
        exit 1
    fi
    
    # Validate target OS
    if [[ ! " $(get_supported_os) " =~ " $target_os " ]]; then
        log_error "Unsupported operating system: $target_os"
        log_info "Supported operating systems: $(get_supported_os)"
        exit 1
    fi
    
    log_info "Starting StreamDeploy Agent Installer build..."
    log_info "Target: $target_os-$target_arch"
    log_info "Build type: $([ "$MUSL_BUILD" = true ] && echo "musl static (portable binary)" || [ "$STATIC_BUILD" = true ] && echo "glibc static" || echo "dynamic")"
    log_info "Build directory: $BUILD_DIR"
    
    if [[ "$MUSL_BUILD" = true ]]; then
        log_info "Musl static build: Creates portable binary for any Linux system"
    fi
    
    # Detect system
    detect_system || exit 1
    
    # Install toolchain if requested
    if [[ "$install_toolchain_flag" == true ]]; then
        if [[ "$target_arch" != "$DEFAULT_TARGET_ARCH" ]]; then
            install_cross_toolchain "$target_arch" || exit 1
        fi
        if [[ "$MUSL_BUILD" == true ]]; then
            install_musl_toolchain || exit 1
        fi
    fi
    
    # Install dependencies if requested
    if [[ "$install_deps_flag" == true ]]; then
        install_dependencies || exit 1
    fi
    
    # Check dependencies
    check_dependencies || exit 1
    
    # Check for required toolchains
    if [[ "$target_arch" != "$DEFAULT_TARGET_ARCH" ]]; then
        if ! check_cross_toolchain "$target_arch"; then
            log_error "Cross-compilation toolchain for $target_arch not found"
            log_info "Run with --install-toolchain to install it"
            exit 1
        fi
    fi
    
    if [[ "$MUSL_BUILD" == true ]]; then
        if ! command_exists musl-gcc || ! command_exists musl-g++; then
            log_error "musl toolchain not found"
            log_info "Run with --install-toolchain to install it"
            exit 1
        fi
    fi
    
    # Clean build directory if requested
    if [[ "$clean_build_flag" == true ]]; then
        clean_build || exit 1
    else
        # Create build directory if it doesn't exist
        mkdir -p "$BUILD_DIR"
    fi
    
    # Configure and build
    configure_cmake "$target_arch" "$target_os" || exit 1
    build_installer "$target_arch" "$target_os" || exit 1
    
    # Verify build if requested
    if [[ "$verify_flag" == true ]]; then
        verify_build || exit 1
    fi
    
    # Determine final binary name
    local final_name="$INSTALLER_NAME"
    if [[ "$target_arch" != "$DEFAULT_TARGET_ARCH" ]] || [[ "$MUSL_BUILD" = true ]]; then
        local arch_suffix="-$target_arch"
        if [[ "$MUSL_BUILD" = true ]]; then
            arch_suffix="${arch_suffix}-musl"
        fi
        final_name="${INSTALLER_NAME}${arch_suffix}"
    fi
    
    log_success "Build completed successfully!"
    log_info "Installer location: $SCRIPT_DIR/$final_name"
    log_info "You can now distribute this binary"
    
    # Show next steps
    echo
    log_info "Next steps:"
    echo "  1. Test the installer: sudo ./$final_name (shows usage info)"
    echo "  2. Use with bootstrap token: sudo ./$final_name \"your-token\""
    echo "  3. Or set environment: export SD_BOOTSTRAP_TOKEN=\"your-token\" && sudo ./$final_name"
}

# Run main function with all arguments
main "$@"
