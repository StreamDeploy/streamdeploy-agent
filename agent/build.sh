#!/bin/bash

# StreamDeploy Agent Build Script
# This script builds the StreamDeploy agent with all dependencies

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color


# Configuration
BUILD_DIR="build"
BINARY_NAME="streamdeploy-agent"
CMAKE_BUILD_TYPE="Release"

# Cross-compilation configuration
DEFAULT_TARGET_ARCH="$(uname -m)"
DEFAULT_TARGET_OS="linux"
MUSL_BUILD=false
STATIC_BUILD=false

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get supported architectures
get_supported_architectures() {
    echo "x86_64 aarch64 armv7l armv6l"
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
        armv6l)
            echo "arm-linux-gnueabi"
            ;;
        *)
            print_error "Unsupported architecture: $arch"
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
    
    print_info "Installing cross-compilation toolchain for $arch..."
    
    case $(detect_os) in
        ubuntu)
            case "$arch" in
                x86_64)
                    sudo apt-get install -y gcc-multilib g++-multilib
                    ;;
                aarch64)
                    sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
                    ;;
                armv7l)
                    sudo apt-get install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
                    ;;
                armv6l)
                    sudo apt-get install -y gcc-arm-linux-gnueabi g++-arm-linux-gnueabi
                    ;;
            esac
            ;;
        centos)
            case "$arch" in
                x86_64)
                    sudo yum install -y gcc gcc-c++
                    ;;
                aarch64)
                    sudo yum install -y gcc-aarch64-linux-gnu gcc-c++-aarch64-linux-gnu
                    ;;
                armv7l)
                    sudo yum install -y gcc-arm-linux-gnu gcc-c++-arm-linux-gnu
                    ;;
            esac
            ;;
        alpine)
            case "$arch" in
                x86_64)
                    sudo apk add --no-cache gcc g++
                    ;;
                aarch64)
                    sudo apk add --no-cache gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
                    ;;
                armv7l)
                    sudo apk add --no-cache gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
                    ;;
            esac
            ;;
        *)
            print_error "Cross-compilation not supported for OS: $(detect_os)"
            return 1
            ;;
    esac
    
    print_success "Cross-compilation toolchain installed for $arch"
}

# Function to install musl toolchain
install_musl_toolchain() {
    print_info "Installing musl toolchain..."
    
    case $(detect_os) in
        ubuntu)
            sudo apt-get install -y musl-tools musl-dev
            ;;
        centos)
            sudo yum install -y musl-gcc musl-libc-static
            ;;
        alpine)
            sudo apk add --no-cache musl-dev
            ;;
        *)
            print_error "musl toolchain not available for OS: $(detect_os)"
            return 1
            ;;
    esac
    
    print_success "musl toolchain installed"
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "ubuntu"
        elif command_exists yum; then
            echo "centos"
        elif command_exists apk; then
            echo "alpine"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to install dependencies
install_dependencies() {
    local os=$(detect_os)
    print_info "Detected OS: $os"
    
    case $os in
        ubuntu)
            print_info "Installing dependencies with apt..."
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                cmake \
                pkg-config \
                libcurl4-openssl-dev \
                libssl-dev \
                libmosquitto-dev \
                nlohmann-json3-dev \
                git
            ;;
        centos)
            print_info "Installing dependencies with yum..."
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                cmake \
                pkgconfig \
                libcurl-devel \
                openssl-devel \
                git
            print_warning "nlohmann-json may need to be installed manually on CentOS"
            ;;
        alpine)
            print_info "Installing dependencies with apk..."
            sudo apk add --no-cache \
                build-base \
                cmake \
                pkgconfig \
                curl-dev \
                openssl-dev \
                mosquitto-dev \
                nlohmann-json \
                git
            ;;
        macos)
            print_info "Installing dependencies with brew..."
            if ! command_exists brew; then
                print_error "Homebrew is required on macOS. Please install it first."
                exit 1
            fi
            brew install cmake pkg-config curl openssl nlohmann-json
            ;;
        *)
            print_warning "Unknown OS. Please install dependencies manually:"
            print_warning "- CMake 3.16+"
            print_warning "- libcurl4-openssl-dev"
            print_warning "- libssl-dev"
            print_warning "- nlohmann-json3-dev"
            print_warning "- build-essential/gcc"
            ;;
    esac
}

# Function to check dependencies
check_dependencies() {
    print_info "Checking build dependencies..."
    
    local missing_deps=()
    
    if ! command_exists cmake; then
        missing_deps+=("cmake")
    else
        local cmake_version=$(cmake --version | head -n1 | grep -o '[0-9]\+\.[0-9]\+')
        local cmake_major=$(echo $cmake_version | cut -d. -f1)
        local cmake_minor=$(echo $cmake_version | cut -d. -f2)
        if [ "$cmake_major" -lt 3 ] || ([ "$cmake_major" -eq 3 ] && [ "$cmake_minor" -lt 16 ]); then
            print_error "CMake 3.16+ required, found $cmake_version"
            missing_deps+=("cmake (version 3.16+)")
        fi
    fi
    
    if ! command_exists gcc && ! command_exists clang; then
        missing_deps+=("gcc or clang")
    fi
    
    if ! command_exists pkg-config; then
        missing_deps+=("pkg-config")
    fi
    
    # Check for libcurl
    if ! pkg-config --exists libcurl; then
        missing_deps+=("libcurl-dev")
    fi
    
    # Check for openssl
    if ! pkg-config --exists openssl; then
        missing_deps+=("libssl-dev")
    fi
    
    # Check for mosquitto
    if ! pkg-config --exists libmosquitto; then
        missing_deps+=("libmosquitto-dev")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_info "Run with --install-deps to install them automatically"
        return 1
    fi
    
    print_success "All dependencies are available"
    return 0
}

# Function to setup nlohmann-json if not available
setup_nlohmann_json() {
    if ! pkg-config --exists nlohmann_json; then
        print_info "nlohmann-json not found via pkg-config, using bundled version..."
        
        # Create third_party directory if it doesn't exist
        mkdir -p ../third_party/nlohmann
        
        # Download nlohmann-json header if not present
        if [ ! -f "../third_party/nlohmann/json.hpp" ]; then
            print_info "Downloading nlohmann-json header..."
            curl -L -o ../third_party/nlohmann/json.hpp \
                https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
        fi
        
        print_success "Using bundled nlohmann-json"
    else
        print_info "Using system nlohmann-json"
    fi
}

# Function to create CMakeLists.txt
create_cmake_file() {
    local target_arch="${1:-$DEFAULT_TARGET_ARCH}"
    local target_os="${2:-$DEFAULT_TARGET_OS}"
    
    print_info "Creating CMakeLists.txt for $target_os-$target_arch..."
    
    cat > CMakeLists.txt << EOF
cmake_minimum_required(VERSION 3.16)
project(streamdeploy-agent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static linking configuration (set by build script for musl/static builds)
# set(CMAKE_EXE_LINKER_FLAGS "\${CMAKE_EXE_LINKER_FLAGS} -static")
# set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Find libcurl
pkg_check_modules(CURL REQUIRED libcurl)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find mosquitto
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)

# Try to find nlohmann-json via pkg-config first
pkg_check_modules(NLOHMANN_JSON nlohmann_json)

# Include directories
include_directories(\${CMAKE_CURRENT_SOURCE_DIR})
include_directories(\${CURL_INCLUDE_DIRS})
include_directories(\${MOSQUITTO_INCLUDE_DIRS})

# Check if we have system nlohmann-json
if(NLOHMANN_JSON_FOUND)
    include_directories(\${NLOHMANN_JSON_INCLUDE_DIRS})
    message(STATUS "Using system nlohmann-json")
else()
    # Use bundled version
    include_directories(\${CMAKE_CURRENT_SOURCE_DIR}/../third_party)
    message(STATUS "Using bundled nlohmann-json")
endif()

# Source files
set(SOURCES
    main.cpp
    agent.cpp
    config_manager.cpp
    metrics_collector.cpp
    container_manager.cpp
    certificate_manager.cpp
    mqtt_client.cpp
    https_client.cpp
    package_manager.cpp
)

# Create executable
add_executable(\${PROJECT_NAME} \${SOURCES})

# Link libraries
target_link_libraries(\${PROJECT_NAME}
    \${CURL_LIBRARIES}
    \${MOSQUITTO_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Compiler flags
target_compile_options(\${PROJECT_NAME} PRIVATE \${CURL_CFLAGS_OTHER} \${MOSQUITTO_CFLAGS_OTHER})

# Set output name
set_target_properties(\${PROJECT_NAME} PROPERTIES OUTPUT_NAME "streamdeploy-agent")

# Install target
install(TARGETS \${PROJECT_NAME} DESTINATION bin)
EOF

    print_success "CMakeLists.txt created"
}

# Function to build the project
build_project() {
    local target_arch="${1:-$DEFAULT_TARGET_ARCH}"
    local target_os="${2:-$DEFAULT_TARGET_OS}"
    
    print_info "Building StreamDeploy Agent for $target_os-$target_arch..."
    print_info "Build type: $([ "$MUSL_BUILD" = true ] && echo "musl static" || [ "$STATIC_BUILD" = true ] && echo "glibc static" || echo "dynamic")"
    
    # Create build directory
    if [ -d "$BUILD_DIR" ]; then
        print_info "Cleaning existing build directory..."
        rm -rf "$BUILD_DIR"
    fi
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    # Set up CMake arguments
    local CMAKE_ARGS=()
    local CC_COMPILER
    local CXX_COMPILER
    
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
        print_error "Required compilers not found: $CC_COMPILER, $CXX_COMPILER"
        exit 1
    fi
    
    print_info "Using compilers: $CC_COMPILER, $CXX_COMPILER"
    
    # Configure with CMake
    print_info "Configuring with CMake..."
    cmake -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
          -DCMAKE_C_COMPILER="$CC_COMPILER" \
          -DCMAKE_CXX_COMPILER="$CXX_COMPILER" \
          "${CMAKE_ARGS[@]}" ..
    
    # Build
    print_info "Compiling..."
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    
    # Create architecture-specific binary name
    local arch_suffix=""
    if [[ "$target_arch" != "$DEFAULT_TARGET_ARCH" ]] || [[ "$MUSL_BUILD" = true ]]; then
        arch_suffix="-$target_arch"
        if [[ "$MUSL_BUILD" = true ]]; then
            arch_suffix="${arch_suffix}-musl"
        fi
    fi
    
    local final_name="${BINARY_NAME}${arch_suffix}"
    
    # Copy binary to parent directory with architecture-specific name
    if [ -f "$BINARY_NAME" ]; then
        cp "$BINARY_NAME" "../$final_name"
        print_success "Binary created: $final_name"
    else
        print_error "Build failed - binary not found"
        exit 1
    fi
    
    cd ..
}

# Function to create systemd service file
create_systemd_service() {
    print_info "Creating systemd service file..."
    
    cat > streamdeploy-agent.service << 'EOF'
[Unit]
Description=StreamDeploy Agent
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/streamdeploy-agent /etc/streamdeploy/agent.json
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/streamdeploy /var/lib/streamdeploy /var/log

[Install]
WantedBy=multi-user.target
EOF

    print_success "systemd service file created: streamdeploy-agent.service"
}

# Function to show usage
show_usage() {
    echo "StreamDeploy Agent Build Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help              Show this help message"
    echo "  --install-deps      Install build dependencies"
    echo "  --check-deps        Check if dependencies are installed"
    echo "  --clean             Clean build directory"
    echo "  --debug             Build in debug mode"
    echo "  --service           Create systemd service file"
    echo "  --install           Install binary to /usr/local/bin (requires sudo)"
    echo "  --musl              Build with musl static linking"
    echo "  --static            Build with static linking (glibc)"
    echo "  --arch ARCH         Target architecture (x86_64, aarch64, armv7l, armv6l)"
    echo "  --os OS             Target operating system (linux)"
    echo "  --install-toolchain Install cross-compilation toolchain"
    echo ""
    echo "Supported Architectures:"
    echo "  x86_64              Intel/AMD 64-bit"
    echo "  aarch64             ARM 64-bit"
    echo "  armv7l              ARM 32-bit (hard float)"
    echo "  armv6l              ARM 32-bit (soft float)"
    echo ""
    echo "Examples:"
    echo "  $0                          # Basic native build"
    echo "  $0 --install-deps           # Install dependencies and build"
    echo "  $0 --debug                  # Build in debug mode"
    echo "  $0 --clean                  # Clean and rebuild"
    echo "  $0 --musl                   # musl static build"
    echo "  $0 --arch aarch64           # Cross-compile for ARM64"
    echo "  $0 --musl --arch aarch64    # musl static build for ARM64"
}

# Main script logic
main() {
    local install_deps=false
    local check_deps_only=false
    local clean_build=false
    local create_service=false
    local install_binary=false
    local install_toolchain=false
    local target_arch="$DEFAULT_TARGET_ARCH"
    local target_os="$DEFAULT_TARGET_OS"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_usage
                exit 0
                ;;
            --install-deps)
                install_deps=true
                shift
                ;;
            --check-deps)
                check_deps_only=true
                shift
                ;;
            --clean)
                clean_build=true
                shift
                ;;
            --debug)
                CMAKE_BUILD_TYPE="Debug"
                shift
                ;;
            --service)
                create_service=true
                shift
                ;;
            --install)
                install_binary=true
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
                install_toolchain=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validate target architecture
    if [[ ! " $(get_supported_architectures) " =~ " $target_arch " ]]; then
        print_error "Unsupported architecture: $target_arch"
        print_info "Supported architectures: $(get_supported_architectures)"
        exit 1
    fi
    
    # Validate target OS
    if [[ ! " $(get_supported_os) " =~ " $target_os " ]]; then
        print_error "Unsupported operating system: $target_os"
        print_info "Supported operating systems: $(get_supported_os)"
        exit 1
    fi
    
    print_info "StreamDeploy Agent Build Script"
    print_info "Target: $target_os-$target_arch"
    print_info "Build type: $([ "$MUSL_BUILD" = true ] && echo "musl static" || [ "$STATIC_BUILD" = true ] && echo "glibc static" || echo "dynamic")"
    print_info "CMake build type: $CMAKE_BUILD_TYPE"
    
    # Clean if requested
    if [ "$clean_build" = true ]; then
        print_info "Cleaning build directory..."
        rm -rf "$BUILD_DIR" "$BINARY_NAME"*
    fi
    
    # Install toolchain if requested
    if [ "$install_toolchain" = true ]; then
        if [ "$target_arch" != "$DEFAULT_TARGET_ARCH" ]; then
            install_cross_toolchain "$target_arch"
        fi
        if [ "$MUSL_BUILD" = true ]; then
            install_musl_toolchain
        fi
    fi
    
    # Install dependencies if requested
    if [ "$install_deps" = true ]; then
        install_dependencies
    fi
    
    # Check dependencies
    if ! check_dependencies; then
        if [ "$install_deps" = false ]; then
            print_error "Dependencies missing. Run with --install-deps to install them."
            exit 1
        fi
    fi
    
    # Check for required toolchains
    if [ "$target_arch" != "$DEFAULT_TARGET_ARCH" ]; then
        if ! check_cross_toolchain "$target_arch"; then
            print_error "Cross-compilation toolchain for $target_arch not found"
            print_info "Run with --install-toolchain to install it"
            exit 1
        fi
    fi
    
    if [ "$MUSL_BUILD" = true ]; then
        if ! command_exists musl-gcc || ! command_exists musl-g++; then
            print_error "musl toolchain not found"
            print_info "Run with --install-toolchain to install it"
            exit 1
        fi
    fi
    
    # Exit if only checking dependencies
    if [ "$check_deps_only" = true ]; then
        exit 0
    fi
    
    # Setup nlohmann-json
    setup_nlohmann_json
    
    # Create CMakeLists.txt
    create_cmake_file "$target_arch" "$target_os"
    
    # Build the project
    build_project "$target_arch" "$target_os"
    
    # Create systemd service if requested
    if [ "$create_service" = true ]; then
        create_systemd_service
    fi
    
    # Determine final binary name
    local final_name="$BINARY_NAME"
    if [ "$target_arch" != "$DEFAULT_TARGET_ARCH" ] || [ "$MUSL_BUILD" = true ]; then
        local arch_suffix="-$target_arch"
        if [ "$MUSL_BUILD" = true ]; then
            arch_suffix="${arch_suffix}-musl"
        fi
        final_name="${BINARY_NAME}${arch_suffix}"
    fi
    
    # Install binary if requested
    if [ "$install_binary" = true ]; then
        print_info "Installing binary to /usr/local/bin..."
        sudo cp "$final_name" /usr/local/bin/
        sudo chmod +x /usr/local/bin/"$final_name"
        print_success "Binary installed to /usr/local/bin/$final_name"
    fi
    
    print_success "Build completed successfully!"
    print_info "Binary: ./$final_name"
    
    if [ "$create_service" = true ]; then
        print_info "To install the systemd service:"
        print_info "  sudo cp streamdeploy-agent.service /etc/systemd/system/"
        print_info "  sudo systemctl daemon-reload"
        print_info "  sudo systemctl enable streamdeploy-agent"
        print_info "  sudo systemctl start streamdeploy-agent"
    fi
}

# Run main function
main "$@"
