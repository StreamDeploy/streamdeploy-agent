# musl Cross-Compilation Guide

This document explains how to use the enhanced build scripts to create musl static binaries for various operating systems and architectures.

## Overview

Both `install/build.sh` and `agent/build.sh` now support:
- **musl static compilation** for maximum portability
- **Cross-compilation** to different architectures
- **Multiple target OS/arch combinations**
- **Automatic toolchain installation**

## Supported Targets

### Architectures
- **x86_64** - Intel/AMD 64-bit processors
- **aarch64** - ARM 64-bit processors (Jetson, Raspberry Pi 4+, Apple Silicon)
- **armv7l** - ARM 32-bit processors with hard float (Raspberry Pi 3)
- **armv6l** - ARM 32-bit processors with soft float (older Raspberry Pi)

### Operating Systems
- **linux** - All Linux distributions

## Build Types

### 1. Dynamic Linking (Default)
```bash
# Native build
./build.sh

# Cross-compile for ARM64
./build.sh --arch aarch64
```

### 2. musl Static Linking
```bash
# Native musl build
./build.sh --musl

# Cross-compile musl for ARM64
./build.sh --musl --arch aarch64
```

### 3. glibc Static Linking
```bash
# Native static build
./build.sh --static

# Cross-compile static for ARM64
./build.sh --static --arch aarch64
```

## Installation and Setup

### Prerequisites

The build scripts can automatically install required toolchains:

```bash
# Install cross-compilation toolchain for ARM64
./build.sh --install-toolchain --arch aarch64

# Install musl toolchain
./build.sh --install-toolchain --musl

# Install both for musl cross-compilation
./build.sh --install-toolchain --musl --arch aarch64
```

### Manual Installation

#### Ubuntu/Debian
```bash
# Cross-compilation toolchains
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
sudo apt-get install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
sudo apt-get install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi

# musl toolchain
sudo apt-get install musl-tools musl-dev
```

#### CentOS/RHEL/Fedora
```bash
# Cross-compilation toolchains
sudo yum install gcc-aarch64-linux-gnu gcc-c++-aarch64-linux-gnu
sudo yum install gcc-arm-linux-gnu gcc-c++-arm-linux-gnu

# musl toolchain
sudo yum install musl-gcc musl-libc-static
```

#### Alpine Linux
```bash
# Cross-compilation toolchains
sudo apk add gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
sudo apk add gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf

# musl toolchain (already available)
sudo apk add musl-dev
```

## Usage Examples

### Installer Build Examples

```bash
# Basic native build
cd install
./build.sh

# musl static build for current architecture
./build.sh --musl

# Cross-compile for ARM64
./build.sh --arch aarch64

# musl static build for ARM64
./build.sh --musl --arch aarch64

# Install toolchain and build
./build.sh --install-toolchain --musl --arch aarch64

# Clean build with verification
./build.sh --clean --verify --musl --arch aarch64
```

### Agent Build Examples

```bash
# Basic native build
cd agent
./build.sh

# musl static build for current architecture
./build.sh --musl

# Cross-compile for ARM64
./build.sh --arch aarch64

# musl static build for ARM64
./build.sh --musl --arch aarch64

# Debug build with musl
./build.sh --debug --musl

# Install toolchain and build
./build.sh --install-toolchain --musl --arch aarch64
```

## Output Files

The build scripts create architecture-specific binary names:

### Installer
- `streamdeploy-installer` - Native build
- `streamdeploy-installer-x86_64` - Cross-compiled for x86_64
- `streamdeploy-installer-aarch64` - Cross-compiled for ARM64
- `streamdeploy-installer-aarch64-musl` - musl static build for ARM64

### Agent
- `streamdeploy-agent` - Native build
- `streamdeploy-agent-x86_64` - Cross-compiled for x86_64
- `streamdeploy-agent-aarch64` - Cross-compiled for ARM64
- `streamdeploy-agent-aarch64-musl` - musl static build for ARM64

## Verification

### Check Static Linking
```bash
# For musl builds, this should show "not a dynamic executable"
ldd streamdeploy-installer-aarch64-musl

# For dynamic builds, this shows linked libraries
ldd streamdeploy-installer-aarch64
```

### Check Architecture
```bash
# Check binary architecture
file streamdeploy-installer-aarch64-musl
# Output: streamdeploy-installer-aarch64-musl: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
```

### Test Execution
```bash
# Test the binary (will show usage info)
./streamdeploy-installer-aarch64-musl --help
```

## Distribution

### musl Static Binaries
musl static binaries are highly portable and can run on:
- Any Linux distribution
- Minimal containers (Alpine, distroless)
- Embedded systems
- Systems without glibc

### Cross-Compiled Binaries
Cross-compiled binaries work on:
- Target architecture systems
- Systems with compatible glibc version
- Container environments

## Troubleshooting

### Common Issues

1. **Missing Toolchain**
   ```
   [ERROR] Cross-compilation toolchain for aarch64 not found
   ```
   **Solution**: Run with `--install-toolchain`

2. **Missing musl Toolchain**
   ```
   [ERROR] musl toolchain not found
   ```
   **Solution**: Run with `--install-toolchain --musl`

3. **Build Dependencies Missing**
   ```
   [ERROR] Missing dependencies: libcurl-dev
   ```
   **Solution**: Run with `--install-deps`

4. **Cross-Compilation Library Issues**
   ```
   [ERROR] Could not find libcurl
   ```
   **Solution**: Install target architecture development libraries

### Debug Information

Enable debug output:
```bash
# For installer
./build.sh --debug --musl --arch aarch64

# For agent
./build.sh --debug --musl --arch aarch64
```

Check build logs:
```bash
# CMake configuration details
cat build/CMakeCache.txt

# Build error logs
cat build/CMakeFiles/CMakeError.log
```

## Advanced Usage

### Custom Build Environment

Set environment variables for custom toolchain paths:
```bash
export CC=/path/to/custom/musl-gcc
export CXX=/path/to/custom/musl-g++
./build.sh --musl
```

### Multiple Architecture Builds

Build for multiple architectures:
```bash
# Build for all supported architectures
for arch in x86_64 aarch64 armv7l armv6l; do
    ./build.sh --musl --arch $arch
done
```

### CI/CD Integration

Example GitHub Actions workflow:
```yaml
- name: Build musl static binaries
  run: |
    cd install
    for arch in x86_64 aarch64 armv7l; do
      ./build.sh --install-toolchain --musl --arch $arch
    done
```

## Performance Considerations

### Build Time
- musl builds are typically slower than dynamic builds
- Cross-compilation adds overhead
- Static linking increases binary size

### Runtime Performance
- musl static binaries have minimal startup overhead
- No dynamic library loading
- Smaller memory footprint
- Better for containerized environments

## Security Benefits

### musl Static Binaries
- No external library dependencies
- Reduced attack surface
- Consistent behavior across systems
- No library version conflicts

### Distribution Security
- Single binary deployment
- No dependency on system libraries
- Easier to verify and audit
- Reduced supply chain risks
