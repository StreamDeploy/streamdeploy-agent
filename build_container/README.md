# StreamDeploy Agent Build Container

This Docker container provides a comprehensive build environment for the StreamDeploy Agent with multi-architecture cross-compilation support.

## Overview

The build container is based on Ubuntu 22.04 and includes all necessary tools and libraries for building the StreamDeploy Agent across multiple architectures. It supports both native builds and cross-compilation for ARM architectures.

## Supported Architectures

### Native Architecture
- **x86_64 (AMD64)** - Native build support

### Cross-Compilation Targets
- **ARM64 (aarch64)** - 64-bit ARM architecture
- **ARMHF (armv7l)** - 32-bit ARM with hard float

### Architecture Support Summary
| Architecture | Build Type | Status | Common Robotics Boards | Notes |
|--------------|------------|--------|----------------------|-------|
| x86_64 | Native | ✅ Supported | Intel NUC, Up Board, LattePanda, BeagleV-Fire | Default build platform |
| ARM64 | Cross-compile | ✅ Supported | Raspberry Pi 4/5, NVIDIA Jetson Nano/Orin, Rock Pi 4, Orange Pi 5 | 64-bit ARM |
| ARMHF (armv7l) | Cross-compile | ✅ Supported | Raspberry Pi 3/Zero, BeagleBone Black, Odroid XU4, Banana Pi | 32-bit ARM with hard float |

## Common Robotics Boards by Architecture

### x86_64 (AMD64) Boards
Popular single-board computers and mini PCs used in robotics:

- **Intel NUC** - Compact, powerful mini PCs ideal for complex robotics applications
- **Up Board** - x86-based SBC with Arduino-compatible headers
- **LattePanda** - Windows/Linux compatible SBC with built-in Arduino
- **BeagleV-Fire** - RISC-V based board with x86 compatibility
- **Jetson Xavier NX** - NVIDIA's ARM-based but with x86 emulation support

### ARM64 (aarch64) Boards
64-bit ARM single-board computers commonly used in modern robotics:

- **Raspberry Pi 4/5** - Most popular SBC for robotics projects
- **NVIDIA Jetson Nano/Orin** - AI-focused boards with GPU acceleration
- **Rock Pi 4** - High-performance ARM64 SBC
- **Orange Pi 5** - Affordable ARM64 alternative to Raspberry Pi
- **Jetson Xavier NX** - High-performance AI computing board
- **Khadas VIM3** - Compact ARM64 board with neural processing unit

### ARMHF (armv7l) Boards
32-bit ARM boards still widely used in robotics:

- **Raspberry Pi 3/Zero** - Popular for lightweight robotics projects
- **BeagleBone Black** - Industrial-grade SBC with real-time capabilities
- **Odroid XU4** - High-performance 32-bit ARM board
- **Banana Pi** - Raspberry Pi compatible alternative
- **Pine64** - Various ARMHF boards for different use cases
- **NanoPi** - Compact ARMHF boards for embedded applications

## Build Tools and Compilers

### Native Build Tools
- `build-essential` - Essential build tools (gcc, g++, make, etc.)
- `cmake` - CMake build system
- `pkg-config` - Package configuration tool
- `musl-tools` - Musl C library tools
- `musl-dev` - Musl development headers

### Cross-Compilation Toolchains
- `gcc-aarch64-linux-gnu` - ARM64 cross-compiler
- `g++-aarch64-linux-gnu` - ARM64 C++ cross-compiler
- `gcc-arm-linux-gnueabihf` - ARMHF cross-compiler
- `g++-arm-linux-gnueabihf` - ARMHF C++ cross-compiler

## Available Libraries

### Native Libraries (x86_64)
- `libcurl4-openssl-dev` - cURL development library
- `libssl-dev` - OpenSSL development library
- `libmosquitto-dev` - MQTT client library
- `nlohmann-json3-dev` - JSON library
- `libjsoncpp-dev` - JSON C++ library
- `libnghttp2-dev` - HTTP/2 library
- `libidn2-dev` - Internationalized domain names library

### Cross-Compilation Libraries
The following libraries are available for ARM64 and ARMHF cross-compilation:

#### ARM64 Libraries
- `libssl-dev:arm64` - OpenSSL development library
- `libmosquitto-dev:arm64` - MQTT client library
- `libjsoncpp-dev:arm64` - JSON C++ library
- `libidn2-dev:arm64` - Internationalized domain names library

#### ARMHF (armv7l) Libraries
- `libssl-dev:armhf` - OpenSSL development library
- `libmosquitto-dev:armhf` - MQTT client library
- `libjsoncpp-dev:armhf` - JSON C++ library
- `libidn2-dev:armhf` - Internationalized domain names library

### Library Limitations
- **libcurl4-openssl-dev**: Only available for native x86_64 builds due to shared binary conflicts
- **libnghttp2-dev**: Not available for cross-compilation due to architecture conflicts
- **nlohmann-json3-dev**: Header-only library, works for all architectures

## Usage

### Building the Container
```bash
docker build -t streamdeploy-build-container .
```

### Running the Container
```bash
# Interactive shell
docker run -it --rm streamdeploy-build-container /bin/bash

# Mount source code and build
docker run -it --rm -v $(pwd):/workspace streamdeploy-build-container /bin/bash
```

### Cross-Compilation Examples

#### Building for ARM64
```bash
# Set up ARM64 cross-compilation environment
export CC=aarch64-linux-gnu-gcc
export CXX=aarch64-linux-gnu-g++
export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig

# Build your project
cmake -DCMAKE_TOOLCHAIN_FILE=arm64-toolchain.cmake .
make
```

#### Building for ARMHF (armv7l)
```bash
# Set up ARMHF cross-compilation environment
export CC=arm-linux-gnueabihf-gcc
export CXX=arm-linux-gnueabihf-g++
export PKG_CONFIG_PATH=/usr/lib/arm-linux-gnueabihf/pkgconfig

# Build your project
cmake -DCMAKE_TOOLCHAIN_FILE=armhf-toolchain.cmake .
make
```

## Repository Configuration

The container uses a custom APT repository configuration to support multi-architecture packages:

- **AMD64 packages**: Fetched from `archive.ubuntu.com`
- **ARM packages**: Fetched from `ports.ubuntu.com`

This configuration ensures that all required packages are available for cross-compilation.

## Musl Support

The container includes musl C library support for building statically linked binaries:

- `musl-tools` - Musl build tools
- `musl-dev` - Musl development headers

This is particularly useful for creating portable, statically linked executables.

## Environment Variables

- `DEBIAN_FRONTEND=noninteractive` - Prevents interactive prompts during package installation

## File Structure

```
build_container/
├── Dockerfile          # Container definition
└── README.md          # This documentation
```

## Troubleshooting

### Common Issues

1. **Package conflicts**: Some packages may conflict between architectures. The container excludes problematic packages like `libcurl4-openssl-dev` for cross-compilation.

2. **Missing libraries**: If you need additional libraries for cross-compilation, you may need to build them from source or find alternative packages.

3. **Repository issues**: The container uses a custom repository configuration. If you encounter package availability issues, check the repository configuration in the Dockerfile.

### Getting Help

If you encounter issues with the build container:

1. Check the Docker build logs for specific error messages
2. Verify that the required packages are available for your target architecture
3. Ensure your build scripts are properly configured for cross-compilation

## License

This build container is part of the StreamDeploy Agent project. Please refer to the main project license for usage terms.
