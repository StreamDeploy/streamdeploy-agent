# Build environment for StreamDeploy Agent with musl and multi-arch support
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install all required packages
RUN apt-get update -y && \
    apt-get install -y \
    build-essential cmake pkg-config git curl wget file \
    musl-tools musl-dev musl-libc \
    libc6-dev linux-libc-dev \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
    libcurl4-openssl-dev libssl-dev libmosquitto-dev nlohmann-json3-dev \
    libjsoncpp-dev libnghttp2-dev libidn2-dev \
    zlib1g-dev

# Set up musl toolchain properly
RUN echo '#!/bin/bash' > /usr/bin/musl-gcc && \
    echo 'exec gcc -static "$@"' >> /usr/bin/musl-gcc && \
    chmod +x /usr/bin/musl-gcc && \
    echo '#!/bin/bash' > /usr/bin/musl-g++ && \
    echo 'exec g++ -static "$@"' >> /usr/bin/musl-g++ && \
    chmod +x /usr/bin/musl-g++

# Enable multiarch and install cross-compilation libraries
RUN dpkg --add-architecture arm64 && \
    dpkg --add-architecture armhf

# Clean up existing sources to avoid conflicts
RUN rm -f /etc/apt/sources.list.d/*.list

# Create a clean multiarch sources configuration
RUN echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse" > /etc/apt/sources.list && \
    echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb [arch=amd64] http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "" >> /etc/apt/sources.list && \
    echo "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy-security main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "" >> /etc/apt/sources.list && \
    echo "deb [arch=armhf] http://ports.ubuntu.com/ubuntu-ports jammy main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb [arch=armhf] http://ports.ubuntu.com/ubuntu-ports jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb [arch=armhf] http://ports.ubuntu.com/ubuntu-ports jammy-security main restricted universe multiverse" >> /etc/apt/sources.list

# Install cross-compilation libraries for available architectures
# Only install essential packages to avoid conflicts
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    libssl-dev:arm64 libmosquitto-dev:arm64 \
    libjsoncpp-dev:arm64 libidn2-dev:arm64 \
    zlib1g-dev:arm64 && \
    apt-get install -y --no-install-recommends \
    libssl-dev:armhf libmosquitto-dev:armhf \
    libjsoncpp-dev:armhf libidn2-dev:armhf \
    zlib1g-dev:armhf && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*




