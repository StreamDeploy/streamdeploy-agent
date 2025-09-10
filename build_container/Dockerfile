# Build environment for StreamDeploy Agent with musl and multi-arch support
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install all required packages
RUN apt-get update -y && \
    apt-get install -y \
    build-essential cmake pkg-config git curl wget file \
    musl-tools musl-dev \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
    gcc-arm-linux-gnueabi g++-arm-linux-gnueabi \
    libcurl4-openssl-dev libssl-dev libmosquitto-dev nlohmann-json3-dev \
    libjsoncpp-dev libnghttp2-dev libidn2-dev

# Enable multiarch and install cross-compilation libraries
RUN dpkg --add-architecture arm64 && \
    dpkg --add-architecture armhf && \
    dpkg --add-architecture armel

# Clean up any existing multiarch sources to avoid conflicts
RUN rm -f /etc/apt/sources.list.d/multiarch.list

# Configure multiarch sources properly
RUN echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse" > /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=amd64] http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy-security main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=armhf] http://ports.ubuntu.com/ubuntu-ports jammy main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=armhf] http://ports.ubuntu.com/ubuntu-ports jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=armhf] http://ports.ubuntu.com/ubuntu-ports jammy-security main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=armel] http://ports.ubuntu.com/ubuntu-ports jammy main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=armel] http://ports.ubuntu.com/ubuntu-ports jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list && \
    echo "deb [arch=armel] http://ports.ubuntu.com/ubuntu-ports jammy-security main restricted universe multiverse" >> /etc/apt/sources.list.d/multiarch.list

# Install cross-compilation libraries for all architectures
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    libcurl4-openssl-dev:arm64 libssl-dev:arm64 libmosquitto-dev:arm64 \
    libcurl4-openssl-dev:armhf libssl-dev:armhf libmosquitto-dev:armhf \
    libcurl4-openssl-dev:armel libssl-dev:armel libmosquitto-dev:armel \
    libjsoncpp-dev:arm64 libnghttp2-dev:arm64 libidn2-dev:arm64 \
    libjsoncpp-dev:armhf libnghttp2-dev:armhf libidn2-dev:armhf \
    libjsoncpp-dev:armel libnghttp2-dev:armel libidn2-dev:armel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*




