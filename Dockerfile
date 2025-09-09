# Build environment for StreamDeploy Agent with musl
FROM alpine:3.19

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    cmake \
    pkgconfig \
    curl-dev \
    openssl-dev \
    mosquitto-dev \
    nlohmann-json \
    git \
    linux-headers

# Set working directory
WORKDIR /workspaces/streamdeploy-agent

# Copy source code
COPY . .

# Build the agent
WORKDIR /workspaces/streamdeploy-agent/agent
RUN ./build.sh --clean

# The binary is now available at /workspaces/streamdeploy-agent/agent/streamdeploy-agent
# This is a musl-linked binary that can be copied to any Alpine-based system
