#!/bin/bash

# Build script for SSH tunnel example
set -e

echo "Building SSH tunnel example..."

# Change to the examples directory
cd "$(dirname "$0")"

# Build the example
go build -o ssh_tunnel_example ssh_tunnel_example.go

echo "Build successful! Run with: ./ssh_tunnel_example"
echo ""
echo "Note: This is a demonstration example with mock implementations."
echo "In a real deployment, you would use actual implementations of:"
echo "- Logger (for proper logging)"
echo "- ConfigManager (for configuration management)"
echo "- HTTPClient (for HTTP communication)"
echo "- MQTTClient (for MQTT communication)"
echo ""
echo "The example shows how to:"
echo "1. Initialize the core agent"
echo "2. Create and configure the SSH tunnel manager"
echo "3. Start the agent with SSH tunnel support"
echo "4. Handle graceful shutdown"
