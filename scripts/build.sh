#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install -y build-essential cmake libcurl4-openssl-dev docker.io

sudo systemctl enable --now docker

cd "$(dirname "$0")/.."
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j"$(nproc)"

sudo install -m 0755 streamdeploy-agent /usr/local/bin/streamdeploy-agent
sudo mkdir -p /etc/streamdeploy /var/lib/streamdeploy
[ -f ../config/agent.json ] && sudo cp ../config/agent.json /etc/streamdeploy/agent.json

sudo cp ../systemd/streamdeploy-agent.service /etc/systemd/system/streamdeploy-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now streamdeploy-agent

echo "✅ StreamDeploy pull agent installed and running."
