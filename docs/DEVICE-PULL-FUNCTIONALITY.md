# Device Pull Functionality Implementation

This document describes the enhanced device pull functionality that has been implemented in the StreamDeploy agent, including heartbeat storage, system metrics collection, and status update enhancements.

## Overview

The agent now implements your exact heartbeat and status update data formats with the following key features:

- **Enhanced Heartbeat Format**: Matches your specification with CPU%, memory%, container details, and custom metrics
- **Detailed Status Updates**: Includes agent settings, environment variables, container details, and scripts
- **Local Heartbeat Storage**: Persistent storage of heartbeat data on device
- **Fault-Tolerant Metrics Collection**: Graceful degradation when metrics can't be collected
- **Configurable Custom Metrics**: User-defined metrics via configuration files

## Heartbeat Format

The agent now sends heartbeats in your exact format:

```json
{
  "status": "normal",
  "agent_setting": {
    "heartbeat_frequency": "15s",
    "update_frequency": "30s",
    "agent_ver": "1"
  },
  "metrics": {
    "cpu_pct": 12.3,
    "mem_pct": 41.7,
    "containers": [
      {
        "name": "sd-app",
        "image": "ghcr.io/acme/app@sha256:abcd...",
        "status": "ready"
      }
    ],
    "custom": {
      "temperature": "45.2",
      "disk_usage": "67",
      "test": "ok"
    }
  }
}
```

## Status Update Format

Status updates now include detailed current_state information:

```json
{
  "update_type": "update_check",
  "status": "normal",
  "current_state": {
    "agent_setting": {
      "heartbeat_frequency": "15s",
      "update_frequency": "30s",
      "agent_ver": "1"
    },
    "env": {
      "DEVICE_ID": "orin01",
      "DEVICE_CLASS": "orin",
      "FOO": "bar",
      "FEATURE_FLAG": "on"
    },
    "containers": [
      {
        "name": "sd-app",
        "image": "ghcr.io/acme/app@sha256:abcd...",
        "env": {},
        "probing": "http://localhost:80/healthz",
        "status": "ready"
      }
    ],
    "scripts": [
      {
        "name": "health_check",
        "cmd": "curl -f http://localhost:80/healthz || echo 'unhealthy'"
      },
      {
        "name": "test",
        "cmd": "ls"
      }
    ]
  }
}
```

## Configuration Files

### Custom Metrics (`/etc/streamdeploy/custom_metrics.json`)

Define custom metrics that will be executed and included in heartbeats:

```json
{
  "temperature": "cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{print $1/1000}' || echo '0'",
  "disk_usage": "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'",
  "uptime": "uptime | awk '{print $3}' | sed 's/,//'",
  "load_avg": "uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//'",
  "test": "ok"
}
```

### Environment Variables (`/etc/streamdeploy/environment.json`)

Define environment variables to include in status updates:

```json
{
  "DEVICE_ID": "orin01",
  "DEVICE_CLASS": "orin",
  "FOO": "bar",
  "FEATURE_FLAG": "on",
  "DEPLOYMENT_ENV": "production",
  "LOG_LEVEL": "info"
}
```

### Scripts (`/etc/streamdeploy/scripts.json`)

Define scripts that can be executed on the device:

```json
[
  {
    "name": "health_check",
    "cmd": "curl -f http://localhost:80/healthz || echo 'unhealthy'"
  },
  {
    "name": "system_info",
    "cmd": "uname -a"
  },
  {
    "name": "disk_check",
    "cmd": "df -h /"
  },
  {
    "name": "test",
    "cmd": "ls"
  }
]
```

## Heartbeat Storage

Heartbeat data is now stored locally on the device at `/var/lib/streamdeploy/heartbeat.json`. Features:

- **Persistent Storage**: Heartbeats are saved with timestamps
- **Rotation**: Only the last 100 heartbeats are kept
- **Atomic Writes**: Uses temporary files to prevent corruption
- **Fault Tolerance**: Storage failures don't affect agent operation

## System Metrics Collection

The agent collects system metrics with fault tolerance:

### CPU Percentage
- Uses `top` command to get current CPU usage
- Falls back to 0.0 if collection fails
- Handles parsing errors gracefully

### Memory Percentage
- Reads from `/proc/meminfo` for total and available memory
- Calculates used percentage: `((total - available) / total) * 100`
- Falls back to 0.0 if collection fails

### Container Information
- Uses `docker ps` to get running container details
- Includes container name, image, and status
- Maps Docker status to "ready" or "stopped"
- Provides fallback container info if Docker is unavailable

## Fault Tolerance Features

1. **Graceful Degradation**: If any metric collection fails, the agent continues with default values
2. **Error Isolation**: Failures in one metric don't affect others
3. **Best-Effort Delivery**: Heartbeats and status updates are sent even with partial data
4. **Configuration Fallbacks**: Default values are used if configuration files are missing
5. **Storage Resilience**: Heartbeat storage failures don't crash the agent

## File Locations

- **Heartbeat Storage**: `/var/lib/streamdeploy/heartbeat.json`
- **Custom Metrics Config**: `/etc/streamdeploy/custom_metrics.json`
- **Environment Config**: `/etc/streamdeploy/environment.json`
- **Scripts Config**: `/etc/streamdeploy/scripts.json`
- **Agent Logs**: `/var/log/streamdeploy-agent/agent.log`

## API Endpoints

The agent communicates with these platform endpoints:

- **Heartbeat**: `POST /v1-device/heartbeat`
- **Status Update**: `POST /v1-device/status-update`

Both endpoints use mTLS authentication with the `X-Device-Id` header.

## Deployment

### Automatic Installation (Recommended)
```bash
export SD_BOOTSTRAP_TOKEN="your-token-from-platform"
curl -fsSL https://api.streamdeploy.com/v1-app/enroll/install.sh | sudo sh
```

### Manual Deployment
1. **Build**: Use the existing CMake build system
2. **Configuration**: Copy configuration files to `/etc/streamdeploy/`
3. **Permissions**: Ensure proper file permissions (600 for secrets, 644 for configs)
4. **Service**: Deploy using the existing systemd service

### Configuration Files
- Copy `config/custom_metrics.json` to `/etc/streamdeploy/custom_metrics.json`
- Copy `config/environment.json` to `/etc/streamdeploy/environment.json`
- Copy `config/scripts.json` to `/etc/streamdeploy/scripts.json`

## Testing

The implementation has been tested for:

- ✅ Compilation without errors
- ✅ Fault tolerance with missing configuration files
- ✅ Graceful handling of system command failures
- ✅ Proper JSON formatting for both heartbeat and status update payloads
- ✅ Heartbeat storage and rotation functionality

## Monitoring

Monitor the agent through:

- **Log Files**: `/var/log/streamdeploy-agent/agent.log`
- **Heartbeat Storage**: Check `/var/lib/streamdeploy/heartbeat.json` for recent data
- **Platform Dashboard**: View heartbeat and status data in the StreamDeploy platform
