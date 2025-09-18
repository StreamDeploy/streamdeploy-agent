# SSH Tunnel Implementation

This document describes the SSH tunnel functionality implemented in the StreamDeploy Agent.

## Overview

The SSH tunnel feature allows secure remote access to devices through the StreamDeploy platform. When a tunnel command is received via the `tmp` field in status updates, the agent establishes a WebSocket connection to tunnel SSH traffic.

## Architecture

### Command Format

The SSH tunnel is initiated via a command in the base response:

```json
{
  "cmd": "custom ssh user_456 2024-01-01T12:00:00Z",
  "new_state": {
    "schemaVersion": "1.0",
    "agent_setting": { ... },
    "containers": [ ... ],
    "env": { ... },
    "packages": [ ... ],
    "custom_metrics": { ... },
    "custom_packages": { ... }
  }
}
```

Where:
- `custom` - Indicates this is an internal communication command (not a shell command)
- `ssh` - Specifies the tunnel type
- `user_456` - The user identifier for the tunnel
- `2024-01-01T12:00:00Z` - Expiration time in RFC3339 format

## Command Type Determination

The agent determines how to handle the `cmd` command based on its format:

### Custom Commands (Internal Communication)
Commands starting with `"custom "` are treated as internal communication:

- **SSH Tunnel**: `"custom ssh user_123 2024-12-31T23:59:59Z"`
- **Future custom commands**: `"custom docker restart nginx"`, `"custom systemctl status"`, etc.

### Regular Commands (Shell Execution)
Commands that don't start with `"custom "` are executed as shell commands:

- **Shell commands**: `"systemctl restart nginx"`
- **Scripts**: `"bash /opt/scripts/backup.sh"`
- **Any executable**: `"docker ps -a"`

### Protocol

The tunnel uses JSON frames over WebSocket:

#### Heartbeat Messages
```json
{"svc":"hb", "t":"ping"}
{"svc":"hb", "t":"pong"}
```

#### Tunnel Control Messages
```json
// Open tunnel channel
{"svc":"tunnel", "t":"open", "ch":"channel_id", "host":"127.0.0.1", "port":22}

// Send data
{"svc":"tunnel", "t":"data", "ch":"channel_id", "b64":"base64_encoded_data"}

// End of file
{"svc":"tunnel", "t":"eof", "ch":"channel_id"}

// Close channel
{"svc":"tunnel", "t":"close", "ch":"channel_id", "reason":"..."}

// Resume session after reconnect
{"svc":"tunnel", "t":"resume", "session":"session_id", "ch_list":["ch1", "ch2"]}
```

## Implementation Details

### Security

- **Allow-list**: Only permits connections to `127.0.0.1:22` (local SSH daemon)
- **Expiration**: Tunnels automatically expire at the specified time
- **mTLS**: All connections use mutual TLS authentication
- **Timeout**: Commands have a 5-minute execution timeout

### Connection Modes

#### HTTP Mode
- Opens dedicated WebSocket to `wss://device.streamdeploy.com/v1-device/tunnel`
- Uses existing mTLS certificates

#### MQTT Mode
- Reuses existing persistent WebSocket connection
- Adds `"svc":"tunnel"` lane to the protocol

### Channel Management

- **Multiplexing**: Maps WebSocket channels to local TCP connections
- **Back-pressure**: Caps per-channel buffer at 512KB
- **Pause Logic**: Pauses TCP reads if WebSocket send queue is high
- **Priority**: Always prioritizes heartbeat messages

### Reconnection & Resume

- **Local Persistence**: Keeps local TCP sockets open during reconnection
- **Session Resume**: Sends resume message with active channel list
- **Buffer Replay**: Replays buffered outbound bytes after reconnection
- **Graceful Degradation**: Fails channels gracefully if TCP connection dies

### Keepalive

- **Ping Interval**: Sends ping every 25 seconds
- **Pong Timeout**: Reconnects if pong not received within 30 seconds
- **Automatic Reconnect**: Handles Cloud Run 60-minute limits and deployments

## Usage

### Command Examples

#### SSH Tunnel Commands
```json
{
  "cmd": "custom ssh user_123 2024-12-31T23:59:59Z",
  "new_state": {
    ...
  }
}
```

#### Regular Shell Commands
```json
{
  "cmd": "systemctl restart nginx",
  "new_state": {
    ...
  }
}
```

```json
{
  "cmd": "docker ps -a && docker logs nginx-container",
  "new_state": {
    ...
  }
}
```

### Starting a Tunnel

1. Send status update with SSH tunnel command:
   ```bash
   curl -X POST https://api.streamdeploy.com/v1-device/status-update \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "cmd": "custom ssh user_123 2024-12-31T23:59:59Z",
       "new_state": {
         "schemaVersion": "1.0",
         "agent_setting": { ... }
       }
     }'
   ```

2. Agent automatically:
   - Parses the command
   - Establishes WebSocket connection
   - Starts tunnel service
   - Removes `tmp` key from state

### Connecting via SSH

Once the tunnel is active, you can connect through the StreamDeploy platform:

```bash
# The platform will provide connection details
ssh user@tunnel.streamdeploy.com -p <tunnel_port>
```

### Monitoring

Check tunnel status:

```bash
# Check agent logs
journalctl -u streamdeploy-agent -f

# Check if tunnel is active
systemctl status streamdeploy-agent
```

## Configuration

### Systemd Service

The agent runs as a systemd service with the following configuration:

```ini
[Unit]
Description=StreamDeploy Agent with SSH Tunnel Support
After=network-online.target docker.service
Wants=docker.service
Requires=network-online.target

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

# SSH tunnel specific settings
PrivateNetwork=false
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

### Agent Configuration

The agent configuration in `/etc/streamdeploy/agent.json` should include:

```json
{
  "device_id": "device_123",
  "https_mtls_endpoint": "https://device.streamdeploy.com",
  "mqtt_ws_mtls_endpoint": "https://mqtt.streamdeploy.com",
  "pki_dir": "/etc/streamdeploy/pki"
}
```

## Troubleshooting

### Common Issues

1. **Tunnel Connection Failed**
   - Check network connectivity to `device.streamdeploy.com`
   - Verify mTLS certificates are valid
   - Check firewall settings

2. **SSH Connection Refused**
   - Ensure SSH daemon is running on port 22
   - Check that only `127.0.0.1:22` is allowed
   - Verify local SSH configuration

3. **Tunnel Expired**
   - Check tunnel expiration time
   - Restart tunnel with new command if needed

4. **WebSocket Reconnection Issues**
   - Check keepalive settings
   - Verify network stability
   - Review agent logs for reconnection attempts

### Debug Mode

Enable debug logging:

```bash
# Set environment variable
export GODEBUG=netdns=go

# Restart agent
systemctl restart streamdeploy-agent

# Monitor logs
journalctl -u streamdeploy-agent -f
```

### Log Analysis

Key log messages to look for:

- `"Starting SSH tunnel for user: ..."` - Tunnel initiation
- `"Opened tunnel channel ..."` - Channel creation
- `"Channel ... closed"` - Channel termination
- `"Reconnecting SSH tunnel"` - Reconnection attempts
- `"SSH tunnel started successfully"` - Successful startup

## Security Considerations

1. **Access Control**: Only authorized users can initiate tunnels
2. **Time Limits**: Tunnels automatically expire
3. **Network Isolation**: Only local SSH access is permitted
4. **Audit Logging**: All tunnel activity is logged
5. **Certificate Validation**: All connections use mTLS
6. **Resource Limits**: Per-channel buffer limits prevent resource exhaustion

## Performance

- **Concurrent Channels**: Supports multiple simultaneous SSH sessions
- **Buffer Management**: 512KB per-channel buffer with back-pressure
- **Memory Usage**: Minimal overhead for tunnel management
- **Network Efficiency**: Binary data is base64 encoded for JSON transport
- **Reconnection**: Sub-second reconnection for brief network interruptions
