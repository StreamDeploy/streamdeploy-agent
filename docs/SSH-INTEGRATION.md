# SSH Integration Implementation

This document describes the SSH tunnel integration implemented for the StreamDeploy agent, enabling automatic SSH connectivity during device enrollment.

## Overview

The SSH integration provides automatic SSH tunnel establishment between devices and the StreamDeploy bastion server, enabling remote access, debugging, and future SSH-based deployment capabilities.

## Architecture

### Agent-Side Implementation

**Configuration Extensions:**
- Added SSH configuration options to `AgentConfig`
- Support for bastion host, user, port, and tunnel settings
- Device-specific SSH key paths

**Enrollment Integration:**
- SSH key generation during device enrollment
- Public key submission to platform for port allocation
- Automatic tunnel establishment post-enrollment

**SSH Management:**
- Health monitoring and auto-reconnection
- Process management for SSH tunnels
- Status reporting via device state updates

### Platform-Side Implementation

**SSH Management APIs:**
- `POST /v1-device/ssh/register` - Register device SSH key and allocate port
- `GET /v1-device/ssh/status/{device_id}` - Get SSH connection status
- `POST /v1-device/ssh/command/{device_id}` - Execute SSH commands (Phase 2)
- `GET /v1-device/ssh/logs/{device_id}` - Stream SSH logs (Phase 3)

**Port Allocation Strategy:**
- Organization-based port ranges for multi-tenant isolation
- Deterministic port assignment using org/device hashing
- Port ranges: 2200-2299, 2300-2399, etc.

## Implementation Details

### Agent Configuration

New configuration options added to `agent.json`:

```json
{
  "ssh_bastion_host": "34.170.221.16",
  "ssh_bastion_user": "tonyloehr",
  "ssh_bastion_port": 22,
  "ssh_tunnel_enabled": true,
  "ssh_tunnel_port": 0
}
```

### SSH Key Management

- **Key Type:** ed25519 (consistent with existing bastion setup)
- **Key Location:** `/etc/streamdeploy/pki/ssh_{device_id}`
- **Permissions:** Private key (600), Public key (644)
- **Registration:** Automatic during enrollment process

### Tunnel Establishment

SSH tunnel command format:
```bash
ssh -f -N -T \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -o StrictHostKeyChecking=no \
  -i /etc/streamdeploy/pki/ssh_device_id -o IdentitiesOnly=yes \
  -R 0.0.0.0:PORT:localhost:22 \
  tonyloehr@34.170.221.16
```

### Status Reporting

SSH status is included in device `current_state`:

```json
{
  "ssh_tunnel": {
    "enabled": true,
    "tunnel_active": true,
    "tunnel_port": 2222,
    "bastion_host": "34.170.221.16",
    "last_check": 1640995200,
    "public_key_fingerprint": "SHA256:..."
  }
}
```

## Multi-Tenant Support

### Port Allocation

- **Base Port Calculation:** `2200 + (org_hash % 100) * 100`
- **Device Offset:** `device_hash % 100`
- **Final Port:** `base_port + device_offset`

### Security Isolation

- SSH keys scoped to organization
- Port ranges prevent cross-tenant access
- Device authentication via mTLS

## Phase Implementation

### Phase 1: SSH Foundation ✅
- [x] SSH configuration in agent
- [x] Enrollment process integration
- [x] Tunnel management and health monitoring
- [x] Backend APIs for SSH management
- [x] Status reporting integration

### Phase 2: Hybrid Deployment (Planned)
- [ ] SSH-based container deployment
- [ ] Hybrid deployment strategies (HTTP + SSH)
- [ ] SSH command execution
- [ ] Deployment method selection

### Phase 3: Advanced Features (Planned)
- [ ] Real-time log streaming
- [ ] Interactive debugging capabilities
- [ ] Emergency deployment system
- [ ] Advanced SSH analytics

## Usage Examples

### Connecting to Device

Once enrolled, connect to any device via:

```bash
# Connect to device with tunnel port 2222
ssh -p 2222 tony@34.170.221.16
```

### Port Mapping

| Organization | Port Range | Example Device | Port |
|-------------|------------|----------------|------|
| Org A       | 2200-2299  | device-001     | 2234 |
| Org B       | 2300-2399  | device-002     | 2367 |
| Org C       | 2400-2499  | device-003     | 2445 |

## Security Considerations

### Key Management
- Device-specific ed25519 keys
- Private keys never leave device
- Public key fingerprinting for identification

### Network Security
- Reverse tunnels (device → bastion)
- No inbound firewall changes required
- mTLS authentication for API access

### Access Control
- Organization-based port isolation
- Device identity verification
- Audit logging for SSH connections

## Monitoring and Troubleshooting

### Health Checks
- Tunnel process monitoring every 60 seconds
- Automatic reconnection on failure
- Status reporting via device heartbeat

### Logging
- SSH setup events in agent logs
- Tunnel establishment/failure logging
- Connection status in device state

### Common Issues
- **Port conflicts:** Resolved by deterministic allocation
- **Key permissions:** Automatically set during generation
- **Network connectivity:** Auto-retry with exponential backoff

## Future Enhancements

### Planned Features
- Multiple bastion server support
- SSH key rotation
- Web-based SSH terminal
- Bulk SSH operations
- Advanced deployment strategies

### Scalability Improvements
- Connection pooling
- Load balancing across bastions
- Geographic distribution
- Performance monitoring

## Integration with Existing Systems

### Device Management
- SSH status in device dashboard
- Connection health monitoring
- Remote debugging capabilities

### Deployment System
- Backup deployment channel
- Emergency update mechanism
- Real-time deployment feedback

### Monitoring
- SSH connection metrics
- Tunnel reliability statistics
- Performance analytics

## Conclusion

The SSH integration provides a robust foundation for remote device access and management. Phase 1 establishes the core infrastructure, with future phases adding advanced deployment and debugging capabilities.

The implementation leverages existing StreamDeploy infrastructure while maintaining security, scalability, and multi-tenant isolation requirements.
