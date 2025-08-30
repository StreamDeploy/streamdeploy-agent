# StreamDeploy Agent Secret Management

This document describes the secure secret management system implemented for the StreamDeploy agent using provisioning-time secret injection.

## Overview

The StreamDeploy agent now supports secure secret management through provisioning-time injection from Google Cloud Secret Manager. This approach is designed for open source compatibility while maintaining enterprise-grade security.

## Architecture

### Provisioning-Time Secret Injection

Instead of embedding cloud credentials in the agent, secrets are fetched during device provisioning and stored as secure local files:

```
GCP Secret Manager → Provisioning Script → Secure Local Files → Agent
```

### Security Model

- **No cloud credentials** in agent code or on devices
- **Secure file permissions** (600 - owner read/write only)
- **Fallback mechanism** to configuration values
- **Comprehensive logging** for audit and debugging

## Secret Files

### File Structure
```
/etc/streamdeploy/secrets/
├── ssh_bastion_host      # SSH bastion server IP
├── ssh_bastion_user      # SSH bastion username
├── bootstrap_token       # Device enrollment token
├── enroll_base_url       # Enrollment API endpoint
└── device_base_url       # Device API endpoint
```

### File Security
- **Permissions**: 600 (owner read/write only)
- **Ownership**: root:root
- **Directory**: 700 permissions
- **Validation**: Automatic permission checking

## Configuration Integration

### Agent Configuration

The agent configuration supports both direct values and file references:

```json
{
  "ssh_bastion_host": "34.170.221.16",
  "ssh_bastion_host_file": "/etc/streamdeploy/secrets/ssh_bastion_host",
  "bootstrap_token": "",
  "bootstrap_token_file": "/etc/streamdeploy/secrets/bootstrap_token"
}
```

### Precedence Order

The agent uses the following precedence for secret values:

1. **Secret file** (if exists and readable)
2. **Configuration value** (fallback)
3. **Default value** (if applicable)

## Provisioning Script

### Usage

Deploy secrets using the provisioning script:

```bash
# Basic deployment
sudo ./scripts/provision-secrets.sh

# With custom options
sudo ./scripts/provision-secrets.sh \
  --project stream-deploy-888888 \
  --environment prod \
  --verbose
```

### Script Features

- **Prerequisites checking** (gcloud, authentication, permissions)
- **Atomic deployment** (temporary files, atomic moves)
- **Permission validation** (600/700 enforcement)
- **Error handling** (graceful fallbacks)
- **Comprehensive logging** (info, warn, error, debug)

### Environment Support

The script supports multiple environments:

```bash
# Production (default)
sudo ./scripts/provision-secrets.sh --environment prod

# Staging
sudo ./scripts/provision-secrets.sh --environment staging

# Development
sudo ./scripts/provision-secrets.sh --environment dev
```

## GCP Secret Manager Setup

### Required Secrets

Create these secrets in your GCP project:

```bash
# SSH configuration
gcloud secrets create streamdeploy-ssh-bastion-host --data-file=- <<< "34.170.221.16"
gcloud secrets create streamdeploy-ssh-bastion-user --data-file=- <<< "tonyloehr"

# API endpoints
gcloud secrets create streamdeploy-enroll-base-url --data-file=- <<< "https://api.streamdeploy.com"
gcloud secrets create streamdeploy-device-base-url --data-file=- <<< "https://device.streamdeploy.com"

# Bootstrap token (update with actual token)
gcloud secrets create streamdeploy-bootstrap-token --data-file=bootstrap-token.txt
```

### IAM Permissions

Grant the provisioning service account access to secrets:

```bash
# For the provisioning service account
gcloud projects add-iam-policy-binding stream-deploy-888888 \
  --member="serviceAccount:provisioning@stream-deploy-888888.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Deployment Workflow

### 1. Prepare Secrets

Ensure all required secrets exist in GCP Secret Manager:

```bash
# List existing secrets
gcloud secrets list --project=stream-deploy-888888

# Verify secret values (be careful with sensitive data)
gcloud secrets versions access latest --secret=streamdeploy-ssh-bastion-host
```

### 2. Provision Device

Run the provisioning script on the target device:

```bash
# Authenticate with GCP
gcloud auth login

# Run provisioning script
sudo ./scripts/provision-secrets.sh --verbose
```

### 3. Install Agent

Install and configure the StreamDeploy agent:

```bash
# Install agent binary
sudo cp streamdeploy-agent /usr/local/bin/

# Install systemd service
sudo cp systemd/streamdeploy-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable streamdeploy-agent

# Start agent (will use secrets automatically)
sudo systemctl start streamdeploy-agent
```

### 4. Verify Operation

Check that the agent is using secrets correctly:

```bash
# Check agent logs
sudo journalctl -u streamdeploy-agent -f

# Look for secret loading messages
sudo grep "Loaded.*from secure file" /var/log/streamdeploy-agent/agent.log
```

## Logging and Monitoring

### Secret Loading Logs

The agent logs secret loading without revealing sensitive values:

```
1640995200 [info] Loaded ssh_bastion_host from secure file: /etc/streamdeploy/secrets/ssh_bastion_host
1640995201 [info] Using bootstrap_token from config file (fallback)
```

### Error Handling

Failed secret loading is logged with fallback information:

```
1640995202 [warn] Failed to load ssh_bastion_user from /etc/streamdeploy/secrets/ssh_bastion_user: Permission denied, using fallback
```

### Monitoring

Monitor secret file integrity:

```bash
# Check file permissions
find /etc/streamdeploy/secrets -type f ! -perm 600 -ls

# Check file ownership
find /etc/streamdeploy/secrets -type f ! -user root -ls

# Validate secret files exist
ls -la /etc/streamdeploy/secrets/
```

## Security Considerations

### File System Security

- **Secure permissions** (600/700) enforced automatically
- **Root ownership** prevents unauthorized access
- **Permission validation** during agent startup
- **Atomic file operations** prevent partial writes

### Secret Rotation

To rotate secrets:

1. **Update GCP Secret Manager** with new secret values
2. **Re-run provisioning script** on devices
3. **Restart agent** to pick up new secrets
4. **Verify operation** through logs and monitoring

### Audit Trail

- **GCP Secret Manager** provides access audit logs
- **Provisioning script** logs all operations
- **Agent logs** record secret source (file vs config)
- **System logs** capture file access patterns

## Troubleshooting

### Common Issues

**Secret file not found:**
```bash
# Check if provisioning script ran successfully
ls -la /etc/streamdeploy/secrets/

# Re-run provisioning if needed
sudo ./scripts/provision-secrets.sh --verbose
```

**Permission denied:**
```bash
# Check file permissions
stat /etc/streamdeploy/secrets/ssh_bastion_host

# Fix permissions if needed
sudo chmod 600 /etc/streamdeploy/secrets/*
sudo chown root:root /etc/streamdeploy/secrets/*
```

**GCP authentication issues:**
```bash
# Check authentication
gcloud auth list

# Re-authenticate if needed
gcloud auth login
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Run provisioning with debug output
sudo ./scripts/provision-secrets.sh --verbose

# Check agent logs for secret loading
sudo grep -i secret /var/log/streamdeploy-agent/agent.log
```

## Migration Guide

### From Hardcoded Secrets

1. **Create secrets** in GCP Secret Manager
2. **Run provisioning script** to deploy secret files
3. **Update configuration** to remove hardcoded values
4. **Restart agent** to use new secret system
5. **Verify operation** through logs

### Rollback Procedure

If issues occur, rollback by:

1. **Restore configuration** with hardcoded values
2. **Remove secret files** (optional)
3. **Restart agent** to use config values
4. **Investigate issues** before re-attempting

## Best Practices

### Security

- **Rotate secrets regularly** (monthly/quarterly)
- **Monitor file permissions** continuously
- **Audit secret access** through GCP logs
- **Use least-privilege** service accounts

### Operations

- **Test provisioning** in staging first
- **Backup configurations** before changes
- **Monitor agent health** after secret updates
- **Document secret rotation** procedures

### Development

- **Use environment-specific** secrets
- **Never commit secrets** to version control
- **Test fallback mechanisms** regularly
- **Validate secret file** integrity

## Conclusion

The provisioning-time secret injection system provides enterprise-grade security for the open source StreamDeploy agent while maintaining operational simplicity and backward compatibility.

Key benefits:
- **Open source safe** - No cloud credentials in code
- **Secure** - Proper file permissions and ownership
- **Flexible** - Supports multiple environments
- **Reliable** - Fallback to configuration values
- **Auditable** - Comprehensive logging and monitoring
