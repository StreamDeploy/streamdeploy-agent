# StreamDeploy Agent Uninstallation Guide

This guide provides step-by-step instructions to completely remove the StreamDeploy agent from your system.

## Prerequisites

- Root/sudo access is required for uninstallation
- The agent should be stopped before removal

## Quick Uninstall Script

For a quick automated uninstall, you can run these commands as root:

```bash
#!/bin/bash
# Stop and disable the service
systemctl stop streamdeploy-agent 2>/dev/null
systemctl disable streamdeploy-agent 2>/dev/null

# Remove service file
rm -f /etc/systemd/system/streamdeploy-agent.service

# Reload systemd
systemctl daemon-reload

# Remove binary
sudo rm -f /usr/local/bin/streamdeploy-agent

# Remove configuration and data directories
sudo rm -rf /etc/streamdeploy/
sudo rm -rf /var/lib/streamdeploy/

echo "StreamDeploy agent has been completely removed."
```

## Manual Uninstallation Steps

### Step 1: Stop the Agent Service

First, stop the running agent service:

```bash
sudo systemctl stop streamdeploy-agent
```

### Step 2: Disable the Service

Disable the service to prevent it from starting on boot:

```bash
sudo systemctl disable streamdeploy-agent
```

### Step 3: Remove Service File

Remove the systemd service file:

```bash
sudo rm /etc/systemd/system/streamdeploy-agent.service
```

### Step 4: Reload Systemd

Reload systemd to recognize the service removal:

```bash
sudo systemctl daemon-reload
```

### Step 5: Remove Agent Binary

Remove the main agent executable:

```bash
sudo rm /usr/local/bin/streamdeploy-agent
```

### Step 6: Remove Configuration Directory

Remove the entire configuration directory including certificates:

```bash
sudo rm -rf /etc/streamdeploy/
```

This removes:
- `/etc/streamdeploy/agent.json` - Device configuration
- `/etc/streamdeploy/state.json` - State configuration  
- `/etc/streamdeploy/pki/device.key` - Private key
- `/etc/streamdeploy/pki/device.crt` - Device certificate
- `/etc/streamdeploy/pki/ca.crt` - CA bundle

### Step 7: Remove Data Directory

Remove the runtime data directory:

```bash
sudo rm -rf /var/lib/streamdeploy/
```

### Step 8: Clean Up System Dependencies (Optional)

The installer installs several system packages. Remove them only if they're not needed by other applications:

**For Ubuntu/Debian systems:**
```bash
sudo apt-get remove --purge docker.io
# Note: curl, ca-certificates, and systemd are typically needed by other applications
```

**For CentOS/RHEL systems:**
```bash
sudo yum remove docker
```

**For Alpine systems:**
```bash
sudo apk del docker
```

**For Arch systems:**
```bash
sudo pacman -R docker
```

## Verification

After uninstallation, verify the agent is completely removed:

### Check Service Status
```bash
systemctl status streamdeploy-agent
```
Should return: `Unit streamdeploy-agent.service could not be found.`

### Check Binary
```bash
which streamdeploy-agent
```
Should return no output.

### Check Configuration Directories
```bash
ls -la /etc/streamdeploy/
ls -la /var/lib/streamdeploy/
```
Both should return: `No such file or directory`

### Check for Running Processes
```bash
ps aux | grep streamdeploy
```
Should show no running StreamDeploy processes.

## Files and Directories Removed

The uninstallation process removes the following:

### System Service
- `/etc/systemd/system/streamdeploy-agent.service`

### Binaries
- `/usr/local/bin/streamdeploy-agent`

### Configuration Files
- `/etc/streamdeploy/agent.json`
- `/etc/streamdeploy/state.json`

### Certificates and PKI
- `/etc/streamdeploy/pki/device.key`
- `/etc/streamdeploy/pki/device.crt`
- `/etc/streamdeploy/pki/ca.crt`

### Data Directories
- `/etc/streamdeploy/` (entire directory)
- `/var/lib/streamdeploy/` (entire directory)

## Troubleshooting

### Service Won't Stop
If the service won't stop gracefully:
```bash
sudo systemctl kill streamdeploy-agent
```

### Permission Denied Errors
Ensure you're running commands with sudo or as root:
```bash
sudo su -
# Then run the uninstall commands
```

### Files Still Present
If some files persist, force remove them:
```bash
sudo rm -rf /etc/streamdeploy/ /var/lib/streamdeploy/
sudo find / -name "*streamdeploy*" -type f 2>/dev/null
```

## Re-installation

If you need to reinstall the agent later, you can use the original installation method with a new bootstrap token from the StreamDeploy console.

## Support

If you encounter issues during uninstallation, please contact StreamDeploy support or check the project documentation.
