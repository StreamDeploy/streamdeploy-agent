package installer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// DeviceConfig represents the device configuration
type DeviceConfig struct {
	DeviceID           string `json:"device_id"`
	EnrollBaseURL      string `json:"enroll_base_url"`
	HTTPSMTLSEndpoint  string `json:"https_mtls_endpoint"`
	MQTTWSMTLSEndpoint string `json:"mqtt_ws_mtls_endpoint"`
	PKIDir             string `json:"pki_dir"`
	OSName             string `json:"os_name"`
	OSVersion          string `json:"os_version"`
	Architecture       string `json:"architecture"`
}

// Installer handles the installation and setup of the StreamDeploy agent
type Installer struct {
	logger types.Logger
}

// New creates a new installer instance
func New(logger types.Logger) *Installer {
	return &Installer{
		logger: logger,
	}
}

// EnsureCertificates checks if certificates exist, runs cert flow if not
func (i *Installer) EnsureCertificates(configPath string) error {
	i.logger.Info("Checking certificates...")

	// Load device config
	deviceConfig, err := i.loadDeviceConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load device config: %w", err)
	}

	// Check if certificates exist
	certPath := filepath.Join(deviceConfig.PKIDir, "device.crt")
	keyPath := filepath.Join(deviceConfig.PKIDir, "device.key")
	caCertPath := filepath.Join(deviceConfig.PKIDir, "ca.crt")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		i.logger.Info("Certificates not found, starting enrollment process...")
		return i.performCertificateEnrollment(deviceConfig)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		i.logger.Info("Private key not found, starting enrollment process...")
		return i.performCertificateEnrollment(deviceConfig)
	}

	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		i.logger.Info("CA certificate not found, starting enrollment process...")
		return i.performCertificateEnrollment(deviceConfig)
	}

	i.logger.Info("Certificates found, skipping enrollment")
	return nil
}

// HandleSystemdService manages systemd service (stop, remove, replace, launch, kill self)
func (i *Installer) HandleSystemdService(configPath string) error {
	i.logger.Info("Handling systemd service management...")

	// Check if systemctl is available
	if !i.commandExists("systemctl") {
		i.logger.Info("systemctl not available, skipping service management")
		return nil
	}

	// Check if we have root privileges
	if os.Geteuid() != 0 {
		i.logger.Info("Not running as root, skipping service management")
		return nil
	}

	// Check if we're already running under systemd (avoid recursive service management)
	if i.isRunningUnderSystemd() {
		i.logger.Info("Already running under systemd service, skipping service management")
		return nil
	}

	i.logger.Info("Not running under systemd, proceeding with service management")

	// Get current executable path
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	expectedPath := "/usr/local/bin/streamdeploy-agent"

	// Step 1: Stop existing systemd service if running (we're running manually)
	if i.isServiceActive() {
		i.logger.Info("Stopping existing streamdeploy-agent systemd service...")
		if err := i.runSystemCommand("systemctl", "stop", "streamdeploy-agent"); err != nil {
			i.logger.Errorf("Failed to stop service: %v", err)
		}
	}

	// Step 2: Disable existing service if installed
	if i.isServiceInstalled() {
		i.logger.Info("Disabling existing streamdeploy-agent service...")
		if err := i.runSystemCommand("systemctl", "disable", "streamdeploy-agent"); err != nil {
			i.logger.Errorf("Failed to disable service: %v", err)
		}
	}

	// Step 3: Copy binary to install directory if needed
	if currentBinary != expectedPath {
		if err := i.copyBinaryToInstallDir(currentBinary, expectedPath); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	// Step 4: Create and launch systemd service
	if err := i.createServiceFile(); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	if err := i.enableAndStartService(); err != nil {
		return fmt.Errorf("failed to enable and start service: %w", err)
	}

	// Step 5: Kill itself if we're not the installed binary (replace with systemd version)
	if currentBinary != expectedPath {
		i.logger.Info("Systemd service started successfully. Replacing manual process with systemd service...")

		// Wait longer for service to fully start and stabilize
		time.Sleep(5 * time.Second)

		// Verify service is running and stable
		if !i.isServiceActive() {
			// Check service logs for debugging
			i.logger.Errorf("Service failed to start properly. Checking service logs...")
			if err := i.checkServiceLogs(); err != nil {
				i.logger.Errorf("Failed to check service logs: %v", err)
			}
			return fmt.Errorf("service failed to start properly")
		}

		// Additional verification: check that the systemd instance is actually running
		time.Sleep(2 * time.Second)
		if !i.isServiceActive() {
			i.logger.Errorf("Service is not stable after start. Checking service logs...")
			if err := i.checkServiceLogs(); err != nil {
				i.logger.Errorf("Failed to check service logs: %v", err)
			}
			return fmt.Errorf("service is not stable after start")
		}

		i.logger.Info("Systemd service verified as running and stable. Exiting manual process.")
		os.Exit(0)
	}

	return nil
}

// performCertificateEnrollment performs certificate enrollment
func (i *Installer) performCertificateEnrollment(deviceConfig *DeviceConfig) error {
	i.logger.Info("Starting certificate enrollment process...")

	// Get bootstrap token from environment
	bootstrapToken := os.Getenv("SD_BOOTSTRAP_TOKEN")
	if bootstrapToken == "" {
		return fmt.Errorf("SD_BOOTSTRAP_TOKEN environment variable not set")
	}

	// Create PKI directory
	if err := os.MkdirAll(deviceConfig.PKIDir, 0755); err != nil {
		return fmt.Errorf("failed to create PKI directory: %w", err)
	}

	// Certificate enrollment is now handled by the modular initialization flow
	// The old installer.Run() is no longer needed as it duplicates systemd service creation
	i.logger.Info("Certificate enrollment will be handled by modular initialization")
	return nil
}

// loadDeviceConfig loads the device configuration from file
func (i *Installer) loadDeviceConfig(configPath string) (*DeviceConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config DeviceConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// isRunningUnderSystemd checks if we're running under systemd using multiple indicators
func (i *Installer) isRunningUnderSystemd() bool {
	// Check environment variables that systemd sets
	invocationID := os.Getenv("INVOCATION_ID")
	notifySocket := os.Getenv("NOTIFY_SOCKET")

	i.logger.Infof("Checking systemd detection: INVOCATION_ID='%s', NOTIFY_SOCKET='%s'", invocationID, notifySocket)

	// Check if we have systemd environment variables (most reliable)
	if invocationID != "" || notifySocket != "" {
		i.logger.Info("Detected systemd via environment variables")
		return true
	}

	// Check if we have a systemd journal fd (fd 3 is typically used by systemd)
	if fd3, err := os.Open("/proc/self/fd/3"); err == nil {
		fd3.Close()
		// Check if it's a systemd journal fd by checking the file descriptor info
		if link, err := os.Readlink("/proc/self/fd/3"); err == nil && strings.Contains(link, "socket") {
			i.logger.Info("Detected systemd via journal fd")
			return true
		}
	}

	// Check if we're running as a systemd service by checking our parent process
	if ppid := os.Getppid(); ppid > 1 {
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ppid)); err == nil {
			cmdlineStr := strings.TrimRight(string(cmdline), "\x00")
			i.logger.Infof("Parent process cmdline: %s", cmdlineStr)
			if strings.Contains(cmdlineStr, "systemd") || strings.Contains(cmdlineStr, "systemctl") {
				i.logger.Info("Detected systemd via parent process")
				return true
			}
		}
	}

	// Check if we're running from the expected systemd location
	if currentBinary, err := os.Executable(); err == nil {
		i.logger.Infof("Current binary path: %s", currentBinary)
		if currentBinary == "/usr/local/bin/streamdeploy-agent" {
			// If we're running from the systemd location, check if systemd is managing us
			if i.isServiceActive() {
				i.logger.Info("Detected systemd via service status check")
				return true
			}
		}
	}

	i.logger.Info("No systemd indicators found, assuming manual execution")
	return false
}

// isServiceActive checks if our service is currently active in systemctl
func (i *Installer) isServiceActive() bool {
	if !i.commandExists("systemctl") {
		return false
	}

	// Use systemctl show to get detailed status
	cmd := exec.Command("systemctl", "show", "streamdeploy-agent", "--property=ActiveState,SubState")
	output, err := cmd.Output()
	if err != nil {
		i.logger.Errorf("Failed to check service status: %v", err)
		return false
	}

	status := string(output)
	i.logger.Infof("Service status: %s", status)

	// Service is considered active if it's in "active" state or "activating" state
	// (activating means it's starting up, which is fine for our purposes)
	return strings.Contains(status, "ActiveState=active") || strings.Contains(status, "ActiveState=activating")
}

// isServiceInstalled checks if the systemd service is installed
func (i *Installer) isServiceInstalled() bool {
	_, err := os.Stat("/etc/systemd/system/streamdeploy-agent.service")
	return err == nil
}

// copyBinaryToInstallDir copies the current binary to the install directory
func (i *Installer) copyBinaryToInstallDir(sourcePath, destPath string) error {
	i.logger.Infof("Copying binary from %s to %s", sourcePath, destPath)

	// Read source file
	sourceData, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read source binary: %w", err)
	}

	// Create destination directory if it doesn't exist
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Write destination file with proper permissions
	if err := os.WriteFile(destPath, sourceData, 0755); err != nil {
		return fmt.Errorf("failed to write destination binary: %w", err)
	}

	i.logger.Info("Binary copied successfully")
	return nil
}

// createServiceFile creates the systemd service file
func (i *Installer) createServiceFile() error {
	i.logger.Info("Creating systemd service file...")

	serviceContent := `[Unit]
Description=StreamDeploy Agent
After=network.target
Wants=network.target

[Service]
Type=simple
# run as root
User=root
Group=root
DynamicUser=no

# remove common filesystem sandboxes
ProtectSystem=off
ProtectHome=off
PrivateTmp=no
PrivateDevices=no
NoNewPrivileges=no

# clear any path allow/deny lists
ReadWritePaths=
ReadOnlyPaths=
InaccessiblePaths=

# allow full capabilities (defaults to full for root, but make it explicit)
CapabilityBoundingSet=
AmbientCapabilities=

# drop other locks that can block writes/tuning (but keep kernel protection)
RestrictNamespaces=no
LockPersonality=no
# Keep these for safety - they could brick the device:
# ProtectKernelTunables=no
# ProtectKernelModules=no
# MemoryDenyWriteExecute=no
# ProtectControlGroups=no
ProtectProc=default

ExecStart=/usr/local/bin/streamdeploy-agent /etc/streamdeploy/agent.json
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec=30

# systemd automatically sets INVOCATION_ID for service detection

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile("/etc/systemd/system/streamdeploy-agent.service", []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	i.logger.Info("Service file created successfully")
	return nil
}

// enableAndStartService enables and starts the systemd service
func (i *Installer) enableAndStartService() error {
	i.logger.Info("Enabling and starting systemd service...")

	commands := []struct {
		cmd  []string
		desc string
	}{
		{[]string{"systemctl", "daemon-reload"}, "reloading systemd daemon"},
		{[]string{"systemctl", "enable", "streamdeploy-agent"}, "enabling service"},
		{[]string{"systemctl", "start", "streamdeploy-agent"}, "starting service"},
	}

	for _, cmdInfo := range commands {
		i.logger.Infof("Running: %s", strings.Join(cmdInfo.cmd, " "))
		if err := i.runSystemCommand(cmdInfo.cmd[0], cmdInfo.cmd[1:]...); err != nil {
			return fmt.Errorf("failed %s: %w", cmdInfo.desc, err)
		}
	}

	i.logger.Info("Service enabled and started successfully")
	return nil
}

// commandExists checks if a command exists in the system PATH
func (i *Installer) commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// runSystemCommand runs a system command and returns the error
func (i *Installer) runSystemCommand(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		i.logger.Errorf("Command failed: %s %s", name, strings.Join(arg, " "))
		i.logger.Errorf("Output: %s", string(output))
		return err
	}
	return nil
}

// checkServiceLogs checks the systemd service logs for debugging
func (i *Installer) checkServiceLogs() error {
	cmd := exec.Command("journalctl", "-u", "streamdeploy-agent", "--no-pager", "-n", "20")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get service logs: %w", err)
	}

	i.logger.Errorf("Recent service logs:")
	i.logger.Errorf("%s", string(output))
	return nil
}
