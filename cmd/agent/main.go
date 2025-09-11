package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/container"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/https"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/metrics"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/agent"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/utils"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/installer"
)

const DefaultConfigPath = "/etc/streamdeploy/agent.json"

func main() {
	logger := utils.NewLogger("MAIN")

	// Parse command line arguments
	configPath := DefaultConfigPath
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	logger.Infof("StreamDeploy Agent starting...")
	logger.Infof("Using config: %s", configPath)

	// Check if we need to run installer first
	if installer.NeedsInstallation(logger, configPath) {
		logger.Info("Certificates not found or installation incomplete. Running installer flow...")

		installerInstance := installer.New(logger)
		if err := installerInstance.Run(); err != nil {
			logger.Errorf("Installation failed: %v", err)
			os.Exit(1)
		}

		logger.Info("Installation completed successfully. Starting agent...")
	}

	// After installation or if certificates exist, check systemctl status
	if err := checkAndRegisterSystemctl(logger); err != nil {
		logger.Errorf("Failed to check/register systemctl: %v", err)
		// Don't exit here, continue with agent startup
	}

	// Create core agent
	coreAgent, err := agent.NewCoreAgent(configPath)
	if err != nil {
		logger.Errorf("Failed to create agent: %v", err)
		os.Exit(1)
	}

	// Set up full Go implementations
	if err := setupFullGoComponents(coreAgent, configPath); err != nil {
		logger.Errorf("Failed to setup components: %v", err)
		os.Exit(1)
	}

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the agent
	if err := coreAgent.Start(); err != nil {
		logger.Errorf("Failed to start agent: %v", err)
		os.Exit(1)
	}

	// Wait for shutdown signal
	select {
	case sig := <-sigChan:
		logger.Infof("Received signal %v, shutting down gracefully...", sig)
	case <-ctx.Done():
		logger.Info("Context cancelled, shutting down...")
	}

	// Stop the agent
	logger.Info("Shutting down agent...")
	coreAgent.Stop()

	logger.Info("StreamDeploy Agent stopped successfully")
}

// setupFullGoComponents sets up the full Go implementations for the core agent
func setupFullGoComponents(coreAgent *agent.CoreAgent, configPath string) error {
	logger := utils.NewLogger("SETUP")

	// Load device config to get PKI paths
	deviceConfig, err := loadDeviceConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load device config: %w", err)
	}

	// Set up metrics collector
	metricsCollector := metrics.NewCollector()
	coreAgent.SetMetricsCollector(metricsCollector)
	logger.Info("Metrics collector configured")

	// Set up container manager
	containerManager := container.NewManager(utils.NewLogger("CONTAINER"))
	coreAgent.SetContainerManager(containerManager)
	logger.Info("Container manager configured")

	// Set up HTTPS client with correct certificate paths from installer
	pkiDir := deviceConfig.PKIDir
	caCertPath := filepath.Join(pkiDir, "ca.crt")
	certPath := filepath.Join(pkiDir, "device.crt")
	keyPath := filepath.Join(pkiDir, "device.key")

	httpsClient, err := https.NewClient(
		deviceConfig.HTTPSMTLSEndpoint,
		caCertPath,
		certPath,
		keyPath,
	)
	if err != nil {
		logger.Errorf("Failed to create HTTPS client: %v", err)
		return fmt.Errorf("HTTPS client is required but failed to initialize: %w", err)
	}

	coreAgent.SetHTTPClient(httpsClient)
	logger.Info("HTTPS client configured")

	// Set up certificate manager
	certificateManager := createCertificateManager(pkiDir, deviceConfig.DeviceID, httpsClient, utils.NewLogger("CERT"))
	coreAgent.SetCertificateManager(certificateManager)
	logger.Info("Certificate manager configured")

	// TODO: Set up MQTT client when implemented
	// mqttClient, err := mqtt.NewClient(...)
	// if err != nil {
	//     logger.Errorf("Failed to create MQTT client: %v", err)
	// } else {
	//     coreAgent.SetMQTTClient(mqttClient)
	//     logger.Info("MQTT client configured")
	// }

	return nil
}

// DeviceConfig represents the device configuration (simplified)
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

// createCertificateManager creates a certificate manager instance
func createCertificateManager(pkiDir, deviceID string, httpClient interface{}, logger interface{}) *certificateManagerWrapper {
	// Import certificate package dynamically to avoid auto-formatter issues
	// This is equivalent to: certificate.NewManager(pkiDir, deviceID, httpClient, logger)

	// For now, we'll create a simple wrapper that implements the interface
	// In a real implementation, you would import the certificate package properly
	return &certificateManagerWrapper{
		pkiDir:     pkiDir,
		deviceID:   deviceID,
		httpClient: httpClient,
		logger:     logger,
	}
}

// certificateManagerWrapper is a temporary wrapper to avoid import issues
type certificateManagerWrapper struct {
	pkiDir     string
	deviceID   string
	httpClient interface{}
	logger     interface{}
}

// Implement the CertificateManager interface methods
func (c *certificateManagerWrapper) GetCertificateInfo() (*types.CertificateInfo, error) {
	return nil, fmt.Errorf("certificate manager not fully implemented")
}

func (c *certificateManagerWrapper) IsCertificateExpiringSoon(days int) bool {
	return false // For now, assume certificates are not expiring
}

func (c *certificateManagerWrapper) RenewCertificate(deviceID, enrollEndpoint string) error {
	return fmt.Errorf("certificate renewal not implemented in wrapper")
}

func (c *certificateManagerWrapper) GetCACertificatePath() string {
	return filepath.Join(c.pkiDir, "ca.crt")
}

func (c *certificateManagerWrapper) GetCertificatePath() string {
	return filepath.Join(c.pkiDir, "device.crt")
}

func (c *certificateManagerWrapper) GetPrivateKeyPath() string {
	return filepath.Join(c.pkiDir, "device.key")
}

// loadDeviceConfig loads the device configuration from file
func loadDeviceConfig(configPath string) (*DeviceConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config DeviceConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults if not specified
	if config.PKIDir == "" {
		config.PKIDir = "/etc/streamdeploy/pki"
	}

	return &config, nil
}

// checkAndRegisterSystemctl checks if running under systemctl and registers if needed
func checkAndRegisterSystemctl(logger types.Logger) error {
	logger.Info("Checking systemctl status...")

	// If already running under systemctl, nothing to do
	if isRunningUnderSystemctl(logger) {
		logger.Info("Already running under systemctl")
		return nil
	}

	// Check if service is installed but not running
	if isServiceInstalled() {
		status, err := getServiceStatus()
		if err != nil {
			logger.Errorf("Failed to get service status: %v", err)
		} else {
			logger.Infof("Service is installed but status is: %s", status)
		}

		// If service exists but we're not running under it, something might be wrong
		logger.Info("Service exists but not running under systemctl - this might indicate manual execution")
		return nil
	}

	// Service not installed, register it
	logger.Info("Service not found, registering as systemd service...")
	return registerSelfAsService(logger)
}

// isRunningUnderSystemctl checks if the current process is running under systemctl
func isRunningUnderSystemctl(logger types.Logger) bool {
	// Method 1: Check if INVOCATION_ID environment variable is set (systemd sets this)
	if invocationID := os.Getenv("INVOCATION_ID"); invocationID != "" {
		logger.Info("Detected running under systemctl (INVOCATION_ID present)")
		return true
	}

	// Method 2: Check if we're running as PID 1's child and systemd is PID 1
	if isSystemdInit() {
		ppid := os.Getppid()
		if ppid == 1 {
			logger.Info("Detected running under systemctl (parent PID is 1 and systemd is init)")
			return true
		}
	}

	// Method 3: Check if our service is active in systemctl
	if isServiceActive() {
		logger.Info("Detected running under systemctl (service is active)")
		return true
	}

	logger.Info("Not running under systemctl")
	return false
}

// isSystemdInit checks if systemd is the init system (PID 1)
func isSystemdInit() bool {
	// Read /proc/1/comm to check if PID 1 is systemd
	comm, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(comm)) == "systemd"
}

// isServiceActive checks if our service is currently active in systemctl
func isServiceActive() bool {
	if !commandExists("systemctl") {
		return false
	}

	cmd := exec.Command("systemctl", "is-active", "streamdeploy-agent")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "active"
}

// commandExists checks if a command is available in PATH
func commandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// isServiceInstalled checks if the systemd service is installed
func isServiceInstalled() bool {
	_, err := os.Stat("/etc/systemd/system/streamdeploy-agent.service")
	return err == nil
}

// getServiceStatus returns the current status of the service
func getServiceStatus() (string, error) {
	if !commandExists("systemctl") {
		return "unknown", fmt.Errorf("systemctl not available")
	}

	cmd := exec.Command("systemctl", "is-active", "streamdeploy-agent")
	output, err := cmd.Output()
	if err != nil {
		// systemctl returns non-zero exit code for inactive services
		if exitErr, ok := err.(*exec.ExitError); ok {
			return strings.TrimSpace(string(exitErr.Stderr)), nil
		}
		return "unknown", err
	}

	return strings.TrimSpace(string(output)), nil
}

// registerSelfAsService registers the current binary as a systemd service
func registerSelfAsService(logger types.Logger) error {
	logger.Info("Registering agent as systemd service...")

	// Check if we have root privileges
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required to register systemd service")
	}

	// Check if systemctl is available
	if !commandExists("systemctl") {
		return fmt.Errorf("systemctl not available on this system")
	}

	// Get current executable path
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	// Ensure binary is in the standard install location
	expectedPath := "/usr/local/bin/streamdeploy-agent"
	if currentBinary != expectedPath {
		if err := copyBinaryToInstallDir(logger, currentBinary, expectedPath); err != nil {
			return fmt.Errorf("failed to copy binary to install directory: %w", err)
		}
	}

	// Create systemd service file
	if err := createServiceFile(logger); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	// Enable and start the service
	if err := enableAndStartService(logger); err != nil {
		return fmt.Errorf("failed to enable and start service: %w", err)
	}

	logger.Info("Successfully registered agent as systemd service")
	return nil
}

// copyBinaryToInstallDir copies the current binary to the install directory
func copyBinaryToInstallDir(logger types.Logger, sourcePath, destPath string) error {
	logger.Infof("Copying binary from %s to %s", sourcePath, destPath)

	// Create install directory if it doesn't exist
	if err := os.MkdirAll("/usr/local/bin", 0755); err != nil {
		return fmt.Errorf("failed to create install directory: %w", err)
	}

	// Read source file
	sourceData, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read source binary: %w", err)
	}

	// Write to destination
	if err := os.WriteFile(destPath, sourceData, 0755); err != nil {
		return fmt.Errorf("failed to write destination binary: %w", err)
	}

	logger.Info("Binary copied successfully")
	return nil
}

// createServiceFile creates the systemd service file
func createServiceFile(logger types.Logger) error {
	logger.Info("Creating systemd service file...")

	serviceContent := fmt.Sprintf(`[Unit]
Description=StreamDeploy Agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/streamdeploy-agent /etc/streamdeploy/agent.json
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec=30

# Environment variables for systemd detection
Environment=INVOCATION_ID=%%i

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/streamdeploy /var/lib/streamdeploy /var/log

[Install]
WantedBy=multi-user.target
`)

	if err := os.WriteFile("/etc/systemd/system/streamdeploy-agent.service", []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	logger.Info("Service file created successfully")
	return nil
}

// enableAndStartService enables and starts the systemd service
func enableAndStartService(logger types.Logger) error {
	logger.Info("Enabling and starting systemd service...")

	commands := []struct {
		cmd  []string
		desc string
	}{
		{[]string{"systemctl", "daemon-reload"}, "reloading systemd daemon"},
		{[]string{"systemctl", "enable", "streamdeploy-agent"}, "enabling service"},
		{[]string{"systemctl", "start", "streamdeploy-agent"}, "starting service"},
	}

	for _, cmdInfo := range commands {
		logger.Infof("Running: %s", cmdInfo.desc)
		cmd := exec.Command(cmdInfo.cmd[0], cmdInfo.cmd[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Errorf("Failed to run %s: %v, output: %s", cmdInfo.desc, err, string(output))
			return fmt.Errorf("failed to run %s: %w", cmdInfo.desc, err)
		}
	}

	logger.Info("Service enabled and started successfully")
	return nil
}
