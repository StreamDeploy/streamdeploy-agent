package installer

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

const (
	InstallDir    = "/usr/local/bin"
	ConfigDir     = "/etc/streamdeploy"
	PKIDir        = "/etc/streamdeploy/pki"
	ServiceFile   = "/etc/systemd/system/streamdeploy-agent.service"
	APIBase       = "https://api.streamdeploy.com"
	HTTPSEndpoint = "https://device.streamdeploy.com"
	MQTTEndpoint  = "https://mqtt.streamdeploy.com"
)

var RequiredPackages = []string{
	"curl",
	"ca-certificates",
	"systemd",
	"docker.io",
}

type PackageManager struct {
	Type       string `json:"type"`
	InstallCmd string `json:"install_cmd"`
	CheckCmd   string `json:"check_cmd"`
	RemoveCmd  string `json:"remove_cmd"`
	UpdateCmd  string `json:"update_cmd"`
}

type DeviceConfig struct {
	DeviceID           string         `json:"device_id"`
	EnrollBaseURL      string         `json:"enroll_base_url"`
	HTTPSMTLSEndpoint  string         `json:"https_mtls_endpoint"`
	MQTTWSMTLSEndpoint string         `json:"mqtt_ws_mtls_endpoint"`
	PKIDir             string         `json:"pki_dir"`
	OSName             string         `json:"os_name"`
	OSVersion          string         `json:"os_version"`
	Architecture       string         `json:"architecture"`
	PackageManager     PackageManager `json:"package_manager"`
}

type StateConfig struct {
	SchemaVersion  string                 `json:"schemaVersion"`
	AgentSetting   AgentSetting           `json:"agent_setting"`
	Containers     []interface{}          `json:"containers"`
	ContainerLogin string                 `json:"containerLogin"`
	Env            map[string]string      `json:"env"`
	Packages       []string               `json:"packages"`
	CustomMetrics  map[string]string      `json:"custom_metrics"`
	CustomPackages map[string]interface{} `json:"custom_packages"`
}

type AgentSetting struct {
	HeartbeatFrequency string `json:"heartbeat_frequency"`
	UpdateFrequency    string `json:"update_frequency"`
	Mode               string `json:"mode"`
	AgentVer           string `json:"agent_ver"`
}

type EnrollStartResponse struct {
	Nonce    string `json:"nonce"`
	CABundle string `json:"ca_bundle"`
}

type EnrollCSRResponse struct {
	CertPEM string   `json:"cert_pem"`
	Chain   []string `json:"chain"`
}

// Installer implements the installation logic
type Installer struct {
	logger         types.Logger
	bootstrapToken string
	deviceID       string
	osName         string
	osVersion      string
	architecture   string
	packageManager PackageManager
}

// New creates a new installer instance
func New(logger types.Logger) *Installer {
	return &Installer{
		logger: logger,
	}
}

// NeedsInstallation checks if the agent needs to run the installer flow
func NeedsInstallation(logger types.Logger, configPath string) bool {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Info("Config file not found, installation needed")
		return true
	}

	// Load config to get PKI directory
	deviceConfig, err := loadDeviceConfig(configPath)
	if err != nil {
		logger.Infof("Failed to load config, installation needed: %v", err)
		return true
	}

	// Check if certificates exist
	pkiDir := deviceConfig.PKIDir
	if pkiDir == "" {
		pkiDir = PKIDir
	}

	requiredFiles := []string{
		filepath.Join(pkiDir, "ca.crt"),
		filepath.Join(pkiDir, "device.crt"),
		filepath.Join(pkiDir, "device.key"),
		filepath.Join(pkiDir, "fullchain.crt"),
	}

	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			logger.Infof("Certificate file missing: %s, installation needed", file)
			return true
		}
	}

	logger.Info("All certificates found, proceeding with agent startup")
	return false
}

// Run executes the complete installer flow
func (i *Installer) Run() error {
	i.logger.Info("StreamDeploy Agent Installer Starting...")

	if !i.checkRoot() {
		return fmt.Errorf("this installer must be run as root (use sudo)")
	}

	if !i.getBootstrapToken() {
		return fmt.Errorf("bootstrap token is required. Usage: sudo ./streamdeploy-agent <token> or export SD_BOOTSTRAP_TOKEN=\"your-token\"")
	}

	if err := i.extractDeviceIDFromJWT(); err != nil {
		return fmt.Errorf("failed to extract device_id from bootstrap token: %w", err)
	}

	if err := i.detectSystem(); err != nil {
		return fmt.Errorf("failed to detect system information: %w", err)
	}

	if err := i.installDependencies(); err != nil {
		return fmt.Errorf("failed to install system dependencies: %w", err)
	}

	if err := i.ensureAgentBinary(); err != nil {
		return fmt.Errorf("failed to ensure agent binary: %w", err)
	}

	if err := i.createConfig(); err != nil {
		return fmt.Errorf("failed to create agent configuration: %w", err)
	}

	if err := i.performCertificateExchange(); err != nil {
		return fmt.Errorf("failed to perform certificate exchange: %w", err)
	}

	if err := i.createSystemdService(); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}

	if err := i.enableAndStartService(); err != nil {
		return fmt.Errorf("failed to enable and start service: %w", err)
	}

	if err := i.cleanupAndExit(); err != nil {
		return fmt.Errorf("failed to cleanup and exit: %w", err)
	}

	return nil
}

func (i *Installer) checkRoot() bool {
	return os.Geteuid() == 0
}

func (i *Installer) getBootstrapToken() bool {
	// Check command line argument (skip first arg which is the binary name)
	if len(os.Args) >= 2 && len(os.Args[1]) > 0 && !strings.HasPrefix(os.Args[1], "/") {
		i.bootstrapToken = os.Args[1]
		i.logger.Info("Bootstrap token provided via command line")
		return true
	}

	// Check environment variable
	if token := os.Getenv("SD_BOOTSTRAP_TOKEN"); len(token) > 0 {
		i.bootstrapToken = token
		i.logger.Info("Bootstrap token found in environment variable")
		return true
	}

	return false
}

func (i *Installer) extractDeviceIDFromJWT() error {
	// JWT has 3 parts separated by dots: header.payload.signature
	parts := strings.Split(i.bootstrapToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	payload := parts[1]

	// Add padding if needed for base64 decoding
	for len(payload)%4 != 0 {
		payload += "="
	}

	// Decode base64 payload
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON to extract device_id
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	deviceID, ok := claims["device_id"].(string)
	if !ok {
		return fmt.Errorf("device_id not found in JWT claims")
	}

	i.deviceID = deviceID
	i.logger.Infof("Device ID extracted from JWT: %s", i.deviceID)
	return nil
}

func (i *Installer) detectSystem() error {
	i.logger.Info("Detecting system information...")

	// Detect architecture and map to StreamDeploy naming convention
	goArch := runtime.GOARCH
	switch goArch {
	case "amd64":
		i.architecture = "amd64"
	case "arm64":
		i.architecture = "arm64"
	case "arm":
		i.architecture = i.detectARMVariant()
	case "riscv64":
		i.architecture = "riscv64"
	default:
		return fmt.Errorf("unsupported architecture: %s", goArch)
	}

	// Detect OS from /etc/os-release
	osInfo, err := i.parseOSRelease()
	if err != nil {
		return fmt.Errorf("failed to parse /etc/os-release: %w", err)
	}

	i.osName = osInfo["ID"]
	i.osVersion = osInfo["VERSION_ID"]

	// Detect package manager
	i.packageManager = i.detectPackageManager()

	i.logger.Infof("Detected OS: %s %s", i.osName, i.osVersion)
	i.logger.Infof("Architecture: %s", i.architecture)
	i.logger.Infof("Package Manager: %s", i.packageManager.Type)

	return nil
}

func (i *Installer) detectARMVariant() string {
	// Try to detect ARM variant by checking /proc/cpuinfo
	if cpuInfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		cpuInfoStr := string(cpuInfo)

		// Look for ARM architecture version
		if strings.Contains(cpuInfoStr, "ARMv6") {
			return "armv6"
		}
		if strings.Contains(cpuInfoStr, "ARMv7") {
			return "armv7"
		}

		// Check for specific CPU features that indicate ARMv7
		if strings.Contains(cpuInfoStr, "vfpv3") || strings.Contains(cpuInfoStr, "neon") {
			return "armv7"
		}
	}

	// Default to armv7 if we can't determine the specific variant
	return "armv7"
}

func (i *Installer) parseOSRelease() (map[string]string, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	osInfo := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := parts[0]
			value := strings.Trim(parts[1], "\"")
			osInfo[key] = value
		}
	}

	return osInfo, scanner.Err()
}

func (i *Installer) detectPackageManager() PackageManager {
	managers := []struct {
		command string
		pm      PackageManager
	}{
		{"apt-get", PackageManager{
			Type:       "apt",
			InstallCmd: "apt-get install -y",
			CheckCmd:   "dpkg -l",
			RemoveCmd:  "apt-get remove -y",
			UpdateCmd:  "apt-get update",
		}},
		{"yum", PackageManager{
			Type:       "yum",
			InstallCmd: "yum install -y",
			CheckCmd:   "rpm -qa",
			RemoveCmd:  "yum remove -y",
			UpdateCmd:  "yum update",
		}},
		{"apk", PackageManager{
			Type:       "apk",
			InstallCmd: "apk add",
			CheckCmd:   "apk list --installed",
			RemoveCmd:  "apk del",
			UpdateCmd:  "apk update",
		}},
		{"pacman", PackageManager{
			Type:       "pacman",
			InstallCmd: "pacman -S --noconfirm",
			CheckCmd:   "pacman -Q",
			RemoveCmd:  "pacman -R --noconfirm",
			UpdateCmd:  "pacman -Sy",
		}},
	}

	for _, mgr := range managers {
		if i.commandExists(mgr.command) {
			return mgr.pm
		}
	}

	return PackageManager{Type: "unknown"}
}

func (i *Installer) commandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

func (i *Installer) installDependencies() error {
	i.logger.Info("=== Installing System Dependencies ===")

	if i.packageManager.Type == "unknown" {
		i.logger.Info("Unknown package manager, skipping dependency installation")
		return nil
	}

	i.logger.Infof("Using package manager: %s", i.packageManager.Type)

	// Update package list
	i.logger.Info("Updating package list...")
	if err := i.runCommandWithLog(i.packageManager.UpdateCmd, "Updating package list"); err != nil {
		i.logger.Errorf("Failed to update package list: %v", err)
	}

	// Install packages
	for _, pkg := range RequiredPackages {
		cmd := fmt.Sprintf("%s %s", i.packageManager.InstallCmd, pkg)
		if err := i.runCommandWithLog(cmd, fmt.Sprintf("Installing %s", pkg)); err != nil {
			i.logger.Errorf("Failed to install %s: %v", pkg, err)
			// Continue with other packages
		} else {
			i.logger.Infof("✓ Successfully installed %s", pkg)
		}
	}

	i.logger.Info("=== Dependency Installation Complete ===")
	return nil
}

func (i *Installer) runCommandWithLog(command string, description string) error {
	i.logger.Infof("Running: %s", description)
	cmd := exec.Command("sh", "-c", command)

	// Set working directory to root to avoid getcwd() issues
	cmd.Dir = "/"

	output, err := cmd.CombinedOutput()
	if err != nil {
		i.logger.Errorf("Command failed: %s", string(output))
		return err
	}
	if len(output) > 0 {
		i.logger.Infof("Command output: %s", string(output))
	}
	return nil
}

func (i *Installer) ensureAgentBinary() error {
	// Check if we're already running as the installed binary
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	expectedPath := filepath.Join(InstallDir, "streamdeploy-agent")

	// If we're already running from the install directory, no need to copy
	if currentBinary == expectedPath {
		i.logger.Info("Already running from install directory")
		return nil
	}

	i.logger.Info("Copying agent binary to install directory...")

	// Create install directory if it doesn't exist
	if err := os.MkdirAll(InstallDir, 0755); err != nil {
		return fmt.Errorf("failed to create install directory: %w", err)
	}

	// Copy current binary to install location
	sourceFile, err := os.Open(currentBinary)
	if err != nil {
		return fmt.Errorf("failed to open source binary: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(expectedPath)
	if err != nil {
		return fmt.Errorf("failed to create destination binary: %w", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	// Make executable
	if err := os.Chmod(expectedPath, 0755); err != nil {
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	i.logger.Infof("Agent binary installed to: %s", expectedPath)
	return nil
}

func (i *Installer) createConfig() error {
	i.logger.Info("Creating agent configuration...")

	// Create directories
	dirs := []string{ConfigDir, PKIDir, "/var/lib/streamdeploy"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create device config
	deviceConfig := DeviceConfig{
		DeviceID:           i.deviceID,
		EnrollBaseURL:      APIBase,
		HTTPSMTLSEndpoint:  HTTPSEndpoint,
		MQTTWSMTLSEndpoint: MQTTEndpoint,
		PKIDir:             PKIDir,
		OSName:             i.osName,
		OSVersion:          i.osVersion,
		Architecture:       i.architecture,
		PackageManager:     i.packageManager,
	}

	deviceConfigPath := filepath.Join(ConfigDir, "agent.json")
	if err := i.writeJSONFile(deviceConfigPath, deviceConfig); err != nil {
		return fmt.Errorf("failed to write device config: %w", err)
	}

	// Create state config
	stateConfig := StateConfig{
		SchemaVersion: "1.0",
		AgentSetting: AgentSetting{
			HeartbeatFrequency: "15s",
			UpdateFrequency:    "30s",
			Mode:               "http",
			AgentVer:           "1",
		},
		Containers:     []interface{}{},
		ContainerLogin: "",
		Env:            make(map[string]string),
		Packages:       RequiredPackages,
		CustomMetrics:  make(map[string]string),
		CustomPackages: make(map[string]interface{}),
	}

	stateConfigPath := filepath.Join(ConfigDir, "state.json")
	if err := i.writeJSONFile(stateConfigPath, stateConfig); err != nil {
		return fmt.Errorf("failed to write state config: %w", err)
	}

	i.logger.Info("Configuration created successfully")
	return nil
}

func (i *Installer) writeJSONFile(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, jsonData, 0644)
}

func (i *Installer) performCertificateExchange() error {
	i.logger.Info("Performing certificate exchange...")

	// Step 1: Enroll start
	nonce, caBundle, err := i.enrollStart()
	if err != nil {
		return fmt.Errorf("failed to start enrollment: %w", err)
	}

	// Step 2: Generate key and CSR
	privateKey, csr, err := i.generateKeyAndCSR()
	if err != nil {
		return fmt.Errorf("failed to generate key and CSR: %w", err)
	}

	// Step 3: Submit CSR
	certPEM, certChain, err := i.enrollCSR(nonce, csr)
	if err != nil {
		return fmt.Errorf("failed to enroll CSR: %w", err)
	}

	// Step 4: Save certificates
	if err := i.saveCertificates(privateKey, certPEM, certChain, caBundle); err != nil {
		return fmt.Errorf("failed to save certificates: %w", err)
	}

	i.logger.Info("Certificate exchange completed successfully")
	return nil
}

func (i *Installer) enrollStart() (string, string, error) {
	i.logger.Info("Starting enrollment...")

	payload := map[string]string{
		"enrollment_token": i.bootstrapToken,
	}

	resp, err := i.httpPost(APIBase+"/v1-app/enroll/start", payload)
	if err != nil {
		return "", "", err
	}

	var response EnrollStartResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return "", "", fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	i.logger.Info("Received nonce and CA bundle")
	return response.Nonce, response.CABundle, nil
}

func (i *Installer) generateKeyAndCSR() (string, string, error) {
	i.logger.Info("Generating RSA key and CSR...")

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create CSR template with both SPIFFE URI and DNS SAN for compatibility
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: i.deviceID,
		},
		DNSNames: []string{i.deviceID}, // Add DNS SAN as required by server
		URIs: []*url.URL{
			{
				Scheme: "spiffe",
				Host:   "streamdeploy.com", // Use proper domain
				Path:   "/device/" + i.deviceID,
			},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create CSR: %w", err)
	}

	// Encode private key to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyStr := string(pem.EncodeToMemory(privateKeyPEM))

	// Encode CSR to PEM
	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}
	csrStr := string(pem.EncodeToMemory(csrPEM))

	i.logger.Info("Generated key and CSR successfully")
	return privateKeyStr, csrStr, nil
}

func (i *Installer) enrollCSR(nonce, csr string) (string, string, error) {
	i.logger.Info("Enrolling CSR...")

	csrBase64 := base64.StdEncoding.EncodeToString([]byte(csr))

	payload := map[string]string{
		"token":      i.bootstrapToken,
		"nonce":      nonce,
		"csr_base64": csrBase64,
	}

	resp, err := i.httpPost(APIBase+"/v1-app/enroll/csr", payload)
	if err != nil {
		return "", "", fmt.Errorf("CSR enrollment request failed: %w", err)
	}

	var response EnrollCSRResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return "", "", fmt.Errorf("failed to parse CSR response: %w", err)
	}

	// Build certificate chain
	certChain := strings.Join(response.Chain, "\n")

	i.logger.Info("Received signed certificate successfully")
	return response.CertPEM, certChain, nil
}

func (i *Installer) httpPost(url string, payload interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "StreamDeploy-Agent/1.0")
	req.Header.Set("x-device-id", i.deviceID)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		i.logger.Errorf("HTTP request failed - URL: %s, Status: %d, Body: %s", url, resp.StatusCode, string(body))
		return nil, fmt.Errorf("request failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (i *Installer) saveCertificates(privateKey, certPEM, certChain, caBundle string) error {
	i.logger.Info("Saving certificates for mTLS...")

	// Save private key
	keyPath := filepath.Join(PKIDir, "device.key")
	if err := os.WriteFile(keyPath, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save leaf certificate only (required for proper mTLS)
	certPath := filepath.Join(PKIDir, "device.crt")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("failed to save leaf certificate: %w", err)
	}

	// Save intermediate certificates separately (required for mTLS chain validation)
	if certChain != "" {
		intermediatePath := filepath.Join(PKIDir, "intermediate.crt")
		if err := os.WriteFile(intermediatePath, []byte(certChain), 0644); err != nil {
			return fmt.Errorf("failed to save intermediate certificates: %w", err)
		}
		i.logger.Info("Saved intermediate certificate chain")
	}

	// Save full certificate chain (leaf + intermediates) for applications that need it
	fullChainPath := filepath.Join(PKIDir, "fullchain.crt")
	var fullChain strings.Builder
	fullChain.WriteString(certPEM)
	if !strings.HasSuffix(certPEM, "\n") {
		fullChain.WriteString("\n")
	}
	if certChain != "" {
		fullChain.WriteString(certChain)
		if !strings.HasSuffix(certChain, "\n") {
			fullChain.WriteString("\n")
		}
	}
	if err := os.WriteFile(fullChainPath, []byte(fullChain.String()), 0644); err != nil {
		return fmt.Errorf("failed to save full certificate chain: %w", err)
	}

	// Save CA bundle (root certificates)
	caPath := filepath.Join(PKIDir, "ca.crt")
	if err := os.WriteFile(caPath, []byte(caBundle), 0644); err != nil {
		return fmt.Errorf("failed to save CA bundle: %w", err)
	}

	i.logger.Infof("Certificates saved to %s", PKIDir)
	i.logger.Info("Saved files: device.key, device.crt (leaf), intermediate.crt, fullchain.crt, ca.crt")
	return nil
}

func (i *Installer) createSystemdService() error {
	i.logger.Info("Creating systemd service...")

	serviceContent := fmt.Sprintf(`[Unit]
Description=StreamDeploy Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s/streamdeploy-agent %s/agent.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, InstallDir, ConfigDir)

	if err := os.WriteFile(ServiceFile, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	i.logger.Info("Systemd service created successfully")
	return nil
}

func (i *Installer) enableAndStartService() error {
	i.logger.Info("Enabling and starting StreamDeploy agent service...")

	if !i.commandExists("systemctl") {
		i.logger.Info("systemctl not available, skipping service start")
		return nil
	}

	commands := []string{
		"systemctl daemon-reload",
		"systemctl enable streamdeploy-agent",
		"systemctl start streamdeploy-agent",
	}

	for _, cmd := range commands {
		if err := i.runCommand(cmd); err != nil {
			i.logger.Errorf("Failed to run command '%s': %v", cmd, err)
		}
	}

	i.logger.Info("StreamDeploy agent service enabled and started")
	return nil
}

func (i *Installer) runCommand(command string) error {
	cmd := exec.Command("sh", "-c", command)

	// Set working directory to root to avoid getcwd() issues
	cmd.Dir = "/"

	return cmd.Run()
}

// cleanupAndExit performs cleanup after successful installation and exits
func (i *Installer) cleanupAndExit() error {
	// Get current executable path
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable: %w", err)
	}

	expectedPath := filepath.Join(InstallDir, "streamdeploy-agent")

	// Only cleanup if we're NOT the installed binary
	if currentBinary != expectedPath {
		i.logger.Info("Installation complete. Cleaning up installer...")

		// Verify service is running
		if err := i.verifyServiceRunning(); err != nil {
			return fmt.Errorf("service verification failed: %w", err)
		}

		// Remove installer binary
		if err := os.Remove(currentBinary); err != nil {
			i.logger.Errorf("Failed to remove installer binary: %v", err)
		} else {
			i.logger.Info("Installer binary removed successfully")
		}

		i.logger.Info("Installation complete. Exiting installer.")
		os.Exit(0)
	}

	return nil
}

// verifyServiceRunning checks that the systemd service is running properly
func (i *Installer) verifyServiceRunning() error {
	if !i.commandExists("systemctl") {
		i.logger.Info("systemctl not available, skipping service verification")
		return nil
	}

	i.logger.Info("Verifying service is running...")

	// Wait a moment for service to start
	time.Sleep(2 * time.Second)

	// Check service status
	cmd := exec.Command("systemctl", "is-active", "streamdeploy-agent")
	// Set working directory to root to avoid getcwd() issues
	cmd.Dir = "/"
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("service is not active: %w", err)
	}

	status := strings.TrimSpace(string(output))
	if status != "active" {
		return fmt.Errorf("service status is '%s', expected 'active'", status)
	}

	i.logger.Info("Service is running successfully")
	return nil
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
		config.PKIDir = PKIDir
	}

	return &config, nil
}
