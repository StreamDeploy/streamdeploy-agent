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

// RequiredPackages contains the essential packages that must be installed during agent installation
var RequiredPackages = []string{
	"ca-certificates", // For HTTPS/TLS connections
	"systemd",         // For service management
	"docker.io",       // For container management
	"curl",            // For health checks
	"openssl",         // For certificate expiration checks
}

// DefaultStateConfig contains the default state configuration values
var DefaultStateConfig = StateConfig{
	SchemaVersion: "1.0",
	AgentSetting: AgentSetting{
		HeartbeatFrequency: "15s",
		UpdateFrequency:    "30s",
		Mode:               "http",
		AgentVer:           "1.0.0",
		LoggingLevel:       "info",
	},
	Containers:     []interface{}{},
	Packages:       RequiredPackages,
	Env:            make(map[string]string),
	CustomMetrics:  make(map[string]string),
	CustomPackages: make(map[string]interface{}),
}

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
	MachineType        string `json:"machine_type"`
}

type StateConfig struct {
	SchemaVersion  string                 `json:"schemaVersion"`
	AgentSetting   AgentSetting           `json:"agent_setting"`
	Containers     []interface{}          `json:"containers"`
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
	LoggingLevel       string `json:"logging_level"`
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
	machineType    string
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

	if err := i.installRequiredPackages(); err != nil {
		return fmt.Errorf("failed to install required packages: %w", err)
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
	token := GetBootstrapToken()
	if token != "" {
		i.bootstrapToken = token
		i.logger.Info("Bootstrap token found")
		return true
	}
	return false
}

func (i *Installer) extractDeviceIDFromJWT() error {
	deviceID, err := ExtractDeviceIDFromJWT(i.bootstrapToken)
	if err != nil {
		return err
	}

	i.deviceID = deviceID
	i.logger.Infof("Device ID extracted from JWT: %s", i.deviceID)
	return nil
}

func (i *Installer) detectSystem() error {
	i.logger.Info("Detecting system information...")

	// Use the modular system detection functions
	systemInfo, err := DetectSystemInfo()
	if err != nil {
		return fmt.Errorf("failed to detect system information: %w", err)
	}

	// Detect machine type
	machineType := DetectMachineType()

	// Set the detected values
	i.osName = systemInfo.OSName
	i.osVersion = systemInfo.OSVersion
	i.architecture = systemInfo.Architecture
	i.machineType = machineType

	i.logger.Infof("Detected OS: %s %s", i.osName, i.osVersion)
	i.logger.Infof("Architecture: %s", i.architecture)
	i.logger.Infof("Machine Type: %s", i.machineType)

	return nil
}

func (i *Installer) installRequiredPackages() error {
	i.logger.Info("Installing required packages...")

	// Check if apt is available (Ubuntu/Debian)
	if CommandExists("apt") {
		return i.installPackagesWithApt()
	}

	// Check if yum is available (RHEL/CentOS)
	if CommandExists("yum") {
		return i.installPackagesWithYum()
	}

	// Check if dnf is available (Fedora/newer RHEL)
	if CommandExists("dnf") {
		return i.installPackagesWithDnf()
	}

	// Check if apk is available (Alpine)
	if CommandExists("apk") {
		return i.installPackagesWithApk()
	}

	i.logger.Info("No supported package manager found, skipping package installation")
	return nil
}

func (i *Installer) installPackagesWithApt() error {
	i.logger.Info("Installing packages using apt...")

	// Update package list first
	if err := RunShellCommand("apt update"); err != nil {
		i.logger.Infof("Failed to update package list: %v", err)
	}

	// Install required packages
	packages := strings.Join(RequiredPackages, " ")
	command := fmt.Sprintf("apt install -y %s", packages)

	if err := RunShellCommand(command); err != nil {
		return fmt.Errorf("failed to install required packages: %w", err)
	}

	i.logger.Info("Required packages installed successfully")
	return nil
}

func (i *Installer) installPackagesWithYum() error {
	i.logger.Info("Installing packages using yum...")

	packages := strings.Join(RequiredPackages, " ")
	command := fmt.Sprintf("yum install -y %s", packages)

	if err := RunShellCommand(command); err != nil {
		return fmt.Errorf("failed to install required packages: %w", err)
	}

	i.logger.Info("Required packages installed successfully")
	return nil
}

func (i *Installer) installPackagesWithDnf() error {
	i.logger.Info("Installing packages using dnf...")

	packages := strings.Join(RequiredPackages, " ")
	command := fmt.Sprintf("dnf install -y %s", packages)

	if err := RunShellCommand(command); err != nil {
		return fmt.Errorf("failed to install required packages: %w", err)
	}

	i.logger.Info("Required packages installed successfully")
	return nil
}

func (i *Installer) installPackagesWithApk() error {
	i.logger.Info("Installing packages using apk...")

	packages := strings.Join(RequiredPackages, " ")
	command := fmt.Sprintf("apk add %s", packages)

	if err := RunShellCommand(command); err != nil {
		return fmt.Errorf("failed to install required packages: %w", err)
	}

	i.logger.Info("Required packages installed successfully")
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
		MachineType:        i.machineType,
	}

	deviceConfigPath := filepath.Join(ConfigDir, "agent.json")
	if err := WriteJSONFile(deviceConfigPath, deviceConfig); err != nil {
		return fmt.Errorf("failed to write device config: %w", err)
	}

	// Create state config
	stateConfig := DefaultStateConfig

	stateConfigPath := filepath.Join(ConfigDir, "state.json")
	if err := WriteJSONFile(stateConfigPath, stateConfig); err != nil {
		return fmt.Errorf("failed to write state config: %w", err)
	}

	i.logger.Info("Configuration created successfully")
	return nil
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
		"token":        i.bootstrapToken,
		"nonce":        nonce,
		"csr_base64":   csrBase64,
		"machine_type": i.machineType,
		"architecture": i.architecture,
		"os_name":      i.osName,
		"os_version":   i.osVersion,
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
	// Use the consolidated CreateServiceFile function
	return CreateServiceFile(i.logger)
}

func (i *Installer) enableAndStartService() error {
	i.logger.Info("Enabling and starting StreamDeploy agent service...")

	if !CommandExists("systemctl") {
		i.logger.Info("systemctl not available, skipping service start")
		return nil
	}

	commands := []string{
		"systemctl daemon-reload",
		"systemctl enable streamdeploy-agent",
		"systemctl start streamdeploy-agent",
	}

	for _, cmd := range commands {
		if err := RunShellCommand(cmd); err != nil {
			i.logger.Errorf("Failed to run command '%s': %v", cmd, err)
		}
	}

	i.logger.Info("StreamDeploy agent service enabled and started")
	return nil
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
	if !CommandExists("systemctl") {
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

// SystemInfo holds system detection information
type SystemInfo struct {
	OSName       string
	OSVersion    string
	Architecture string
}

// Public utility functions for use by main.go

// ExtractDeviceIDFromJWT extracts device ID from JWT token (public version)
func ExtractDeviceIDFromJWT(token string) (string, error) {
	// JWT has 3 parts separated by dots: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	payload := parts[1]

	// Add padding if needed for base64 decoding
	for len(payload)%4 != 0 {
		payload += "="
	}

	// Decode base64 payload
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON to extract device_id
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	deviceID, ok := claims["device_id"].(string)
	if !ok {
		return "", fmt.Errorf("device_id not found in JWT claims")
	}

	return deviceID, nil
}

// ExtractDeviceIDFromCert extracts the device ID from a certificate's Common Name
func ExtractDeviceIDFromCert(certData []byte) (string, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// The device ID should be in the Common Name (CN) of the certificate subject
	deviceID := cert.Subject.CommonName
	if deviceID == "" {
		return "", fmt.Errorf("device ID (CN) not found in certificate")
	}

	return deviceID, nil
}

// GetBootstrapToken gets bootstrap token from command line or environment (public version)
func GetBootstrapToken() string {
	// Check command line argument (skip first arg which is the binary name)
	if len(os.Args) >= 2 && len(os.Args[1]) > 0 && !strings.HasPrefix(os.Args[1], "/") {
		return os.Args[1]
	}

	// Check environment variable
	return os.Getenv("SD_BOOTSTRAP_TOKEN")
}

// DetectSystemInfo detects system information (public version)
func DetectSystemInfo() (*SystemInfo, error) {
	// Detect OS from /etc/os-release
	osInfo, err := ParseOSRelease()
	if err != nil {
		return nil, fmt.Errorf("failed to parse /etc/os-release: %w", err)
	}

	// Detect architecture
	arch := DetectArchitecture()
	if arch == "" {
		return nil, fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	return &SystemInfo{
		OSName:       osInfo["ID"],
		OSVersion:    osInfo["VERSION_ID"],
		Architecture: arch,
	}, nil
}

// ParseOSRelease parses /etc/os-release file (public version)
func ParseOSRelease() (map[string]string, error) {
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

// DetectArchitecture detects system architecture (public version)
func DetectArchitecture() string {
	// Use Go's runtime to detect architecture
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "arm":
		return DetectARMVariant()
	case "riscv64":
		return "riscv64"
	default:
		// Return error for unsupported architecture to match full installer behavior
		// This will cause DetectSystemInfo to fail, which is the correct behavior
		return ""
	}
}

// DetectARMVariant detects ARM variant (public version)
func DetectARMVariant() string {
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

// DetectMachineType detects machine type (public version)
func DetectMachineType() string {
	// Detect architecture first
	arch := DetectArchitecture()

	// Try to detect from device tree first (NVIDIA Jetson devices)
	if model, err := os.ReadFile("/sys/firmware/devicetree/base/model"); err == nil {
		modelStr := strings.TrimSpace(string(model))
		if strings.Contains(modelStr, "Jetson") {
			return modelStr
		}
		if strings.Contains(modelStr, "AGX Orin") || strings.Contains(modelStr, "Orin") {
			return "NVIDIA Jetson AGX Orin"
		}
		if strings.Contains(modelStr, "Xavier") {
			return "NVIDIA Jetson Xavier"
		}
		if strings.Contains(modelStr, "Nano") {
			return "NVIDIA Jetson Nano"
		}
	}

	// Try to detect Raspberry Pi from /proc/cpuinfo
	if cpuInfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		cpuInfoStr := string(cpuInfo)

		// Check for Raspberry Pi indicators
		if strings.Contains(cpuInfoStr, "Raspberry Pi") {
			// Try to extract model from cpuinfo
			lines := strings.Split(cpuInfoStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "Model") && strings.Contains(line, "Raspberry Pi") {
					model := strings.TrimSpace(strings.Split(line, ":")[1])
					return model
				}
			}
			return "Raspberry Pi"
		}

		// Check for other ARM-based single board computers
		if strings.Contains(cpuInfoStr, "Hardware") {
			lines := strings.Split(cpuInfoStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "Hardware") && strings.Contains(line, ":") {
					hardware := strings.TrimSpace(strings.Split(line, ":")[1])
					if strings.Contains(hardware, "ODROID") {
						return "ODROID " + hardware
					}
					if strings.Contains(hardware, "Banana Pi") || strings.Contains(hardware, "BananaPro") {
						return hardware
					}
					if strings.Contains(hardware, "Orange Pi") {
						return hardware
					}
					if strings.Contains(hardware, "Rockchip") {
						return "Rockchip " + hardware
					}
				}
			}
		}
	}

	// Check for RISC-V boards
	if arch == "riscv64" {
		// Try to detect from device tree
		if model, err := os.ReadFile("/sys/firmware/devicetree/base/model"); err == nil {
			modelStr := strings.TrimSpace(string(model))
			if strings.Contains(modelStr, "VisionFive") {
				return "StarFive VisionFive"
			}
			if strings.Contains(modelStr, "HiFive") {
				return "SiFive HiFive"
			}
			if strings.Contains(modelStr, "Pine64") || strings.Contains(modelStr, "Pine") {
				return "Pine64 " + modelStr
			}
			if strings.Contains(modelStr, "Unmatched") {
				return "SiFive HiFive Unmatched"
			}
			if strings.Contains(modelStr, "Allwinner") {
				return "Allwinner RISC-V " + modelStr
			}
			return modelStr
		}

		// Check /proc/cpuinfo for RISC-V specific information
		if cpuInfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			cpuInfoStr := string(cpuInfo)
			if strings.Contains(cpuInfoStr, "Hardware") {
				lines := strings.Split(cpuInfoStr, "\n")
				for _, line := range lines {
					if strings.Contains(line, "Hardware") && strings.Contains(line, ":") {
						hardware := strings.TrimSpace(strings.Split(line, ":")[1])
						if strings.Contains(hardware, "VisionFive") {
							return "StarFive VisionFive"
						}
						if strings.Contains(hardware, "HiFive") {
							return "SiFive HiFive"
						}
						if strings.Contains(hardware, "Pine64") {
							return "Pine64 " + hardware
						}
						if strings.Contains(hardware, "Unmatched") {
							return "SiFive HiFive Unmatched"
						}
						if strings.Contains(hardware, "Allwinner") {
							return "Allwinner RISC-V " + hardware
						}
					}
				}
			}
		}

		return "Generic RISC-V 64"
	}

	// Check for ARM64-based devices
	if arch == "arm64" {
		// Check if it's a virtual machine
		if hypervisor, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
			vendor := strings.TrimSpace(string(hypervisor))
			if strings.Contains(vendor, "QEMU") || strings.Contains(vendor, "VMware") || strings.Contains(vendor, "VirtualBox") {
				return "Virtual Machine (" + vendor + ")"
			}
		}

		// Check for specific ARM64 devices from DMI
		if product, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
			productStr := strings.TrimSpace(string(product))
			if strings.Contains(productStr, "Raspberry Pi") {
				return "Raspberry Pi (" + productStr + ")"
			}
			if strings.Contains(productStr, "Orange Pi") {
				return "Orange Pi (" + productStr + ")"
			}
			if strings.Contains(productStr, "Banana Pi") {
				return "Banana Pi (" + productStr + ")"
			}
			if strings.Contains(productStr, "Rockchip") {
				return "Rockchip (" + productStr + ")"
			}
		}

		// Check for ARM64-specific hardware from cpuinfo
		if cpuInfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			cpuInfoStr := string(cpuInfo)

			// Look for specific ARM64 hardware identifiers
			if strings.Contains(cpuInfoStr, "Hardware") {
				lines := strings.Split(cpuInfoStr, "\n")
				for _, line := range lines {
					if strings.Contains(line, "Hardware") && strings.Contains(line, ":") {
						hardware := strings.TrimSpace(strings.Split(line, ":")[1])
						if strings.Contains(hardware, "Raspberry Pi") {
							return "Raspberry Pi " + hardware
						}
						if strings.Contains(hardware, "Orange Pi") {
							return "Orange Pi " + hardware
						}
						if strings.Contains(hardware, "Banana Pi") {
							return "Banana Pi " + hardware
						}
						if strings.Contains(hardware, "Rockchip") {
							return "Rockchip " + hardware
						}
						if strings.Contains(hardware, "Allwinner") {
							return "Allwinner " + hardware
						}
						if strings.Contains(hardware, "Amlogic") {
							return "Amlogic " + hardware
						}
						if strings.Contains(hardware, "Broadcom") {
							return "Broadcom " + hardware
						}
					}
				}
			}

			// Check for specific CPU features that might indicate device type
			if strings.Contains(cpuInfoStr, "BCM2711") {
				return "Raspberry Pi 4 Model B"
			}
			if strings.Contains(cpuInfoStr, "BCM2835") {
				return "Raspberry Pi 1/Zero"
			}
			if strings.Contains(cpuInfoStr, "BCM2836") {
				return "Raspberry Pi 2"
			}
			if strings.Contains(cpuInfoStr, "BCM2837") {
				return "Raspberry Pi 3"
			}
		}

		return "Generic ARM64"
	}

	// Check for Intel NUC or other x86-based devices
	if arch == "amd64" || arch == "x86_64" {
		// Check if it's a virtual machine
		if hypervisor, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
			vendor := strings.TrimSpace(string(hypervisor))
			if strings.Contains(vendor, "QEMU") || strings.Contains(vendor, "VMware") || strings.Contains(vendor, "VirtualBox") {
				return "Virtual Machine (" + vendor + ")"
			}
		}

		// Check for specific x86 devices
		if product, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
			productStr := strings.TrimSpace(string(product))
			if strings.Contains(productStr, "NUC") {
				return "Intel NUC (" + productStr + ")"
			}
			if strings.Contains(productStr, "Raspberry Pi") {
				return "Raspberry Pi (" + productStr + ")"
			}
		}

		return "Generic x86_64"
	}

	// Default fallback - never return empty or "Unknown"
	if arch != "" {
		return "Generic " + arch
	}
	return "Generic"
}

// WriteJSONFile writes data to JSON file (public version)
func WriteJSONFile(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, jsonData, 0644)
}

// RunSystemCommand runs a system command (public version)
func RunSystemCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = "/"
	return cmd.Run()
}

// RunShellCommand runs a shell command (public version)
func RunShellCommand(command string) error {
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = "/"
	return cmd.Run()
}

// CommandExists checks if a command is available in PATH (public version)
func CommandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// IsRunningUnderSystemd checks if we're running under systemd using multiple indicators
func IsRunningUnderSystemd() bool {
	// Check environment variables that systemd sets
	invocationID := os.Getenv("INVOCATION_ID")
	notifySocket := os.Getenv("NOTIFY_SOCKET")

	// Check if we have systemd environment variables (most reliable)
	if invocationID != "" || notifySocket != "" {
		return true
	}

	// Check if we have a systemd journal fd (fd 3 is typically used by systemd)
	if fd3, err := os.Open("/proc/self/fd/3"); err == nil {
		fd3.Close()
		// Check if it's a systemd journal fd by checking the file descriptor info
		if link, err := os.Readlink("/proc/self/fd/3"); err == nil && strings.Contains(link, "socket") {
			return true
		}
	}

	// Check if we're running as a systemd service by checking our parent process
	if ppid := os.Getppid(); ppid > 1 {
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ppid)); err == nil {
			cmdlineStr := strings.TrimRight(string(cmdline), "\x00")
			if strings.Contains(cmdlineStr, "systemd") || strings.Contains(cmdlineStr, "systemctl") {
				return true
			}
		}
	}

	// Check if we're running from the expected systemd location
	if currentBinary, err := os.Executable(); err == nil {
		if currentBinary == "/usr/local/bin/streamdeploy-agent" {
			// If we're running from the systemd location, check if systemd is managing us
			if IsServiceActive() {
				return true
			}
		}
	}

	return false
}

// IsServiceActive checks if our service is currently active in systemctl
func IsServiceActive() bool {
	if !CommandExists("systemctl") {
		return false
	}

	cmd := exec.Command("systemctl", "is-active", "streamdeploy-agent")
	// Set working directory to root to avoid getcwd() issues
	cmd.Dir = "/"
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "active"
}

// IsServiceInstalled checks if the systemd service is installed
func IsServiceInstalled() bool {
	_, err := os.Stat("/etc/systemd/system/streamdeploy-agent.service")
	return err == nil
}

// CopyBinaryToInstallDir copies the current binary to the install directory
func CopyBinaryToInstallDir(logger types.Logger, sourcePath, destPath string) error {
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

// CreateServiceFile creates the systemd service file
func CreateServiceFile(logger types.Logger) error {
	logger.Info("Creating systemd service file...")

	serviceContent := `[Unit]
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

# Resource accounting
CPUAccounting=yes
MemoryAccounting=yes
IOAccounting=yes
TasksAccounting=yes

# systemd automatically sets INVOCATION_ID for service detection

# Security settings - permissive to allow agent full system access while preventing device bricking
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
# Allow access to critical system paths but prevent modification of boot/kernel files
PrivateTmp=false
PrivateDevices=false
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectControlGroups=false
# Prevent access to critical system files that could brick the device
InaccessiblePaths=/boot /sys/firmware /proc/sys/kernel /proc/sysrq-trigger

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile("/etc/systemd/system/streamdeploy-agent.service", []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	logger.Info("Service file created successfully")
	return nil
}

// EnableAndStartService enables and starts the systemd service
func EnableAndStartService(logger types.Logger) error {
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

		// Set working directory to root to avoid getcwd() issues
		cmd.Dir = "/"

		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Errorf("Failed to run %s: %v, output: %s", cmdInfo.desc, err, string(output))
			return fmt.Errorf("failed to run %s: %w", cmdInfo.desc, err)
		}
	}

	logger.Info("Service enabled and started successfully")
	return nil
}

// Modular initialization functions for use by main.go

// RunModularInitialization performs modular initialization checks
func RunModularInitialization(logger types.Logger, configPath string) error {
	logger.Info("Starting modular initialization flow...")

	// Step 1: Check and create agent.json if needed
	if err := EnsureAgentConfig(logger, configPath); err != nil {
		return fmt.Errorf("failed to ensure agent config: %w", err)
	}

	// Step 2: Check and create state.json if needed
	if err := EnsureStateConfig(logger); err != nil {
		return fmt.Errorf("failed to ensure state config: %w", err)
	}

	// Step 3: Check and perform certificate flow if needed
	if err := EnsureCertificates(logger, configPath); err != nil {
		return fmt.Errorf("failed to ensure certificates: %w", err)
	}

	// Step 4: Handle systemd service management
	if err := HandleSystemdService(logger, configPath); err != nil {
		return fmt.Errorf("failed to handle systemd service: %w", err)
	}

	logger.Info("Modular initialization completed successfully")
	return nil
}

// EnsureAgentConfig checks if agent.json exists, creates it if not
func EnsureAgentConfig(logger types.Logger, configPath string) error {
	logger.Info("Checking agent.json configuration...")

	if _, err := os.Stat(configPath); err == nil {
		logger.Info("agent.json already exists")
		return nil
	}

	logger.Info("agent.json not found, creating default configuration...")

	// Check if certificates exist - if they do, we don't need bootstrap token
	pkiDir := PKIDir
	requiredCertFiles := []string{
		filepath.Join(pkiDir, "ca.crt"),
		filepath.Join(pkiDir, "device.crt"),
		filepath.Join(pkiDir, "device.key"),
		filepath.Join(pkiDir, "fullchain.crt"),
	}

	certsExist := true
	for _, file := range requiredCertFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			certsExist = false
			break
		}
	}

	var deviceID string
	if certsExist {
		// Certificates exist, we can extract device ID from the certificate
		logger.Info("Certificates found, extracting device ID from certificate...")
		certData, err := os.ReadFile(filepath.Join(pkiDir, "device.crt"))
		if err != nil {
			return fmt.Errorf("failed to read device certificate: %w", err)
		}

		// Extract device ID from cert CN (Common Name)
		deviceID, err = ExtractDeviceIDFromCert(certData)
		if err != nil {
			return fmt.Errorf("failed to extract device_id from certificate: %w", err)
		}
		logger.Infof("Extracted device ID from certificate: %s", deviceID)
	} else {
		// No certificates, bootstrap token is required
		bootstrapToken := GetBootstrapToken()
		if bootstrapToken == "" {
			return fmt.Errorf("bootstrap token is required to create agent.json. Usage: sudo ./streamdeploy-agent <token> or export SD_BOOTSTRAP_TOKEN=\"your-token\"")
		}

		// Extract device ID from JWT
		var err error
		deviceID, err = ExtractDeviceIDFromJWT(bootstrapToken)
		if err != nil {
			return fmt.Errorf("failed to extract device_id from bootstrap token: %w", err)
		}
		logger.Infof("Extracted device ID from bootstrap token: %s", deviceID)
	}

	// Detect system information
	osInfo, err := DetectSystemInfo()
	if err != nil {
		return fmt.Errorf("failed to detect system information: %w", err)
	}

	// Detect machine type
	machineType := DetectMachineType()

	// Create device config
	deviceConfig := DeviceConfig{
		DeviceID:           deviceID,
		EnrollBaseURL:      APIBase,
		HTTPSMTLSEndpoint:  HTTPSEndpoint,
		MQTTWSMTLSEndpoint: MQTTEndpoint,
		PKIDir:             PKIDir,
		OSName:             osInfo.OSName,
		OSVersion:          osInfo.OSVersion,
		Architecture:       osInfo.Architecture,
		MachineType:        machineType,
	}

	// Create config directory
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write config file
	if err := WriteJSONFile(configPath, deviceConfig); err != nil {
		return fmt.Errorf("failed to write agent config: %w", err)
	}

	logger.Infof("Created agent.json with device ID: %s", deviceID)
	return nil
}

// EnsureStateConfig checks if state.json exists, creates it if not
func EnsureStateConfig(logger types.Logger) error {
	logger.Info("Checking state.json configuration...")

	stateConfigPath := "/etc/streamdeploy/state.json"
	if _, err := os.Stat(stateConfigPath); err == nil {
		logger.Info("state.json already exists")
		return nil
	}

	logger.Info("state.json not found, creating default configuration...")

	// Create state config with default values
	stateConfig := DefaultStateConfig

	// Create config directory
	if err := os.MkdirAll("/etc/streamdeploy", 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write state config file
	if err := WriteJSONFile(stateConfigPath, stateConfig); err != nil {
		return fmt.Errorf("failed to write state config: %w", err)
	}

	logger.Info("Created state.json with default configuration")
	return nil
}

// EnsureCertificates checks if certificates exist, runs cert flow if not
func EnsureCertificates(logger types.Logger, configPath string) error {
	logger.Info("Checking certificates...")

	// Load device config to get PKI directory
	deviceConfig, err := LoadDeviceConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load device config: %w", err)
	}

	pkiDir := deviceConfig.PKIDir
	if pkiDir == "" {
		pkiDir = PKIDir
	}

	// Check if certificates exist
	requiredFiles := []string{
		filepath.Join(pkiDir, "ca.crt"),
		filepath.Join(pkiDir, "device.crt"),
		filepath.Join(pkiDir, "device.key"),
		filepath.Join(pkiDir, "fullchain.crt"),
	}

	allExist := true
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			logger.Infof("Certificate file missing: %s", file)
			allExist = false
			break
		}
	}

	if allExist {
		logger.Info("All certificates found")
		return nil
	}

	logger.Info("Certificates missing, running certificate enrollment flow...")

	// Get bootstrap token
	bootstrapToken := GetBootstrapToken()
	if bootstrapToken == "" {
		return fmt.Errorf("bootstrap token is required for certificate enrollment")
	}

	// Run certificate enrollment using installer logic
	if err := PerformCertificateEnrollment(logger, deviceConfig, bootstrapToken); err != nil {
		return fmt.Errorf("certificate enrollment failed: %w", err)
	}

	logger.Info("Certificate enrollment completed successfully")
	return nil
}

// HandleSystemdService manages systemd service (stop, remove, replace, launch, kill self)
func HandleSystemdService(logger types.Logger, configPath string) error {
	logger.Info("Handling systemd service management...")

	// Check if systemctl is available
	if !CommandExists("systemctl") {
		logger.Info("systemctl not available, skipping service management")
		return nil
	}

	// Check if we have root privileges
	if os.Geteuid() != 0 {
		logger.Info("Not running as root, skipping service management")
		return nil
	}

	// Check if we're already running under systemd (avoid recursive service management)
	if IsRunningUnderSystemd() {
		logger.Info("Already running under systemd service, skipping service management")
		return nil
	}

	logger.Info("Not running under systemd, proceeding with service management")

	// Get current executable path
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	expectedPath := "/usr/local/bin/streamdeploy-agent"

	// Step 1: Stop existing systemd service if running (we're running manually)
	if IsServiceActive() {
		logger.Info("Stopping existing streamdeploy-agent systemd service...")
		if err := RunSystemCommand("systemctl", "stop", "streamdeploy-agent"); err != nil {
			logger.Errorf("Failed to stop service: %v", err)
		}
	}

	// Step 2: Disable existing service if installed
	if IsServiceInstalled() {
		logger.Info("Disabling existing streamdeploy-agent service...")
		if err := RunSystemCommand("systemctl", "disable", "streamdeploy-agent"); err != nil {
			logger.Errorf("Failed to disable service: %v", err)
		}
	}

	// Step 3: Replace the streamdeploy file with own executable
	if currentBinary != expectedPath {
		logger.Infof("Copying binary from %s to %s", currentBinary, expectedPath)
		if err := CopyBinaryToInstallDir(logger, currentBinary, expectedPath); err != nil {
			return fmt.Errorf("failed to copy binary to install directory: %w", err)
		}
	}

	// Step 4: Create and launch systemd service
	if err := CreateServiceFile(logger); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	if err := EnableAndStartService(logger); err != nil {
		return fmt.Errorf("failed to enable and start service: %w", err)
	}

	// Step 5: Kill itself if we're not the installed binary (replace with systemd version)
	if currentBinary != expectedPath {
		logger.Info("Systemd service started successfully. Replacing manual process with systemd service...")

		// Wait longer for service to fully start and stabilize
		time.Sleep(5 * time.Second)

		// Verify service is running and stable
		if !IsServiceActive() {
			return fmt.Errorf("service failed to start properly")
		}

		// Additional verification: check that the systemd instance is actually running
		time.Sleep(2 * time.Second)
		if !IsServiceActive() {
			return fmt.Errorf("service is not stable after start")
		}

		logger.Info("Systemd service verified as running and stable. Exiting manual process.")
		os.Exit(0)
	}

	return nil
}

// PerformCertificateEnrollment performs certificate enrollment only (without full installation)
func PerformCertificateEnrollment(logger types.Logger, deviceConfig *DeviceConfig, bootstrapToken string) error {
	logger.Info("Starting certificate enrollment process...")

	// Create PKI directory
	if err := os.MkdirAll(deviceConfig.PKIDir, 0755); err != nil {
		return fmt.Errorf("failed to create PKI directory: %w", err)
	}

	// Create installer instance for certificate enrollment
	installerInstance := &Installer{
		logger:         logger,
		bootstrapToken: bootstrapToken,
		deviceID:       deviceConfig.DeviceID,
		osName:         deviceConfig.OSName,
		osVersion:      deviceConfig.OSVersion,
		architecture:   deviceConfig.Architecture,
		machineType:    deviceConfig.MachineType,
	}

	// Run only the certificate exchange part (not the full installer)
	if err := installerInstance.performCertificateExchange(); err != nil {
		return fmt.Errorf("certificate enrollment failed: %w", err)
	}

	logger.Info("Certificate enrollment completed successfully")
	return nil
}

// LoadDeviceConfig loads the device configuration from file (public version)
func LoadDeviceConfig(configPath string) (*DeviceConfig, error) {
	return loadDeviceConfig(configPath)
}
