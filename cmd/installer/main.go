package main

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
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/utils"
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

type Installer struct {
	logger         types.Logger
	bootstrapToken string
	deviceID       string
	osName         string
	osVersion      string
	architecture   string
	packageManager PackageManager
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

func main() {
	logger := utils.NewLogger("INSTALLER")

	installer := &Installer{
		logger: logger,
	}

	if err := installer.Run(); err != nil {
		logger.Errorf("Installation failed: %v", err)
		os.Exit(1)
	}

	logger.Info("StreamDeploy agent installation completed successfully!")
	logger.Info("Check status with: systemctl status streamdeploy-agent")
	logger.Info("View logs with: journalctl -u streamdeploy-agent -f")
}

func (i *Installer) Run() error {
	i.logger.Info("StreamDeploy Agent Installer Starting...")

	if !i.checkRoot() {
		return fmt.Errorf("this installer must be run as root (use sudo)")
	}

	if !i.getBootstrapToken() {
		return fmt.Errorf("bootstrap token is required. Usage: sudo ./streamdeploy-installer <token> or export SD_BOOTSTRAP_TOKEN=\"your-token\"")
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

	if err := i.downloadOrBuildAgent(); err != nil {
		return fmt.Errorf("failed to install StreamDeploy agent binary: %w", err)
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

	if err := i.startService(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

func (i *Installer) checkRoot() bool {
	return os.Geteuid() == 0
}

func (i *Installer) getBootstrapToken() bool {
	// Check command line argument
	if len(os.Args) >= 2 && len(os.Args[1]) > 0 {
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
		// For ARM, we need to detect the specific variant
		// Default to armv7, but could be enhanced to detect armv6/armv7 specifically
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

	// Step 1: Check which packages are already installed
	i.logger.Info("Step 1: Checking existing packages...")
	installedPackages, err := i.checkInstalledPackages()
	if err != nil {
		i.logger.Errorf("Failed to check installed packages: %v", err)
		installedPackages = make(map[string]bool)
	}

	// Step 2: Update package list
	i.logger.Info("Step 2: Updating package list...")
	if err := i.runCommandWithLog(i.packageManager.UpdateCmd, "Updating package list"); err != nil {
		i.logger.Errorf("Failed to update package list: %v", err)
		// Continue with installation even if update fails
	}

	// Step 3: Install missing packages
	i.logger.Info("Step 3: Installing missing packages...")
	packagesToInstall := []string{}
	packagesAlreadyInstalled := []string{}

	for _, pkg := range RequiredPackages {
		if installedPackages[pkg] {
			packagesAlreadyInstalled = append(packagesAlreadyInstalled, pkg)
			i.logger.Infof("✓ Package %s is already installed", pkg)
		} else {
			packagesToInstall = append(packagesToInstall, pkg)
		}
	}

	if len(packagesAlreadyInstalled) > 0 {
		i.logger.Infof("Found %d already installed packages: %v", len(packagesAlreadyInstalled), packagesAlreadyInstalled)
	}

	if len(packagesToInstall) > 0 {
		i.logger.Infof("Installing %d missing packages: %v", len(packagesToInstall), packagesToInstall)

		for _, pkg := range packagesToInstall {
			cmd := fmt.Sprintf("%s %s", i.packageManager.InstallCmd, pkg)
			if err := i.runCommandWithLog(cmd, fmt.Sprintf("Installing %s", pkg)); err != nil {
				i.logger.Errorf("Failed to install %s: %v", pkg, err)
				return fmt.Errorf("failed to install package %s: %w", pkg, err)
			}
			i.logger.Infof("✓ Successfully installed %s", pkg)
		}
	} else {
		i.logger.Info("✓ All required packages are already installed")
	}

	// Step 4: Verify installations
	i.logger.Info("Step 4: Verifying package installations...")
	if err := i.verifyPackageInstallations(); err != nil {
		i.logger.Errorf("Package verification failed: %v", err)
		// Don't fail the installation for verification issues
	}

	i.logger.Info("=== Dependency Installation Complete ===")
	return nil
}

func (i *Installer) runCommand(command string) error {
	cmd := exec.Command("sh", "-c", command)
	return cmd.Run()
}

func (i *Installer) runCommandWithLog(command string, description string) error {
	i.logger.Infof("Running: %s", description)
	cmd := exec.Command("sh", "-c", command)
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

func (i *Installer) checkInstalledPackages() (map[string]bool, error) {
	installedPackages := make(map[string]bool)

	// Run the check command to get list of installed packages
	cmd := exec.Command("sh", "-c", i.packageManager.CheckCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to check installed packages: %w", err)
	}

	installedList := string(output)

	// Check each required package
	for _, pkg := range RequiredPackages {
		installed := i.isPackageInstalled(pkg, installedList)
		installedPackages[pkg] = installed
		if installed {
			i.logger.Infof("Package %s is installed", pkg)
		} else {
			i.logger.Infof("Package %s is not installed", pkg)
		}
	}

	return installedPackages, nil
}

func (i *Installer) isPackageInstalled(packageName, installedList string) bool {
	// Different package managers have different output formats
	switch i.packageManager.Type {
	case "apt":
		// For apt, check if package name appears in dpkg -l output
		// Format: ii  package-name  version  architecture  description
		lines := strings.Split(installedList, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "ii" && fields[1] == packageName {
				return true
			}
		}
	case "yum":
		// For yum, check if package name appears in rpm -qa output
		lines := strings.Split(installedList, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, packageName+"-") {
				return true
			}
		}
	case "apk":
		// For apk, check if package name appears in apk list output
		lines := strings.Split(installedList, "\n")
		for _, line := range lines {
			if strings.Contains(line, packageName) && strings.Contains(line, "[installed]") {
				return true
			}
		}
	case "pacman":
		// For pacman, check if package name appears in pacman -Q output
		lines := strings.Split(installedList, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 1 && fields[0] == packageName {
				return true
			}
		}
	}

	return false
}

func (i *Installer) verifyPackageInstallations() error {
	i.logger.Info("Verifying that installed packages are working correctly...")

	verificationTests := map[string]func() error{
		"curl": func() error {
			cmd := exec.Command("curl", "--version")
			return cmd.Run()
		},
		"ca-certificates": func() error {
			// Check if ca-certificates directory exists
			_, err := os.Stat("/etc/ssl/certs")
			return err
		},
		"systemd": func() error {
			cmd := exec.Command("systemctl", "--version")
			return cmd.Run()
		},
		"docker.io": func() error {
			cmd := exec.Command("docker", "--version")
			return cmd.Run()
		},
	}

	allVerified := true
	for pkg, testFunc := range verificationTests {
		if err := testFunc(); err != nil {
			i.logger.Errorf("Verification failed for %s: %v", pkg, err)
			allVerified = false
		} else {
			i.logger.Infof("✓ %s verification passed", pkg)
		}
	}

	if !allVerified {
		return fmt.Errorf("some package verifications failed")
	}

	i.logger.Info("✓ All package verifications passed")
	return nil
}

func (i *Installer) downloadOrBuildAgent() error {
	i.logger.Info("Downloading StreamDeploy agent binary...")

	// Validate that we have a supported architecture
	supportedArchs := []string{"amd64", "arm64", "armv6", "armv7", "riscv64"}
	archSupported := false
	for _, arch := range supportedArchs {
		if i.architecture == arch {
			archSupported = true
			break
		}
	}

	if !archSupported {
		return fmt.Errorf("unsupported architecture: %s. Supported architectures: %v", i.architecture, supportedArchs)
	}

	// Construct download URL using the specified naming convention
	downloadURL := fmt.Sprintf("https://get.streamdeploy.com/agent/streamdeploy-agent-linux-%s", i.architecture)
	i.logger.Infof("Downloading from: %s", downloadURL)

	// Download the binary
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download agent binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download agent binary: HTTP %d", resp.StatusCode)
	}

	// Create install directory if it doesn't exist
	if err := os.MkdirAll(InstallDir, 0755); err != nil {
		return fmt.Errorf("failed to create install directory: %w", err)
	}

	// Create the binary file
	binaryPath := filepath.Join(InstallDir, "streamdeploy-agent")
	file, err := os.Create(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to create binary file: %w", err)
	}
	defer file.Close()

	// Copy the downloaded content to the file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write binary file: %w", err)
	}

	// Make the binary executable
	if err := os.Chmod(binaryPath, 0755); err != nil {
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	i.logger.Infof("Agent binary installed successfully to: %s", binaryPath)
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
	i.logger.Infof("CSR includes DNS SAN: %s and SPIFFE URI: spiffe://streamdeploy.com/device/%s", i.deviceID, i.deviceID)
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

	i.logger.Infof("Sending CSR enrollment request to: %s", APIBase+"/v1-app/enroll/csr")
	i.logger.Infof("CSR length: %d bytes", len(csr))
	i.logger.Infof("Base64 CSR length: %d bytes", len(csrBase64))
	i.logger.Infof("Token length: %d bytes", len(i.bootstrapToken))
	i.logger.Infof("Nonce length: %d bytes", len(nonce))

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
	i.logger.Infof("Certificate PEM length: %d bytes", len(response.CertPEM))
	i.logger.Infof("Certificate chain parts: %d", len(response.Chain))
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
	req.Header.Set("User-Agent", "StreamDeploy-Installer/1.0")
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
	i.logger.Info("Saving certificates...")

	// Save private key
	keyPath := filepath.Join(PKIDir, "device.key")
	if err := os.WriteFile(keyPath, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save certificate with chain
	certPath := filepath.Join(PKIDir, "device.crt")
	fullCert := certPEM + "\n" + certChain
	if err := os.WriteFile(certPath, []byte(fullCert), 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	// Save CA bundle
	caPath := filepath.Join(PKIDir, "ca.crt")
	if err := os.WriteFile(caPath, []byte(caBundle), 0644); err != nil {
		return fmt.Errorf("failed to save CA bundle: %w", err)
	}

	i.logger.Infof("Certificates saved to %s", PKIDir)
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

func (i *Installer) startService() error {
	i.logger.Info("Starting StreamDeploy agent service...")

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

	i.logger.Info("StreamDeploy agent service started")
	return nil
}
