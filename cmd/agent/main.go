package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/container"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/environment"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/https"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/metrics"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/packages"
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

	// Run modular initialization flow
	if err := runModularInitialization(logger, configPath); err != nil {
		logger.Errorf("Initialization failed: %v", err)
		os.Exit(1)
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

	// Set up certificate manager with proper implementation
	certificateManager := createCertificateManager(pkiDir, deviceConfig.DeviceID, httpsClient, utils.NewLogger("CERT"))
	coreAgent.SetCertificateManager(certificateManager)
	logger.Info("Certificate manager configured with renewal support")

	// Set up environment manager
	environmentManager := environment.NewManager(utils.NewLogger("ENV"))
	coreAgent.SetEnvironmentManager(environmentManager)
	logger.Info("Environment manager configured")

	// Set up package manager
	packageManager := packages.NewManager(utils.NewLogger("PACKAGE"))
	coreAgent.SetPackageManager(packageManager)
	logger.Info("Package manager configured")

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
func createCertificateManager(pkiDir, deviceID string, httpClient interface{}, logger interface{}) types.CertificateManager {
	// Cast the interfaces to their proper types
	httpClientTyped, ok := httpClient.(types.HTTPClient)
	if !ok {
		panic("httpClient must implement types.HTTPClient")
	}

	loggerTyped, ok := logger.(types.Logger)
	if !ok {
		panic("logger must implement types.Logger")
	}

	// Create a direct implementation to avoid import issues with auto-formatter
	return &certificateManagerImpl{
		pkiDir:     pkiDir,
		deviceID:   deviceID,
		httpClient: httpClientTyped,
		logger:     loggerTyped,
	}
}

// certificateManagerImpl implements the CertificateManager interface
type certificateManagerImpl struct {
	pkiDir     string
	deviceID   string
	httpClient types.HTTPClient
	logger     types.Logger
}

// Implement the CertificateManager interface methods with full functionality
func (c *certificateManagerImpl) GetCertificateInfo() (*types.CertificateInfo, error) {
	certPath := c.GetCertificatePath()
	keyPath := c.GetPrivateKeyPath()
	caCertPath := c.GetCACertificatePath()

	// Check if certificate file exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate file not found: %s", certPath)
	}

	// Get certificate expiration using openssl
	cmd := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-dates")
	// Set working directory to root to avoid getcwd() issues
	cmd.Dir = "/"
	output, err := cmd.Output()
	if err != nil {
		c.logger.Errorf("Failed to get certificate dates: %v", err)
		// Return basic info without expiration
		return &types.CertificateInfo{
			CertPath:   certPath,
			KeyPath:    keyPath,
			CACertPath: caCertPath,
		}, nil
	}

	// Parse the output to get expiration date
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "notAfter=") {
			dateStr := strings.TrimPrefix(line, "notAfter=")
			// Parse the date format: "Jan  2 15:04:05 2006 GMT"
			if expiresAt, err := time.Parse("Jan  2 15:04:05 2006 MST", dateStr); err == nil {
				return &types.CertificateInfo{
					CertPath:   certPath,
					KeyPath:    keyPath,
					CACertPath: caCertPath,
					ExpiresAt:  expiresAt,
				}, nil
			}
			break
		}
	}

	// Return basic info if parsing failed
	return &types.CertificateInfo{
		CertPath:   certPath,
		KeyPath:    keyPath,
		CACertPath: caCertPath,
	}, nil
}

func (c *certificateManagerImpl) IsCertificateExpiringSoon(days int) bool {
	certInfo, err := c.GetCertificateInfo()
	if err != nil {
		c.logger.Errorf("Failed to get certificate info: %v", err)
		return true // Assume expiring if we can't check
	}

	if certInfo.ExpiresAt.IsZero() {
		c.logger.Info("Certificate expiration date not available, assuming not expiring")
		return false
	}

	threshold := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	isExpiring := certInfo.ExpiresAt.Before(threshold)

	if isExpiring {
		c.logger.Infof("Certificate expires at %v, which is within %d days", certInfo.ExpiresAt, days)
	} else {
		c.logger.Infof("Certificate expires at %v, which is more than %d days away", certInfo.ExpiresAt, days)
	}

	return isExpiring
}

func (c *certificateManagerImpl) RenewCertificate(deviceID, enrollEndpoint string) error {
	c.logger.Info("Starting certificate renewal process with mTLS support")

	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a certificate signing request with both DNS SAN and SPIFFE URI for compatibility
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: deviceID,
		},
		DNSNames:           []string{deviceID}, // Add DNS SAN as required by server
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Add SPIFFE URI manually
	spiffeURI := "spiffe://streamdeploy.com/device/" + deviceID
	template.Extensions = append(template.Extensions, pkix.Extension{
		Id:       []int{2, 5, 29, 17}, // Subject Alternative Name OID
		Critical: false,
		Value:    []byte(spiffeURI), // This is a simplified approach
	})

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Encode CSR to PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Base64 encode the CSR
	csrBase64 := base64.StdEncoding.EncodeToString(csrPEM)

	c.logger.Infof("Generated CSR for renewal with DNS SAN: %s and SPIFFE URI: %s", deviceID, spiffeURI)

	// Prepare the request payload
	requestPayload := map[string]string{
		"csr_base64": csrBase64,
	}

	requestData, err := json.Marshal(requestPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal request payload: %w", err)
	}

	// Send the renewal request
	renewalURL := fmt.Sprintf("%s/v1-device/enroll/renew", enrollEndpoint)
	headers := map[string]string{
		"Content-Type": "application/json",
		"x-device-id":  deviceID,
		"User-Agent":   "StreamDeploy-Agent/1.0",
	}

	response, err := c.httpClient.Post(renewalURL, requestData, headers)
	if err != nil {
		return fmt.Errorf("failed to send renewal request: %w", err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("certificate renewal failed with status %d: %s", response.StatusCode, string(response.Body))
	}

	// Parse successful response
	var renewalResponse struct {
		CertPEM  string    `json:"cert_pem"`
		Chain    []string  `json:"chain"`
		NotAfter time.Time `json:"not_after"`
	}

	if err := json.Unmarshal(response.Body, &renewalResponse); err != nil {
		return fmt.Errorf("failed to parse renewal response: %w", err)
	}

	// Save the new private key
	if err := c.savePrivateKey(privateKey); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save the new leaf certificate
	if err := c.saveCertificate(renewalResponse.CertPEM); err != nil {
		return fmt.Errorf("failed to save leaf certificate: %w", err)
	}

	// Save the intermediate certificates and full chain
	if err := c.saveCertificateChain(renewalResponse.CertPEM, renewalResponse.Chain); err != nil {
		return fmt.Errorf("failed to save certificate chain: %w", err)
	}

	c.logger.Infof("Certificate renewed successfully, expires at: %v", renewalResponse.NotAfter)
	return nil
}

func (c *certificateManagerImpl) GetCACertificatePath() string {
	return filepath.Join(c.pkiDir, "ca.crt")
}

func (c *certificateManagerImpl) GetCertificatePath() string {
	return filepath.Join(c.pkiDir, "device.crt")
}

func (c *certificateManagerImpl) GetPrivateKeyPath() string {
	return filepath.Join(c.pkiDir, "device.key")
}

// Helper methods for certificate operations
func (c *certificateManagerImpl) savePrivateKey(key *rsa.PrivateKey) error {
	keyPath := c.GetPrivateKeyPath()

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("failed to create PKI directory: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

func (c *certificateManagerImpl) saveCertificate(certPEM string) error {
	certPath := c.GetCertificatePath()

	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}

func (c *certificateManagerImpl) saveCertificateChain(leafCertPEM string, intermediateChain []string) error {
	c.logger.Info("Saving certificate chain for mTLS...")

	// Save intermediate certificates separately (required for mTLS chain validation)
	if len(intermediateChain) > 0 {
		intermediatePath := filepath.Join(c.pkiDir, "intermediate.crt")
		var intermediatePEM strings.Builder
		for _, cert := range intermediateChain {
			intermediatePEM.WriteString(cert)
			if !strings.HasSuffix(cert, "\n") {
				intermediatePEM.WriteString("\n")
			}
		}
		if err := os.WriteFile(intermediatePath, []byte(intermediatePEM.String()), 0644); err != nil {
			return fmt.Errorf("failed to write intermediate certificates: %w", err)
		}
		c.logger.Info("Saved intermediate certificate chain")
	}

	// Save full certificate chain (leaf + intermediates) for applications that need it
	fullChainPath := filepath.Join(c.pkiDir, "fullchain.crt")
	var fullChain strings.Builder
	fullChain.WriteString(leafCertPEM)
	if !strings.HasSuffix(leafCertPEM, "\n") {
		fullChain.WriteString("\n")
	}
	for _, cert := range intermediateChain {
		fullChain.WriteString(cert)
		if !strings.HasSuffix(cert, "\n") {
			fullChain.WriteString("\n")
		}
	}
	if err := os.WriteFile(fullChainPath, []byte(fullChain.String()), 0644); err != nil {
		return fmt.Errorf("failed to write full certificate chain: %w", err)
	}

	c.logger.Info("Saved certificate files: device.crt (leaf), intermediate.crt, fullchain.crt")
	return nil
}

// runModularInitialization performs modular initialization checks
func runModularInitialization(logger types.Logger, configPath string) error {
	logger.Info("Starting modular initialization flow...")

	// Step 1: Check and create agent.json if needed
	if err := ensureAgentConfig(logger, configPath); err != nil {
		return fmt.Errorf("failed to ensure agent config: %w", err)
	}

	// Step 2: Check and create state.json if needed
	if err := ensureStateConfig(logger); err != nil {
		return fmt.Errorf("failed to ensure state config: %w", err)
	}

	// Step 3: Check and perform certificate flow if needed
	if err := ensureCertificates(logger, configPath); err != nil {
		return fmt.Errorf("failed to ensure certificates: %w", err)
	}

	// Step 4: Handle systemd service management
	if err := handleSystemdService(logger, configPath); err != nil {
		return fmt.Errorf("failed to handle systemd service: %w", err)
	}

	logger.Info("Modular initialization completed successfully")
	return nil
}

// ensureAgentConfig checks if agent.json exists, creates it if not
func ensureAgentConfig(logger types.Logger, configPath string) error {
	logger.Info("Checking agent.json configuration...")

	if _, err := os.Stat(configPath); err == nil {
		logger.Info("agent.json already exists")
		return nil
	}

	logger.Info("agent.json not found, creating default configuration...")

	// Get bootstrap token for device ID extraction
	bootstrapToken := getBootstrapToken()
	if bootstrapToken == "" {
		return fmt.Errorf("bootstrap token is required to create agent.json. Usage: sudo ./streamdeploy-agent <token> or export SD_BOOTSTRAP_TOKEN=\"your-token\"")
	}

	// Extract device ID from JWT
	deviceID, err := extractDeviceIDFromJWT(bootstrapToken)
	if err != nil {
		return fmt.Errorf("failed to extract device_id from bootstrap token: %w", err)
	}

	// Detect system information
	osInfo, err := detectSystemInfo()
	if err != nil {
		return fmt.Errorf("failed to detect system information: %w", err)
	}

	// Create device config
	deviceConfig := DeviceConfig{
		DeviceID:           deviceID,
		EnrollBaseURL:      "https://api.streamdeploy.com",
		HTTPSMTLSEndpoint:  "https://device.streamdeploy.com",
		MQTTWSMTLSEndpoint: "https://mqtt.streamdeploy.com",
		PKIDir:             "/etc/streamdeploy/pki",
		OSName:             osInfo.OSName,
		OSVersion:          osInfo.OSVersion,
		Architecture:       osInfo.Architecture,
	}

	// Create config directory
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write config file
	if err := writeJSONFile(configPath, deviceConfig); err != nil {
		return fmt.Errorf("failed to write agent config: %w", err)
	}

	logger.Infof("Created agent.json with device ID: %s", deviceID)
	return nil
}

// ensureStateConfig checks if state.json exists, creates it if not
func ensureStateConfig(logger types.Logger) error {
	logger.Info("Checking state.json configuration...")

	stateConfigPath := "/etc/streamdeploy/state.json"
	if _, err := os.Stat(stateConfigPath); err == nil {
		logger.Info("state.json already exists")
		return nil
	}

	logger.Info("state.json not found, creating default configuration...")

	// Create state config with default values
	stateConfig := map[string]interface{}{
		"schemaVersion": "1.0",
		"agent_setting": map[string]string{
			"heartbeat_frequency": "15s",
			"update_frequency":    "30s",
			"mode":                "http",
			"agent_ver":           "1",
		},
		"containers":      []interface{}{},
		"containerLogin":  "",
		"env":             map[string]string{},
		"packages":        []string{"curl", "ca-certificates", "systemd", "docker.io"},
		"custom_metrics":  map[string]string{},
		"custom_packages": map[string]interface{}{},
	}

	// Create config directory
	if err := os.MkdirAll("/etc/streamdeploy", 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write state config file
	if err := writeJSONFile(stateConfigPath, stateConfig); err != nil {
		return fmt.Errorf("failed to write state config: %w", err)
	}

	logger.Info("Created state.json with default configuration")
	return nil
}

// ensureCertificates checks if certificates exist, runs cert flow if not
func ensureCertificates(logger types.Logger, configPath string) error {
	logger.Info("Checking certificates...")

	// Load device config to get PKI directory
	deviceConfig, err := loadDeviceConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load device config: %w", err)
	}

	pkiDir := deviceConfig.PKIDir
	if pkiDir == "" {
		pkiDir = "/etc/streamdeploy/pki"
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
	bootstrapToken := getBootstrapToken()
	if bootstrapToken == "" {
		return fmt.Errorf("bootstrap token is required for certificate enrollment")
	}

	// Run certificate enrollment using installer logic
	if err := performCertificateEnrollment(logger, deviceConfig, bootstrapToken); err != nil {
		return fmt.Errorf("certificate enrollment failed: %w", err)
	}

	logger.Info("Certificate enrollment completed successfully")
	return nil
}

// handleSystemdService manages systemd service (stop, remove, replace, launch, kill self)
func handleSystemdService(logger types.Logger, configPath string) error {
	logger.Info("Handling systemd service management...")

	// Check if systemctl is available
	if !commandExists("systemctl") {
		logger.Info("systemctl not available, skipping service management")
		return nil
	}

	// Check if we have root privileges
	if os.Geteuid() != 0 {
		logger.Info("Not running as root, skipping service management")
		return nil
	}

	// Check if we're already running under systemd (avoid recursive service management)
	invocationID := os.Getenv("INVOCATION_ID")
	notifySocket := os.Getenv("NOTIFY_SOCKET")
	logger.Infof("INVOCATION_ID: '%s', NOTIFY_SOCKET: '%s'", invocationID, notifySocket)

	// Check multiple indicators of systemd execution
	if invocationID != "" || notifySocket != "" {
		logger.Info("Already running under systemd service, skipping service management")
		return nil
	}

	// Get current executable path
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	expectedPath := "/usr/local/bin/streamdeploy-agent"

	// Step 1: Stop existing systemd service if running (we're running manually)
	if isServiceActive() {
		logger.Info("Stopping existing streamdeploy-agent systemd service...")
		if err := runSystemCommand("systemctl", "stop", "streamdeploy-agent"); err != nil {
			logger.Errorf("Failed to stop service: %v", err)
		}
	}

	// Step 2: Disable existing service if installed
	if isServiceInstalled() {
		logger.Info("Disabling existing streamdeploy-agent service...")
		if err := runSystemCommand("systemctl", "disable", "streamdeploy-agent"); err != nil {
			logger.Errorf("Failed to disable service: %v", err)
		}
	}

	// Step 3: Replace the streamdeploy file with own executable
	if currentBinary != expectedPath {
		logger.Infof("Copying binary from %s to %s", currentBinary, expectedPath)
		if err := copyBinaryToInstallDir(logger, currentBinary, expectedPath); err != nil {
			return fmt.Errorf("failed to copy binary to install directory: %w", err)
		}
	}

	// Step 4: Create and launch systemd service
	if err := createServiceFile(logger); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	if err := enableAndStartService(logger); err != nil {
		return fmt.Errorf("failed to enable and start service: %w", err)
	}

	// Step 5: Kill itself if we're not the installed binary (replace with systemd version)
	if currentBinary != expectedPath {
		logger.Info("Systemd service started successfully. Replacing manual process with systemd service...")

		// Wait a moment for service to start
		time.Sleep(2 * time.Second)

		// Verify service is running
		if !isServiceActive() {
			return fmt.Errorf("service failed to start properly")
		}

		logger.Info("Systemd service verified as running. Exiting manual process.")
		os.Exit(0)
	}

	return nil
}

// Helper functions for modular initialization

// getBootstrapToken gets bootstrap token from command line or environment
func getBootstrapToken() string {
	// Check command line argument (skip first arg which is the binary name)
	if len(os.Args) >= 2 && len(os.Args[1]) > 0 && !strings.HasPrefix(os.Args[1], "/") {
		return os.Args[1]
	}

	// Check environment variable
	return os.Getenv("SD_BOOTSTRAP_TOKEN")
}

// extractDeviceIDFromJWT extracts device ID from JWT token
func extractDeviceIDFromJWT(token string) (string, error) {
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

// SystemInfo holds system detection information
type SystemInfo struct {
	OSName       string
	OSVersion    string
	Architecture string
}

// detectSystemInfo detects system information
func detectSystemInfo() (*SystemInfo, error) {
	// Detect OS from /etc/os-release
	osInfo, err := parseOSRelease()
	if err != nil {
		return nil, fmt.Errorf("failed to parse /etc/os-release: %w", err)
	}

	// Detect architecture
	arch := detectArchitecture()

	return &SystemInfo{
		OSName:       osInfo["ID"],
		OSVersion:    osInfo["VERSION_ID"],
		Architecture: arch,
	}, nil
}

// parseOSRelease parses /etc/os-release file
func parseOSRelease() (map[string]string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return nil, err
	}

	osInfo := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := parts[0]
			value := strings.Trim(parts[1], "\"")
			osInfo[key] = value
		}
	}

	return osInfo, nil
}

// detectArchitecture detects system architecture
func detectArchitecture() string {
	// Use Go's runtime to detect architecture
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "arm":
		return detectARMVariant()
	case "riscv64":
		return "riscv64"
	default:
		return runtime.GOARCH
	}
}

// detectARMVariant detects ARM variant
func detectARMVariant() string {
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

// writeJSONFile writes data to JSON file
func writeJSONFile(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, jsonData, 0644)
}

// runSystemCommand runs a system command
func runSystemCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = "/"
	return cmd.Run()
}

// performCertificateEnrollment performs certificate enrollment
func performCertificateEnrollment(logger types.Logger, deviceConfig *DeviceConfig, bootstrapToken string) error {
	logger.Info("Starting certificate enrollment process...")

	// Create PKI directory
	if err := os.MkdirAll(deviceConfig.PKIDir, 0755); err != nil {
		return fmt.Errorf("failed to create PKI directory: %w", err)
	}

	// Use the installer package to perform certificate enrollment
	installerInstance := installer.New(logger)

	// Run the full installer which includes certificate enrollment
	// This will handle the complete certificate flow
	if err := installerInstance.Run(); err != nil {
		return fmt.Errorf("certificate enrollment failed: %w", err)
	}

	logger.Info("Certificate enrollment completed successfully")
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
		config.PKIDir = "/etc/streamdeploy/pki"
	}

	return &config, nil
}

// isServiceActive checks if our service is currently active in systemctl
func isServiceActive() bool {
	if !commandExists("systemctl") {
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

# systemd automatically sets INVOCATION_ID for service detection

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/streamdeploy /var/lib/streamdeploy /var/log

[Install]
WantedBy=multi-user.target
`

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
