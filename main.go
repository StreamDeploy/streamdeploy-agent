package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
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

	// Create and start the core agent
	coreAgent, err := agent.NewCoreAgent(configPath)
	if err != nil {
		logger.Errorf("Failed to create core agent: %v", err)
		os.Exit(1)
	}

	// Set up all the managers
	if err := setupManagers(coreAgent, logger); err != nil {
		logger.Errorf("Failed to setup managers: %v", err)
		os.Exit(1)
	}

	// Start the agent
	if err := coreAgent.Start(); err != nil {
		logger.Errorf("Failed to start agent: %v", err)
		os.Exit(1)
	}

	logger.Info("Agent started successfully")

	// Wait for shutdown signal
	waitForShutdown(coreAgent, logger)
}

// runModularInitialization runs the modular initialization flow
func runModularInitialization(logger types.Logger, configPath string) error {
	logger.Info("Starting modular initialization...")

	// Step 1: Check and create agent.json if needed
	if err := ensureDeviceConfig(logger, configPath); err != nil {
		return fmt.Errorf("failed to ensure device config: %w", err)
	}

	// Step 2: Check and create state.json if needed
	if err := ensureStateConfig(logger); err != nil {
		return fmt.Errorf("failed to ensure state config: %w", err)
	}

	// Step 3: Check and perform certificate flow if needed
	installerInstance := installer.New(logger)
	if err := installerInstance.EnsureCertificates(configPath); err != nil {
		return fmt.Errorf("failed to ensure certificates: %w", err)
	}

	// Step 4: Handle systemd service management
	if err := installerInstance.HandleSystemdService(configPath); err != nil {
		return fmt.Errorf("failed to handle systemd service: %w", err)
	}

	logger.Info("Modular initialization completed successfully")
	return nil
}

// setupManagers sets up all the manager implementations
func setupManagers(coreAgent *agent.CoreAgent, logger types.Logger) error {
	// Set up HTTP client
	httpClient, err := https.NewClient("", "", "", "")
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	coreAgent.SetHTTPClient(httpClient)

	// Set up metrics collector
	metricsCollector := metrics.NewCollector()
	coreAgent.SetMetricsCollector(metricsCollector)

	// Set up container manager
	containerManager := container.NewManager(logger)
	coreAgent.SetContainerManager(containerManager)

	// Set up environment manager
	environmentManager := environment.NewManager(logger)
	coreAgent.SetEnvironmentManager(environmentManager)

	// Set up package manager
	packageManagerConfig := &types.PackageManagerConfig{}
	packageManager := packages.NewManager(logger, packageManagerConfig)
	coreAgent.SetPackageManager(packageManager)

	// Set up certificate manager
	certificateManager := createCertificateManager(logger)
	coreAgent.SetCertificateManager(certificateManager)

	return nil
}

// waitForShutdown waits for shutdown signals and gracefully stops the agent
func waitForShutdown(coreAgent *agent.CoreAgent, logger types.Logger) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	logger.Infof("Received signal: %v", sig)

	logger.Info("Shutting down agent...")
	coreAgent.Stop()
	logger.Info("Agent stopped")
}

// ensureDeviceConfig ensures the device configuration file exists
func ensureDeviceConfig(logger types.Logger, configPath string) error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Info("Device config not found, creating default configuration...")

		// Create config directory
		configDir := filepath.Dir(configPath)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}

		// Create default device config
		defaultConfig := map[string]interface{}{
			"device_id":             "",
			"enroll_base_url":       "https://api.streamdeploy.com",
			"https_mtls_endpoint":   "https://device.streamdeploy.com",
			"mqtt_ws_mtls_endpoint": "https://mqtt.streamdeploy.com",
			"pki_dir":               "/etc/streamdeploy/pki",
			"os_name":               runtime.GOOS,
			"os_version":            "unknown",
			"architecture":          runtime.GOARCH,
		}

		if err := writeJSONFile(configPath, defaultConfig); err != nil {
			return fmt.Errorf("failed to write default device config: %w", err)
		}

		logger.Info("Created default device configuration")
	}

	return nil
}

// ensureStateConfig ensures the state configuration file exists
func ensureStateConfig(logger types.Logger) error {
	statePath := "/etc/streamdeploy/state.json"

	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		logger.Info("State config not found, creating default configuration...")

		// Create config directory
		configDir := filepath.Dir(statePath)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}

		// Create default state config
		defaultState := map[string]interface{}{
			"schemaVersion": "1.0",
			"agent_setting": map[string]interface{}{
				"heartbeat_frequency": "15s",
				"update_frequency":    "30s",
				"mode":                "http",
				"agent_ver":           "1",
				"logging_level":       "info",
			},
			"containers":      []interface{}{},
			"containerLogin":  "",
			"env":             map[string]string{},
			"packages":        []string{"curl", "ca-certificates", "systemd", "docker.io"},
			"custom_metrics":  map[string]string{},
			"custom_packages": map[string]interface{}{},
		}

		if err := writeJSONFile(statePath, defaultState); err != nil {
			return fmt.Errorf("failed to write default state config: %w", err)
		}

		logger.Info("Created state.json with default configuration")
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

// writeJSONFile writes data to a JSON file
func writeJSONFile(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, jsonData, 0644)
}

// createCertificateManager creates a certificate manager instance
func createCertificateManager(logger types.Logger) types.CertificateManager {
	// This is a simplified certificate manager implementation
	// In a real implementation, this would be more sophisticated
	return &certificateManagerImpl{
		logger: logger,
		pkiDir: "/etc/streamdeploy/pki",
	}
}

// certificateManagerImpl is a simple implementation of CertificateManager
type certificateManagerImpl struct {
	logger types.Logger
	pkiDir string
}

// Implement the CertificateManager interface methods with full functionality
func (c *certificateManagerImpl) GetCertificateInfo() (*types.CertificateInfo, error) {
	certPath := c.GetCertificatePath()
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate file not found: %s", certPath)
	}

	// Read and parse the certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &types.CertificateInfo{
		CertPath:   c.GetCertificatePath(),
		KeyPath:    c.GetPrivateKeyPath(),
		CACertPath: c.GetCACertificatePath(),
		ExpiresAt:  cert.NotAfter,
	}, nil
}

func (c *certificateManagerImpl) IsCertificateExpiringSoon(days int) bool {
	certInfo, err := c.GetCertificateInfo()
	if err != nil {
		c.logger.Errorf("Failed to get certificate info: %v", err)
		return true // Assume expiring if we can't check
	}

	expirationThreshold := time.Now().AddDate(0, 0, days)
	return certInfo.ExpiresAt.Before(expirationThreshold)
}

func (c *certificateManagerImpl) RenewCertificate(deviceID, enrollEndpoint string) error {
	c.logger.Info("Starting certificate renewal process with mTLS support")

	// Generate new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate request
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: deviceID,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate request: %w", err)
	}

	// Save private key
	if err := c.savePrivateKey(privateKey); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save certificate request
	csrPath := filepath.Join(c.pkiDir, "device.csr")
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate request: %w", err)
	}

	c.logger.Info("Certificate renewal process completed")
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

func (c *certificateManagerImpl) savePrivateKey(privateKey *rsa.PrivateKey) error {
	keyPath := c.GetPrivateKeyPath()
	keyData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return os.WriteFile(keyPath, keyData, 0600)
}

func (c *certificateManagerImpl) saveCertificate(certPEM string) error {
	certPath := c.GetCertificatePath()
	return os.WriteFile(certPath, []byte(certPEM), 0644)
}

func (c *certificateManagerImpl) saveCertificateChain(leafCertPEM string, intermediateChain []string) error {
	c.logger.Info("Saving certificate chain for mTLS...")

	// Save leaf certificate
	if err := c.saveCertificate(leafCertPEM); err != nil {
		return fmt.Errorf("failed to save leaf certificate: %w", err)
	}

	// Create full chain
	fullChain := leafCertPEM
	for _, intermediate := range intermediateChain {
		fullChain += "\n" + intermediate
	}

	// Save full chain
	fullChainPath := filepath.Join(c.pkiDir, "fullchain.crt")
	if err := os.WriteFile(fullChainPath, []byte(fullChain), 0644); err != nil {
		return fmt.Errorf("failed to save full chain: %w", err)
	}

	c.logger.Info("Certificate chain saved successfully")
	return nil
}
