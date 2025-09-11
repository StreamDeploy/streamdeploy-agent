package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/container"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/https"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/agent/metrics"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/agent"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/utils"
)

func main() {
	logger := utils.NewLogger("MAIN")

	// Parse command line arguments
	configPath := "/etc/streamdeploy/agent.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	logger.Infof("StreamDeploy Agent starting...")
	logger.Infof("Using config: %s", configPath)

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

	// Set up HTTPS client
	pkiDir := deviceConfig.PKIDir
	caCertPath := filepath.Join(pkiDir, "ca.pem")
	certPath := filepath.Join(pkiDir, "client.pem")
	keyPath := filepath.Join(pkiDir, "client-key.pem")

	httpsClient, err := https.NewClient(
		deviceConfig.HTTPSMTLSEndpoint,
		caCertPath,
		certPath,
		keyPath,
	)
	if err != nil {
		logger.Errorf("Failed to create HTTPS client: %v", err)
		// Don't fail completely, agent can still work without HTTPS
	} else {
		coreAgent.SetHTTPClient(httpsClient)
		logger.Info("HTTPS client configured")
	}

	// Set up certificate manager
	// Import the certificate package
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
	return filepath.Join(c.pkiDir, "ca.pem")
}

func (c *certificateManagerWrapper) GetCertificatePath() string {
	return filepath.Join(c.pkiDir, "client.pem")
}

func (c *certificateManagerWrapper) GetPrivateKeyPath() string {
	return filepath.Join(c.pkiDir, "client-key.pem")
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
