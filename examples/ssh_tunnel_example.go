package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/agent"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/tunnel"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

func main() {
	// Initialize the core agent
	coreAgent, err := agent.NewCoreAgent("/etc/streamdeploy/agent.json")
	if err != nil {
		log.Fatalf("Failed to create core agent: %v", err)
	}

	// Create mock implementations for required components
	// In a real implementation, these would be proper implementations
	logger := &mockLogger{}
	configManager := &mockConfigManager{}
	httpClient := &mockHTTPClient{}
	mqttClient := &mockMQTTClient{}

	// Create SSH tunnel manager
	sshTunnelManager := tunnel.NewSSHTunnelManager(
		logger,
		configManager,
		httpClient,
		mqttClient,
	)

	// Set the SSH tunnel manager
	coreAgent.SetSSHTunnelManager(sshTunnelManager)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the agent in a goroutine
	go func() {
		if err := coreAgent.Start(); err != nil {
			log.Fatalf("Failed to start agent: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down...")
	coreAgent.Stop()
}

// Mock implementations for demonstration
type mockLogger struct{}

func (m *mockLogger) Info(msg string)                          { log.Printf("INFO: %s", msg) }
func (m *mockLogger) Infof(format string, args ...interface{}) { log.Printf("INFO: "+format, args...) }
func (m *mockLogger) Error(msg string)                         { log.Printf("ERROR: %s", msg) }
func (m *mockLogger) Errorf(format string, args ...interface{}) {
	log.Printf("ERROR: "+format, args...)
}
func (m *mockLogger) Debug(msg string) { log.Printf("DEBUG: %s", msg) }
func (m *mockLogger) Debugf(format string, args ...interface{}) {
	log.Printf("DEBUG: "+format, args...)
}

type mockConfigManager struct{}

func (m *mockConfigManager) GetDeviceConfig() *types.DeviceConfig {
	return &types.DeviceConfig{
		HTTPSMTLSEndpoint: "device.streamdeploy.com",
	}
}

func (m *mockConfigManager) GetStateConfig() *types.StateConfig {
	return &types.StateConfig{
		SchemaVersion: "1.0",
		AgentSetting: types.AgentSetting{
			HeartbeatFrequency: "15s",
			UpdateFrequency:    "30s",
			Mode:               "http",
			AgentVer:           "0.0",
			LoggingLevel:       "info",
		},
	}
}

func (m *mockConfigManager) UpdateStateConfig(config *types.StateConfig) error { return nil }
func (m *mockConfigManager) SaveStateConfig() error                            { return nil }
func (m *mockConfigManager) StartMonitoring() error                            { return nil }
func (m *mockConfigManager) StopMonitoring()                                   {}
func (m *mockConfigManager) SetConfigChangeCallback(callback func(string))     {}
func (m *mockConfigManager) GetMode() string                                   { return "http" }
func (m *mockConfigManager) GetDeviceID() string                               { return "mock-device-123" }
func (m *mockConfigManager) GetHeartbeatFrequency() time.Duration              { return 15 * time.Second }
func (m *mockConfigManager) GetUpdateFrequency() time.Duration                 { return 30 * time.Second }
func (m *mockConfigManager) ReloadStateConfig() error                          { return nil }
func (m *mockConfigManager) GetDeviceConfigPath() string                       { return "/etc/streamdeploy/agent.json" }
func (m *mockConfigManager) RestartMonitoring()                                {}

type mockHTTPClient struct{}

func (m *mockHTTPClient) SendHeartbeat(payload *types.HeartbeatPayload, deviceID string) (*types.HTTPResponse, error) {
	return &types.HTTPResponse{StatusCode: 200, Body: []byte(`{"status": "ok"}`)}, nil
}

func (m *mockHTTPClient) SendStatusUpdate(payload *types.StatusUpdatePayload, deviceID string) (*types.HTTPResponse, error) {
	return &types.HTTPResponse{StatusCode: 200, Body: []byte(`{"status": "ok"}`)}, nil
}

func (m *mockHTTPClient) Post(url string, data []byte, headers map[string]string) (*types.HTTPResponse, error) {
	return &types.HTTPResponse{StatusCode: 200, Body: []byte(`{"status": "ok"}`)}, nil
}

func (m *mockHTTPClient) Get(url string, headers map[string]string) (*types.HTTPResponse, error) {
	return &types.HTTPResponse{StatusCode: 200, Body: []byte(`{"status": "ok"}`)}, nil
}

type mockMQTTClient struct{}

func (m *mockMQTTClient) Connect() error                                               { return nil }
func (m *mockMQTTClient) Disconnect()                                                  {}
func (m *mockMQTTClient) IsConnected() bool                                            { return true }
func (m *mockMQTTClient) PublishHeartbeat(payload *types.HeartbeatPayload) error       { return nil }
func (m *mockMQTTClient) PublishStatusUpdate(payload *types.StatusUpdatePayload) error { return nil }
func (m *mockMQTTClient) Subscribe(topic string, callback func([]byte)) error          { return nil }

// Example of how the tmp command would be processed:
// When the agent receives a status update with:
// {
//   "new_state": {
//     "tmp": "custom ssh user_456 2024-01-01T12:00:00Z",
//     "schemaVersion": "1.0",
//     "agent_setting": { ... },
//     "containers": [ ... ],
//     "env": { ... },
//     "packages": [ ... ],
//     "custom_metrics": { ... },
//     "custom_packages": { ... }
//   }
// }
//
// The agent will:
// 1. Parse the command and extract user and expiration
// 2. Start an SSH tunnel for user_456 that expires at 2024-01-01T12:00:00Z
// 3. Connect to wss://device.streamdeploy.com/v1-device/tunnel
// 4. Handle tunnel messages for SSH forwarding
// 5. Remove the "tmp" key from the response before saving state
