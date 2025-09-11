package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Manager implements the ConfigManager
type Manager struct {
	deviceConfigPath string
	stateConfigPath  string
	deviceConfig     *types.DeviceConfig
	stateConfig      *types.StateConfig
	changeCallback   func(string)
}

// NewManager creates a new configuration manager
func NewManager(deviceConfigPath string) (*Manager, error) {
	m := &Manager{
		deviceConfigPath: deviceConfigPath,
		stateConfigPath:  getStateConfigPath(deviceConfigPath),
	}

	if err := m.loadDeviceConfig(); err != nil {
		return nil, fmt.Errorf("failed to load device config: %w", err)
	}

	if err := m.loadStateConfig(); err != nil {
		return nil, fmt.Errorf("failed to load state config: %w", err)
	}

	return m, nil
}

// GetDeviceConfig returns the device configuration
func (m *Manager) GetDeviceConfig() *types.DeviceConfig {
	return m.deviceConfig
}

// GetStateConfig returns the state configuration
func (m *Manager) GetStateConfig() *types.StateConfig {
	return m.stateConfig
}

// UpdateStateConfig updates the state configuration
func (m *Manager) UpdateStateConfig(config *types.StateConfig) error {
	m.stateConfig = config
	return m.SaveStateConfig()
}

// SaveStateConfig saves the state configuration to disk
func (m *Manager) SaveStateConfig() error {
	data, err := json.MarshalIndent(m.stateConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state config: %w", err)
	}

	if err := os.WriteFile(m.stateConfigPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write state config: %w", err)
	}

	return nil
}

// StartMonitoring starts monitoring configuration files for changes
func (m *Manager) StartMonitoring() error {
	// TODO: Implement file system monitoring
	return nil
}

// StopMonitoring stops monitoring configuration files
func (m *Manager) StopMonitoring() {

}

// SetConfigChangeCallback sets the callback for configuration changes
func (m *Manager) SetConfigChangeCallback(callback func(string)) {
	m.changeCallback = callback
}

// GetDeviceID returns the device ID
func (m *Manager) GetDeviceID() string {
	if m.deviceConfig == nil {
		return ""
	}
	return m.deviceConfig.DeviceID
}

// GetMode returns the communication mode (http or mqtt)
func (m *Manager) GetMode() string {
	if m.stateConfig == nil {
		return "http"
	}
	return m.stateConfig.AgentSetting.Mode
}

// GetHeartbeatFrequency returns the heartbeat frequency
func (m *Manager) GetHeartbeatFrequency() time.Duration {
	if m.stateConfig == nil {
		return 15 * time.Second
	}
	return ParseFrequencyToDuration(m.stateConfig.AgentSetting.HeartbeatFrequency)
}

// GetUpdateFrequency returns the update frequency
func (m *Manager) GetUpdateFrequency() time.Duration {
	if m.stateConfig == nil {
		return 30 * time.Second
	}
	return ParseFrequencyToDuration(m.stateConfig.AgentSetting.UpdateFrequency)
}

// GetPKIDir returns the PKI directory path
func (m *Manager) GetPKIDir() string {
	if m.deviceConfig == nil {
		return "/etc/streamdeploy/pki"
	}
	return m.deviceConfig.PKIDir
}

// GetHTTPSEndpoint returns the HTTPS endpoint
func (m *Manager) GetHTTPSEndpoint() string {
	if m.deviceConfig == nil {
		return ""
	}
	return m.deviceConfig.HTTPSMTLSEndpoint
}

// GetMQTTEndpoint returns the MQTT endpoint
func (m *Manager) GetMQTTEndpoint() string {
	if m.deviceConfig == nil {
		return ""
	}
	return m.deviceConfig.MQTTWSMTLSEndpoint
}

// loadDeviceConfig loads the device configuration from file
func (m *Manager) loadDeviceConfig() error {
	data, err := os.ReadFile(m.deviceConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read device config file: %w", err)
	}

	var config types.DeviceConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse device config: %w", err)
	}

	m.deviceConfig = &config
	return nil
}

// loadStateConfig loads the state configuration from file
func (m *Manager) loadStateConfig() error {
	data, err := os.ReadFile(m.stateConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read state config file: %w", err)
	}

	var config types.StateConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse state config: %w", err)
	}

	m.stateConfig = &config
	return nil
}

// getStateConfigPath derives the state config path from device config path
func getStateConfigPath(deviceConfigPath string) string {
	dir := filepath.Dir(deviceConfigPath)
	return filepath.Join(dir, "state.json")
}

// ParseFrequency parses a frequency string (e.g., "15s", "1m", "1h") into seconds
func ParseFrequency(freq string) int {
	if freq == "" {
		return 15 // default 15 seconds
	}

	// Simple parser
	freq = strings.TrimSpace(freq)
	if len(freq) < 2 {
		return 15
	}

	unit := freq[len(freq)-1]
	valueStr := freq[:len(freq)-1]

	// Simple integer parsing
	value := 0
	for _, r := range valueStr {
		if r >= '0' && r <= '9' {
			value = value*10 + int(r-'0')
		} else {
			return 15 // invalid format, return default
		}
	}

	switch unit {
	case 's':
		return value
	case 'm':
		return value * 60
	case 'h':
		return value * 3600
	case 'd':
		return value * 86400
	case 'w':
		return value * 604800
	case 'M':
		return value * 2592000 // 30 days
	case 'y':
		return value * 31536000 // 365 days
	default:
		return 15
	}
}

// ParseFrequencyToDuration parses a frequency string into time.Duration
func ParseFrequencyToDuration(freq string) time.Duration {
	if freq == "" {
		return 15 * time.Second // default 15 seconds
	}

	// Simple parser
	freq = strings.TrimSpace(freq)
	if len(freq) < 2 {
		return 15 * time.Second
	}

	unit := freq[len(freq)-1]
	valueStr := freq[:len(freq)-1]

	// Simple integer parsing
	value := 0
	for _, r := range valueStr {
		if r >= '0' && r <= '9' {
			value = value*10 + int(r-'0')
		} else {
			return 15 * time.Second // invalid format, return default
		}
	}

	switch unit {
	case 's':
		return time.Duration(value) * time.Second
	case 'm':
		return time.Duration(value) * time.Minute
	case 'h':
		return time.Duration(value) * time.Hour
	case 'd':
		return time.Duration(value) * 24 * time.Hour
	case 'w':
		return time.Duration(value) * 7 * 24 * time.Hour
	case 'M':
		return time.Duration(value) * 30 * 24 * time.Hour // 30 days
	case 'y':
		return time.Duration(value) * 365 * 24 * time.Hour // 365 days
	default:
		return 15 * time.Second
	}
}

// ValidateDeviceConfig validates the device configuration
func ValidateDeviceConfig(config *types.DeviceConfig) error {
	if config.DeviceID == "" {
		return fmt.Errorf("device_id is required")
	}
	if config.EnrollBaseURL == "" {
		return fmt.Errorf("enroll_base_url is required")
	}
	if config.HTTPSMTLSEndpoint == "" && config.MQTTWSMTLSEndpoint == "" {
		return fmt.Errorf("at least one endpoint (https_mtls_endpoint or mqtt_ws_mtls_endpoint) is required")
	}
	if config.PKIDir == "" {
		return fmt.Errorf("pki_dir is required")
	}
	return nil
}

// ValidateStateConfig validates the state configuration
func ValidateStateConfig(config *types.StateConfig) error {
	if config.SchemaVersion == "" {
		return fmt.Errorf("schemaVersion is required")
	}

	mode := config.AgentSetting.Mode
	if mode != "http" && mode != "mqtt" {
		return fmt.Errorf("mode must be 'http' or 'mqtt'")
	}

	// Validate frequency formats
	if ParseFrequency(config.AgentSetting.HeartbeatFrequency) <= 0 {
		return fmt.Errorf("invalid heartbeat_frequency format")
	}
	if ParseFrequency(config.AgentSetting.UpdateFrequency) <= 0 {
		return fmt.Errorf("invalid update_frequency format")
	}

	return nil
}
