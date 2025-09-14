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
	deviceConfigPath  string
	stateConfigPath   string
	deviceConfig      *types.DeviceConfig
	stateConfig       *types.StateConfig
	changeCallback    func(string)
	monitoring        bool
	stopMonitoring    chan bool
	restartMonitoring chan bool
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

// GetDeviceConfigPath returns the device configuration file path
func (m *Manager) GetDeviceConfigPath() string {
	return m.deviceConfigPath
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
	if m.monitoring {
		return nil // Already monitoring
	}

	m.monitoring = true
	m.stopMonitoring = make(chan bool)
	m.restartMonitoring = make(chan bool)

	// Start monitoring goroutine with polling
	go m.monitorFiles()

	return nil
}

// StopMonitoring stops monitoring configuration files
func (m *Manager) StopMonitoring() {
	if !m.monitoring || m.stopMonitoring == nil {
		return
	}

	m.monitoring = false
	close(m.stopMonitoring)
	m.stopMonitoring = nil
	if m.restartMonitoring != nil {
		close(m.restartMonitoring)
		m.restartMonitoring = nil
	}
}

// SetConfigChangeCallback sets the callback for configuration changes
func (m *Manager) SetConfigChangeCallback(callback func(string)) {
	m.changeCallback = callback
}

// RestartMonitoring restarts the file monitoring with the current update frequency
func (m *Manager) RestartMonitoring() {
	if m.monitoring && m.restartMonitoring != nil {
		select {
		case m.restartMonitoring <- true:
			// Signal sent successfully
		default:
			// Channel is full or closed, ignore
		}
	}
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

// ReloadStateConfig reloads the state configuration from file
func (m *Manager) ReloadStateConfig() error {
	return m.loadStateConfig()
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

// ParseFrequency parses a frequency string (e.g., "15s", "1m", "1h", "1m30s", "2m 3s") into seconds
func ParseFrequency(freq string) int {
	if freq == "" {
		return 15 // default 15 seconds
	}

	freq = strings.TrimSpace(freq)
	if len(freq) < 2 {
		return 15
	}

	totalSeconds := 0

	// Parse compound frequency strings like "1m30s" or "2m 3s"
	// Split by spaces first, then parse each part
	parts := strings.Fields(freq)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) < 2 {
			continue
		}

		// Find the unit (last character)
		unit := part[len(part)-1]
		valueStr := part[:len(part)-1]

		// Parse the numeric value
		value := 0
		for _, r := range valueStr {
			if r >= '0' && r <= '9' {
				value = value*10 + int(r-'0')
			} else {
				// Invalid format, skip this part
				value = 0
				break
			}
		}

		// Convert to seconds based on unit
		switch unit {
		case 's':
			totalSeconds += value
		case 'm':
			totalSeconds += value * 60
		case 'h':
			totalSeconds += value * 3600
		case 'd':
			totalSeconds += value * 86400
		case 'w':
			totalSeconds += value * 604800
		case 'M':
			totalSeconds += value * 2592000 // 30 days
		case 'y':
			totalSeconds += value * 31536000 // 365 days
		default:
			// Invalid unit, skip this part
			continue
		}
	}

	// If no valid parts were parsed, return default
	if totalSeconds == 0 {
		return 15
	}

	return totalSeconds
}

// ParseFrequencyToDuration parses a frequency string into time.Duration
func ParseFrequencyToDuration(freq string) time.Duration {
	if freq == "" {
		return 15 * time.Second // default 15 seconds
	}

	freq = strings.TrimSpace(freq)
	if len(freq) < 2 {
		return 15 * time.Second
	}

	totalDuration := time.Duration(0)

	// Parse compound frequency strings like "1m30s" or "2m 3s"
	// Split by spaces first, then parse each part
	parts := strings.Fields(freq)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) < 2 {
			continue
		}

		// Find the unit (last character)
		unit := part[len(part)-1]
		valueStr := part[:len(part)-1]

		// Parse the numeric value
		value := 0
		for _, r := range valueStr {
			if r >= '0' && r <= '9' {
				value = value*10 + int(r-'0')
			} else {
				// Invalid format, skip this part
				value = 0
				break
			}
		}

		// Convert to duration based on unit
		switch unit {
		case 's':
			totalDuration += time.Duration(value) * time.Second
		case 'm':
			totalDuration += time.Duration(value) * time.Minute
		case 'h':
			totalDuration += time.Duration(value) * time.Hour
		case 'd':
			totalDuration += time.Duration(value) * 24 * time.Hour
		case 'w':
			totalDuration += time.Duration(value) * 7 * 24 * time.Hour
		case 'M':
			totalDuration += time.Duration(value) * 30 * 24 * time.Hour // 30 days
		case 'y':
			totalDuration += time.Duration(value) * 365 * 24 * time.Hour // 365 days
		default:
			// Invalid unit, skip this part
			continue
		}
	}

	// If no valid parts were parsed, return default
	if totalDuration == 0 {
		return 15 * time.Second
	}

	return totalDuration
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

// monitorFiles monitors configuration files for changes using polling
func (m *Manager) monitorFiles() {
	var ticker *time.Ticker

	// Initialize with current update frequency
	pollInterval := m.GetUpdateFrequency()
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second // Default fallback
	}

	ticker = time.NewTicker(pollInterval)
	defer ticker.Stop()

	// Track file modification times
	deviceConfigModTime := m.getFileModTime(m.deviceConfigPath)
	stateConfigModTime := m.getFileModTime(m.stateConfigPath)

	for {
		select {
		case <-ticker.C:
			// Check device config
			if newModTime := m.getFileModTime(m.deviceConfigPath); newModTime.After(deviceConfigModTime) {
				deviceConfigModTime = newModTime
				m.handleDeviceConfigChange()
			}

			// Check state config
			if newModTime := m.getFileModTime(m.stateConfigPath); newModTime.After(stateConfigModTime) {
				stateConfigModTime = newModTime
				m.handleStateConfigChange()
			}

		case <-m.restartMonitoring:
			// Restart with new interval
			ticker.Stop()
			newInterval := m.GetUpdateFrequency()
			if newInterval <= 0 {
				newInterval = 30 * time.Second // Default fallback
			}
			ticker = time.NewTicker(newInterval)

		case <-m.stopMonitoring:
			return
		}
	}
}

// getFileModTime gets the modification time of a file
func (m *Manager) getFileModTime(filePath string) time.Time {
	info, err := os.Stat(filePath)
	if err != nil {
		return time.Time{} // Return zero time if file doesn't exist or can't be read
	}
	return info.ModTime()
}

// handleDeviceConfigChange handles device configuration file changes
func (m *Manager) handleDeviceConfigChange() {
	// Reload device config
	if err := m.loadDeviceConfig(); err != nil {
		fmt.Printf("Failed to reload device config: %v\n", err)
		// Notify callback with error so agent can handle it
		if m.changeCallback != nil {
			m.changeCallback(m.deviceConfigPath + ":error")
		}
		return
	}

	// Notify callback
	if m.changeCallback != nil {
		m.changeCallback(m.deviceConfigPath)
	}
}

// handleStateConfigChange handles state configuration file changes
func (m *Manager) handleStateConfigChange() {
	// Reload state config
	if err := m.loadStateConfig(); err != nil {
		fmt.Printf("Failed to reload state config: %v\n", err)
		// Notify callback with error so agent can handle it
		if m.changeCallback != nil {
			m.changeCallback(m.stateConfigPath + ":error")
		}
		return
	}

	// Notify callback
	if m.changeCallback != nil {
		m.changeCallback(m.stateConfigPath)
	}
}
