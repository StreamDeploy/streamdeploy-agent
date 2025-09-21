package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// AgentInterface defines the interface that the agent must implement for config change handling
type AgentInterface interface {
	// Logger access
	GetLogger() types.Logger

	// State management
	GetDesiredState() *types.StateConfig
	SetDesiredState(state *types.StateConfig)
	GetCurrentSystemState() *types.StateConfig
	SetCurrentSystemState(state *types.StateConfig)

	// Manager access
	GetHeartbeatManager() interface{}
	GetStatusUpdateManager() interface{}
	GetContainerManager() types.ContainerManager
	GetSystemPackageManager() types.SystemPackageManager
	GetCustomPackageManager() types.CustomPackageManager
	GetEnvironmentManager() types.EnvironmentManager

	// System operations
	IsUpdating() bool
	SyncSystemToDesiredState(triggeredBy string) (bool, error)
	LogStateDiff(oldState, newState *types.StateConfig)
	WaitForUpdateAndApplyStateChange()

	// Utility functions
	CloneStateConfig(state *types.StateConfig) *types.StateConfig
}

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
	updatingState     bool // Flag to prevent circular updates
	updatingMutex     sync.Mutex
	agent             AgentInterface // Reference to agent for config change handling
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
	m.updatingMutex.Lock()
	m.updatingState = true
	m.updatingMutex.Unlock()

	// Check if this is an empty state (backend returned {} meaning no change)
	if isStateConfigEmpty(config) {
		// Don't save empty states to avoid triggering file monitoring
		m.updatingMutex.Lock()
		m.updatingState = false
		m.updatingMutex.Unlock()
		return nil
	}

	// Ensure mode is never empty
	if config.AgentSetting.Mode == "" {
		config.AgentSetting.Mode = "http"
	}

	m.stateConfig = config
	err := m.SaveStateConfig()

	m.updatingMutex.Lock()
	m.updatingState = false
	m.updatingMutex.Unlock()

	return err
}

// IsStateConfigEmpty checks if a state configuration is empty (no meaningful content)
func (m *Manager) IsStateConfigEmpty(config *types.StateConfig) bool {
	return isStateConfigEmpty(config)
}

// isStateConfigEmpty checks if a state configuration is empty (no meaningful content)
func isStateConfigEmpty(config *types.StateConfig) bool {
	if config == nil {
		return true
	}

	// Check if all fields are empty or default
	return config.SchemaVersion == "" &&
		config.AgentSetting.HeartbeatFrequency == "" &&
		config.AgentSetting.UpdateFrequency == "" &&
		config.AgentSetting.Mode == "" &&
		config.AgentSetting.AgentVer == "" &&
		config.AgentSetting.LoggingLevel == "" &&
		len(config.Containers) == 0 &&
		len(config.Env) == 0 &&
		len(config.Packages) == 0 &&
		len(config.CustomMetrics) == 0 &&
		len(config.CustomPackages) == 0
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
	mode := m.stateConfig.AgentSetting.Mode
	if mode == "" {
		return "http"
	}
	return mode
}

// GetHeartbeatFrequency returns the heartbeat frequency
func (m *Manager) GetHeartbeatFrequency() time.Duration {
	if m.stateConfig == nil {
		return 15 * time.Second
	}
	return ParseFrequencyToDuration(m.stateConfig.AgentSetting.HeartbeatFrequency)
}

// GetStatusFrequency returns the status update frequency
func (m *Manager) GetStatusFrequency() time.Duration {
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

	// Set defaults
	if config.AgentSetting.LoggingLevel == "" {
		config.AgentSetting.LoggingLevel = "info"
	}
	if config.AgentSetting.Mode == "" {
		config.AgentSetting.Mode = "http"
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
	pollInterval := m.GetStatusFrequency()
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

			// Check state config (only if not currently updating)
			if newModTime := m.getFileModTime(m.stateConfigPath); newModTime.After(stateConfigModTime) {
				m.updatingMutex.Lock()
				isUpdating := m.updatingState
				m.updatingMutex.Unlock()

				if !isUpdating {
					stateConfigModTime = newModTime
					m.handleStateConfigChange()
				}
			}

		case <-m.restartMonitoring:
			// Restart with new interval
			ticker.Stop()
			newInterval := m.GetStatusFrequency()
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

// SetAgent sets the agent interface for config change handling
func (m *Manager) SetAgent(agent interface{}) {
	if agentInterface, ok := agent.(AgentInterface); ok {
		m.agent = agentInterface
	}
}

// HandleConfigChange handles configuration file changes
func (m *Manager) HandleConfigChange(filePath string) {
	if m.agent == nil {
		return
	}

	m.agent.GetLogger().Infof("Configuration changed: %s", filePath)

	// Check if this is an error case
	isError := strings.HasSuffix(filePath, ":error")
	if isError {
		// Remove the error suffix to get the actual file path
		filePath = strings.TrimSuffix(filePath, ":error")
	}

	// Determine which config file changed
	if strings.HasSuffix(filePath, "agent.json") {
		m.HandleDeviceConfigChange(isError)
	} else if strings.HasSuffix(filePath, "state.json") {
		m.HandleStateConfigChange(isError)
	}

	m.agent.GetLogger().Info("Configuration reloaded successfully")
}

// HandleDeviceConfigChange handles device configuration changes
func (m *Manager) HandleDeviceConfigChange(isError bool) {
	if m.agent == nil {
		return
	}

	if isError {
		m.agent.GetLogger().Errorf("Failed to parse agent.json, resetting with default configuration from memory...")
		// Reset agent.json with default configuration
		if err := m.ResetAgentConfigToDefault(); err != nil {
			m.agent.GetLogger().Errorf("Failed to reset agent.json: %v", err)
		} else {
			m.agent.GetLogger().Info("agent.json reset to default configuration successfully")
		}
		return
	}

	m.agent.GetLogger().Info("Device configuration changed, updating timing intervals...")

	// Reinitialize heartbeat manager if heartbeat interval changed
	if heartbeatManager := m.agent.GetHeartbeatManager(); heartbeatManager != nil {
		m.agent.GetLogger().Infof("Heartbeat frequency changed, reinitializing heartbeat manager")
		// Note: The agent would need to implement a Stop method for heartbeat manager
		// and reinitialize it. This is a placeholder for now.
	}

	// Reinitialize status update manager if status update interval changed
	if statusUpdateManager := m.agent.GetStatusUpdateManager(); statusUpdateManager != nil {
		m.agent.GetLogger().Infof("Status update frequency changed, reinitializing status update manager")
		// Note: The agent would need to implement a Stop method for status update manager
		// and reinitialize it. This is a placeholder for now.
	}

	m.agent.GetLogger().Info("Device configuration updated successfully")
}

// HandleStateConfigChange handles state configuration changes
func (m *Manager) HandleStateConfigChange(isError bool) {
	if m.agent == nil {
		return
	}

	if isError {
		m.agent.GetLogger().Errorf("Failed to parse state.json, saving memory state back to file...")
		// Save current in-memory state back to state.json
		if err := m.SaveStateConfig(); err != nil {
			m.agent.GetLogger().Errorf("Failed to save state config back to file: %v", err)
		} else {
			m.agent.GetLogger().Info("Memory state saved back to state.json successfully")
		}
		return
	}

	// Check if agent is currently updating
	if m.agent.IsUpdating() {
		m.agent.GetLogger().Info("Agent is currently updating, waiting for update to complete before applying file changes...")
		// Wait for update to complete
		go m.agent.WaitForUpdateAndApplyStateChange()
		return
	}

	m.agent.GetLogger().Info("State.json file changed, treating as update...")

	// Refresh desired state from config manager (file was already reloaded)
	m.agent.SetDesiredState(m.GetStateConfig())

	// Validate: Get the new state from our internal field
	deviceDesiredState := m.agent.GetDesiredState()
	if deviceDesiredState == nil {
		m.agent.GetLogger().Errorf("Failed to get new state configuration from state.json")
		return
	}

	// Update heartbeat manager with new desired state
	if heartbeatManager := m.agent.GetHeartbeatManager(); heartbeatManager != nil {
		// Note: The agent would need to implement a SetDesiredState method for heartbeat manager
		// This is a placeholder for now.
	}

	m.agent.GetLogger().Info("State.json validated successfully, processing update...")

	// Detect: Get actual system state
	actualSystemState := m.detectCurrentState(deviceDesiredState)
	m.agent.SetCurrentSystemState(m.agent.CloneStateConfig(actualSystemState))

	// If logging level is debug, print diff between current system state and desired state
	if strings.ToLower(deviceDesiredState.AgentSetting.LoggingLevel) == "debug" {
		m.agent.LogStateDiff(actualSystemState, deviceDesiredState)
	}

	// Sync: Compare currentSystemState vs deviceDesiredState and apply changes
	_, err := m.agent.SyncSystemToDesiredState("file")
	if err != nil {
		m.agent.GetLogger().Errorf("Failed to sync system to desired state: %v", err)
		return
	}

	m.agent.GetLogger().Info("File-based state update completed successfully")
}

// ResetAgentConfigToDefault resets agent.json with the current device configuration from memory
func (m *Manager) ResetAgentConfigToDefault() error {
	// Get the current device configuration from memory
	deviceConfig := m.GetDeviceConfig()
	if deviceConfig == nil {
		return fmt.Errorf("no device configuration available in memory")
	}

	// Get the device config path
	deviceConfigPath := m.GetDeviceConfigPath()
	if deviceConfigPath == "" {
		return fmt.Errorf("device config path not available")
	}

	// Write the current device config back to the file
	data, err := json.MarshalIndent(deviceConfig, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal device config: %w", err)
	}

	if err := os.WriteFile(deviceConfigPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write device config file: %w", err)
	}

	if m.agent != nil {
		m.agent.GetLogger().Info("agent.json reset with current device configuration from memory")
	}
	return nil
}

// detectCurrentState detects the actual current state of the system
func (m *Manager) detectCurrentState(desiredState *types.StateConfig) *types.StateConfig {
	// This would need to be implemented to call the statusupdate.DetectCurrentState function
	// For now, return the desired state as a placeholder
	return desiredState
}
