package statusupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// AgentInterface defines the interface that the agent must implement for statusupdate callbacks
type AgentInterface interface {
	// Logger access
	GetLogger() types.Logger

	// Config management
	GetConfigManager() types.ConfigManager
	GetDesiredState() *types.StateConfig
	SetDesiredState(state *types.StateConfig)
	GetCurrentSystemState() *types.StateConfig
	SetCurrentSystemState(state *types.StateConfig)

	// Manager access
	GetContainerManager() types.ContainerManager
	GetSystemPackageManager() types.SystemPackageManager
	GetCustomPackageManager() types.CustomPackageManager
	GetEnvironmentManager() types.EnvironmentManager
	GetStatusUpdateManager() interface{}

	// System operations
	ExecuteCommand(cmd interface{}) error
	SyncSystemToDesiredState(triggeredBy string) (bool, error)
	VerifyAndCorrectSystemState(desiredState *types.StateConfig) error

	// Utility functions
	CloneStateConfig(state *types.StateConfig) *types.StateConfig
}

// ManagerInterface defines the interface for status update management
type ManagerInterface interface {
	StartStatusUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool, isSelfHealing func() bool) error
	Stop()
}

// Manager provides a complete status update management solution
type Manager struct {
	*StatusUpdateSender
	payloadBuilder       *PayloadBuilder
	logger               types.Logger
	running              bool
	stopChan             chan struct{}
	containerManager     types.ContainerManager
	systemPackageManager types.SystemPackageManager
	customPackageManager types.CustomPackageManager
	environmentManager   types.EnvironmentManager
	configManager        types.ConfigManager
	agent                AgentInterface
	currentState         *types.StateConfig
}

// NewManager creates a new status update manager with the new architecture
func NewManager(
	httpClient types.HTTPClient,
	mqttClient types.MQTTClient,
	deviceID string,
	mode string,
	logger types.Logger,
	containerManager types.ContainerManager,
	systemPackageManager types.SystemPackageManager,
	customPackageManager types.CustomPackageManager,
	environmentManager types.EnvironmentManager,
	configManager types.ConfigManager,
	agent AgentInterface,
) *Manager {
	baseSender := NewStatusUpdateSender(httpClient, mqttClient, deviceID, mode, logger)

	return &Manager{
		StatusUpdateSender:   baseSender.(*StatusUpdateSender),
		payloadBuilder:       NewPayloadBuilder(agent.CloneStateConfig),
		logger:               logger,
		stopChan:             make(chan struct{}),
		running:              false,
		containerManager:     containerManager,
		systemPackageManager: systemPackageManager,
		customPackageManager: customPackageManager,
		environmentManager:   environmentManager,
		configManager:        configManager,
		agent:                agent,
		currentState:         nil,
	}
}

// StartStatusUpdateLoop starts the status update loop with new architecture
func (m *Manager) StartStatusUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool, isSelfHealing func() bool) error {
	if m.running {
		return fmt.Errorf("status update loop is already running")
	}

	m.running = true
	m.logger.Infof("Status update loop started with interval: %v", interval)

	go m.statusUpdateLoop(ctx, interval, isUpdating, isSelfHealing)
	return nil
}

// statusUpdateLoop runs the new status update loop according to requirements
func (m *Manager) statusUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool, isSelfHealing func() bool) {
	m.logger.Infof("Starting status update loop with interval: %v", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			m.logger.Info("Status update loop stopped")
			m.running = false
			return
		case <-ctx.Done():
			m.logger.Info("Status update loop stopped due to context cancellation")
			m.running = false
			return
		case <-ticker.C:
			m.logger.Infof("Status update ticker triggered, interval was: %v", interval)
			// Skip update check if agent is updating or self-healing
			if isUpdating() {
				m.logger.Info("Skipping status update - agent is updating")
				continue
			}
			if isSelfHealing() {
				m.logger.Info("Skipping status update - agent is self-healing")
				continue
			}

			if err := m.performStatusUpdateCycle(); err != nil {
				m.logger.Errorf("Status update cycle failed: %v", err)
			}
		}
	}
}

// performStatusUpdateCycle performs the complete status update cycle according to new requirements
func (m *Manager) performStatusUpdateCycle() error {
	m.logger.Info("Status update cycle started")

	// Step 1: Get actual state (run the managers one by one)
	m.logger.Debug("Step 1: Detecting current actual state")
	if err := m.detectCurrentState(); err != nil {
		m.logger.Errorf("Failed to detect current state: %v", err)
		return fmt.Errorf("failed to detect current state: %w", err)
	}

	// Step 2: Send API with current state
	m.logger.Debug("Step 2: Sending status update with current state")
	apiResponse, apiError := m.sendStatusUpdateAPI()

	// Step 3: Process API response - update desired state if new_state received
	var hasCommand bool
	var command interface{}

	if apiError == nil && apiResponse != nil {
		m.logger.Debug("Step 3: Processing API response")
		newState, cmd, err := m.processAPIResponse(apiResponse)
		if err != nil {
			m.logger.Errorf("Failed to process API response: %v", err)
		} else {
			if newState != nil {
				m.logger.Info("Received new desired state from API")
				// Update desired state and save to config
				m.agent.SetDesiredState(newState)
				if err := m.configManager.UpdateStateConfig(newState); err != nil {
					m.logger.Errorf("Failed to save new state to config: %v", err)
				} else {
					m.logger.Debug("New desired state saved to config successfully")
				}
			}
			if cmd != nil {
				hasCommand = true
				command = cmd
				m.logger.Infof("Received command from API: %v", cmd)
			}
		}
	} else if apiError != nil {
		m.logger.Errorf("API call failed: %v", apiError)
	}

	// Step 4: Execute command if present (before state consolidation)
	if hasCommand {
		m.logger.Info("Executing command")
		if err := m.agent.ExecuteCommand(command); err != nil {
			m.logger.Errorf("Command execution failed: %v", err)
		} else {
			m.logger.Debug("Command executed successfully")
		}
	}

	// Step 5: Individual manager state comparison and consolidation
	m.logger.Debug("Step 5: Performing state consolidation")
	consolidationErrors := m.performStateConsolidation()

	// Step 6: Collect all errors and send feedback to backend
	m.logger.Debug("Step 6: Collecting results and sending feedback")
	if err := m.sendConsolidationFeedback(apiError, consolidationErrors); err != nil {
		m.logger.Errorf("Failed to send consolidation feedback: %v", err)
	}

	m.logger.Info("Status update cycle completed")
	return nil
}

// detectCurrentState detects the current actual state by running managers one by one
func (m *Manager) detectCurrentState() error {
	desiredState := m.agent.GetDesiredState()
	if desiredState == nil {
		return fmt.Errorf("desired state is nil")
	}

	m.currentState = DetectCurrentState(
		desiredState,
		m.containerManager,
		m.systemPackageManager,
		m.customPackageManager,
		m.environmentManager,
	)

	m.logger.Info("Current state detected successfully")
	return nil
}

// sendStatusUpdateAPI sends the status update API call with current state
func (m *Manager) sendStatusUpdateAPI() (*types.HTTPResponse, error) {
	if m.currentState == nil {
		return nil, fmt.Errorf("current state not detected")
	}

	// Build status update payload
	payload, _, err := m.payloadBuilder.BuildStatusUpdatePayload("update_check", m.currentState)
	if err != nil {
		return nil, fmt.Errorf("failed to build status update payload: %w", err)
	}

	// Send the status update
	sendResult := m.StatusUpdateSender.SendStatusUpdateWithResult(payload)
	if sendResult.Error != nil {
		m.logger.Errorf("API call failed: %v", sendResult.Error)
		return nil, sendResult.Error
	}

	m.logger.Info("API call succeeded")
	return sendResult.Response, nil
}

// processAPIResponse processes the API response and extracts new_state and cmd
func (m *Manager) processAPIResponse(response *types.HTTPResponse) (*types.StateConfig, interface{}, error) {
	if len(response.Body) == 0 {
		return nil, nil, nil
	}

	var apiResponse map[string]interface{}
	if err := json.Unmarshal(response.Body, &apiResponse); err != nil {
		return nil, nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	// Extract new_state
	var newState *types.StateConfig
	if newStateData, exists := apiResponse["new_state"]; exists && newStateData != nil {
		newStateJSON, err := json.Marshal(newStateData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal new state: %w", err)
		}

		var state types.StateConfig
		if err := json.Unmarshal(newStateJSON, &state); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal new state: %w", err)
		}

		// Check if the new state is empty (backend returned {} meaning no change)
		if !m.configManager.IsStateConfigEmpty(&state) {
			newState = &state
		}
	}

	// Extract cmd
	var cmd interface{}
	if cmdData, exists := apiResponse["cmd"]; exists && cmdData != nil {
		if cmdStr, ok := cmdData.(string); ok && cmdStr != "" {
			cmd = cmdStr
		}
	}

	return newState, cmd, nil
}

// performStateConsolidation performs individual manager state comparison and consolidation
func (m *Manager) performStateConsolidation() map[string]error {
	errors := make(map[string]error)
	desiredState := m.agent.GetDesiredState()

	if desiredState == nil {
		errors["general"] = fmt.Errorf("desired state is nil")
		return errors
	}

	// Container state consolidation
	if m.containerManager != nil {
		m.logger.Info("Performing container state consolidation")
		currentContainers := m.currentState.Containers
		desiredContainers := desiredState.Containers
		if _, err := m.containerManager.StateConsolidation(currentContainers, desiredContainers); err != nil {
			errors["containers"] = err
			m.logger.Errorf("Container state consolidation failed: %v", err)
		} else {
			m.logger.Info("Container state consolidation completed successfully")
		}
	}

	// System package state consolidation
	if m.systemPackageManager != nil {
		m.logger.Info("Performing system package state consolidation")
		currentPackages := m.currentState.Packages
		desiredPackages := desiredState.Packages
		if _, err := m.systemPackageManager.StateConsolidation(currentPackages, desiredPackages); err != nil {
			errors["system_packages"] = err
			m.logger.Errorf("System package state consolidation failed: %v", err)
		} else {
			m.logger.Info("System package state consolidation completed successfully")
		}
	}

	// Custom package state consolidation
	if m.customPackageManager != nil {
		m.logger.Info("Performing custom package state consolidation")
		currentCustomPackages := m.currentState.CustomPackages
		desiredCustomPackages := desiredState.CustomPackages
		if _, err := m.customPackageManager.StateConsolidation(currentCustomPackages, desiredCustomPackages); err != nil {
			errors["custom_packages"] = err
			m.logger.Errorf("Custom package state consolidation failed: %v", err)
		} else {
			m.logger.Info("Custom package state consolidation completed successfully")
		}
	}

	// Environment state consolidation
	if m.environmentManager != nil {
		m.logger.Info("Performing environment state consolidation")
		desiredEnv := desiredState.Env
		if err := m.environmentManager.SyncSystemEnvironment(desiredEnv); err != nil {
			errors["environment"] = err
			m.logger.Errorf("Environment state consolidation failed: %v", err)
		} else {
			m.logger.Info("Environment state consolidation completed successfully")
		}
	}

	return errors
}

// sendConsolidationFeedback sends feedback about the consolidation results to backend
func (m *Manager) sendConsolidationFeedback(apiError error, consolidationErrors map[string]error) error {
	// Determine overall success
	success := apiError == nil && len(consolidationErrors) == 0

	// Create feedback payload
	feedback := map[string]interface{}{
		"success":     success,
		"api_success": apiError == nil,
		"errors":      make(map[string]string),
	}

	// Add API error if present
	if apiError != nil {
		feedback["errors"].(map[string]string)["api"] = apiError.Error()
	}

	// Add consolidation errors
	for component, err := range consolidationErrors {
		feedback["errors"].(map[string]string)[component] = err.Error()
	}

	// Build feedback payload
	feedbackPayload := &types.StatusUpdatePayload{
		UpdateType:   "consolidation_feedback",
		CurrentState: *m.currentState,
	}

	// Send feedback
	sendResult := m.StatusUpdateSender.SendStatusUpdateWithResult(feedbackPayload)
	if sendResult.Error != nil {
		return fmt.Errorf("failed to send consolidation feedback: %w", sendResult.Error)
	}

	if success {
		m.logger.Info("Consolidation feedback sent successfully - all operations succeeded")
	} else {
		m.logger.Infof("Consolidation feedback sent successfully - some operations failed")
	}

	return nil
}

// Stop stops the status update manager
func (m *Manager) Stop() {
	if m.running {
		close(m.stopChan)
		m.running = false
	}
}
