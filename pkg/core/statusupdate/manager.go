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
	feedbackManager      *FeedbackManager
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
	payloadBuilder := NewPayloadBuilder(agent.CloneStateConfig)
	feedbackManager := NewFeedbackManager(payloadBuilder, baseSender, logger)

	return &Manager{
		StatusUpdateSender:   baseSender.(*StatusUpdateSender),
		payloadBuilder:       payloadBuilder,
		feedbackManager:      feedbackManager,
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
	var hasNewState bool

	if apiError == nil && apiResponse != nil {
		m.logger.Debug("Step 3: Processing API response")
		newState, cmd, err := m.processAPIResponse(apiResponse)
		if err != nil {
			m.logger.Errorf("Failed to process API response: %v", err)
		} else {
			if newState != nil {
				hasNewState = true
				m.logger.Info("Received new desired state from API")
				// Update desired state in memory only (state.json will be saved later)
				m.agent.SetDesiredState(newState)
			} else {
				m.logger.Debug("API returned empty state ({}), no state changes needed")
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

	// Step 4: Execute command if present
	if hasCommand {
		m.logger.Info("Executing command")
		if err := m.agent.ExecuteCommand(command); err != nil {
			m.logger.Errorf("Command execution failed: %v", err)
		} else {
			m.logger.Debug("Command executed successfully")
		}
	}

	// Step 5: Update agent settings in memory (logging_level, mode, update_frequency, heartbeat_frequency)
	if hasNewState {
		m.logger.Debug("Step 5: Updating agent settings in memory")
		if err := m.updateAgentSettingsInMemory(); err != nil {
			m.logger.Errorf("Failed to update agent settings in memory: %v", err)
		} else {
			m.logger.Debug("Agent settings updated in memory successfully")
		}
	}

	// Step 5: Individual manager state comparison and consolidation
	m.logger.Debug("Step 5: Performing state consolidation")
	consolidationResult := m.performStateConsolidation()

	// Step 6: Collect all errors and send feedback to backend
	m.logger.Debug("Step 6: Collecting results and sending feedback")
	// Only send feedback if there are actual changes made or new state was received
	if hasNewState || consolidationResult.OperationsPerformed {
		// Determine if this was triggered by an API update (only if API succeeded and provided new state/command)
		// If API failed or returned empty state ({}), it's considered selfheal
		isUpdate := (apiError == nil) && (hasCommand || hasNewState)
		if isUpdate {
			m.logger.Info("Status update triggered by API (new state or command received)")
		} else {
			m.logger.Info("Status update triggered by self-healing (no new state or command from API)")
		}
		if err := m.sendConsolidationFeedback(apiError, consolidationResult, isUpdate); err != nil {
			m.logger.Errorf("Failed to send consolidation feedback: %v", err)
		}
	} else {
		m.logger.Info("No changes made and no new state received, skipping feedback")
	}

	// Step 7: Update state.json after all operations complete (only if there are changes and no errors)
	if hasNewState && len(consolidationResult.Errors) == 0 {
		m.logger.Debug("Step 7: Updating state.json")
		desiredState := m.agent.GetDesiredState()
		if desiredState != nil {
			if err := m.configManager.UpdateStateConfig(desiredState); err != nil {
				m.logger.Errorf("Failed to save state to config: %v", err)
			} else {
				m.logger.Debug("State saved to config successfully")
			}
		}
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

	// Build status update payload (only current_state field)
	payload, _, err := m.payloadBuilder.BuildStatusUpdatePayload(m.currentState)
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

// ConsolidationResult represents the result of state consolidation
type ConsolidationResult struct {
	Errors              map[string]error
	OperationsPerformed bool
}

// performStateConsolidation performs individual manager state comparison and consolidation
func (m *Manager) performStateConsolidation() *ConsolidationResult {
	result := &ConsolidationResult{
		Errors:              make(map[string]error),
		OperationsPerformed: false,
	}

	desiredState := m.agent.GetDesiredState()

	if desiredState == nil {
		result.Errors["general"] = fmt.Errorf("desired state is nil")
		return result
	}

	// Environment state consolidation (first)
	if m.environmentManager != nil {
		m.logger.Info("Performing environment state consolidation")
		desiredEnv := desiredState.Env
		if _, changesMade, err := m.environmentManager.SyncSystemEnvironment(desiredEnv); err != nil {
			result.Errors["environment"] = err
			result.OperationsPerformed = true // Mark as performed even if failed
			m.logger.Errorf("Environment state consolidation failed: %v", err)
		} else {
			if changesMade {
				result.OperationsPerformed = true
				m.logger.Info("Environment state consolidation completed successfully with changes")
			} else {
				m.logger.Info("Environment state consolidation completed successfully - no changes needed")
			}
		}
	}

	// System package state consolidation (second)
	if m.systemPackageManager != nil {
		m.logger.Info("Performing system package state consolidation")
		currentPackages := m.currentState.Packages
		desiredPackages := desiredState.Packages
		if _, changesMade, err := m.systemPackageManager.StateConsolidation(currentPackages, desiredPackages); err != nil {
			result.Errors["system_packages"] = err
			result.OperationsPerformed = true // Mark as performed even if failed
			m.logger.Errorf("System package state consolidation failed: %v", err)
		} else {
			if changesMade {
				result.OperationsPerformed = true
				m.logger.Info("System package state consolidation completed successfully with changes")
			} else {
				m.logger.Info("System package state consolidation completed successfully - no changes needed")
			}
		}
	}

	// Custom package state consolidation (third)
	if m.customPackageManager != nil {
		m.logger.Info("Performing custom package state consolidation")
		currentCustomPackages := m.currentState.CustomPackages
		desiredCustomPackages := desiredState.CustomPackages
		if _, changesMade, err := m.customPackageManager.StateConsolidation(currentCustomPackages, desiredCustomPackages); err != nil {
			result.Errors["custom_packages"] = err
			result.OperationsPerformed = true // Mark as performed even if failed
			m.logger.Errorf("Custom package state consolidation failed: %v", err)
		} else {
			if changesMade {
				result.OperationsPerformed = true
				m.logger.Info("Custom package state consolidation completed successfully with changes")
			} else {
				m.logger.Info("Custom package state consolidation completed successfully - no changes needed")
			}
		}
	}

	// Container state consolidation (last)
	if m.containerManager != nil {
		m.logger.Info("Performing container state consolidation")
		currentContainers := m.currentState.Containers
		desiredContainers := desiredState.Containers
		if _, changesMade, err := m.containerManager.StateConsolidation(currentContainers, desiredContainers); err != nil {
			result.Errors["containers"] = err
			result.OperationsPerformed = true // Mark as performed even if failed
			m.logger.Errorf("Container state consolidation failed: %v", err)
		} else {
			if changesMade {
				result.OperationsPerformed = true
				m.logger.Info("Container state consolidation completed successfully with changes")
			} else {
				m.logger.Info("Container state consolidation completed successfully - no changes needed")
			}
		}
	}

	return result
}

// sendConsolidationFeedback sends feedback about the consolidation results to backend
// Sends feedback if operations were performed OR if this was triggered by an API update
func (m *Manager) sendConsolidationFeedback(apiError error, consolidationResult *ConsolidationResult, isUpdate bool) error {
	// Send feedback if operations were performed OR if this was an API update (even with no changes)
	if !consolidationResult.OperationsPerformed && !isUpdate {
		m.logger.Debug("No operations were performed and not an API update, no feedback needed")
		return nil
	}

	// Determine API success (API call succeeded and no API-level errors)
	apiSuccess := apiError == nil

	// Get current state for feedback
	currentState := m.agent.GetCurrentSystemState()

	// Send feedback using the feedback manager
	if err := m.feedbackManager.SendFeedback(apiSuccess, consolidationResult.Errors, isUpdate, currentState); err != nil {
		return fmt.Errorf("failed to send feedback: %w", err)
	}

	return nil
}

// updateAgentSettingsInMemory updates agent settings in memory without saving to file
func (m *Manager) updateAgentSettingsInMemory() error {
	desiredState := m.agent.GetDesiredState()
	if desiredState == nil {
		return fmt.Errorf("desired state is nil")
	}

	// Update agent settings in the config manager's memory
	// This updates logging_level, mode, update_frequency, and heartbeat_frequency
	m.configManager.SetAgentSettings(desiredState.AgentSetting)

	m.logger.Debugf("Agent settings updated in memory: logging_level=%s, mode=%s, update_frequency=%s, heartbeat_frequency=%s",
		desiredState.AgentSetting.LoggingLevel,
		desiredState.AgentSetting.Mode,
		desiredState.AgentSetting.UpdateFrequency,
		desiredState.AgentSetting.HeartbeatFrequency)

	return nil
}

// Stop stops the status update manager
func (m *Manager) Stop() {
	if m.running {
		close(m.stopChan)
		m.running = false
	}
}
