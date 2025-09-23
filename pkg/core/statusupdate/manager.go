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
	consolidationResult := m.performStateConsolidation()

	// Step 6: Collect all errors and send feedback to backend
	m.logger.Debug("Step 6: Collecting results and sending feedback")
	// Determine if this was triggered by an API update (only if API succeeded and provided new state/command)
	// If API failed, it's considered selfheal
	isUpdate := (apiError == nil) && (hasCommand || (apiResponse != nil))
	if err := m.sendConsolidationFeedback(apiError, consolidationResult, isUpdate); err != nil {
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

	// System package state consolidation (before containers)
	if m.systemPackageManager != nil {
		m.logger.Info("Performing system package state consolidation")
		currentPackages := m.currentState.Packages
		desiredPackages := desiredState.Packages
		if changes, err := m.systemPackageManager.StateConsolidation(currentPackages, desiredPackages); err != nil {
			result.Errors["system_packages"] = err
			m.logger.Errorf("System package state consolidation failed: %v", err)
		} else {
			if len(changes) > 0 {
				result.OperationsPerformed = true
				m.logger.Infof("System package state consolidation completed successfully with %d changes", len(changes))
			} else {
				m.logger.Info("System package state consolidation completed successfully - no changes needed")
			}
		}
	}

	// Custom package state consolidation (before containers)
	if m.customPackageManager != nil {
		m.logger.Info("Performing custom package state consolidation")
		currentCustomPackages := m.currentState.CustomPackages
		desiredCustomPackages := desiredState.CustomPackages
		if changes, err := m.customPackageManager.StateConsolidation(currentCustomPackages, desiredCustomPackages); err != nil {
			result.Errors["custom_packages"] = err
			m.logger.Errorf("Custom package state consolidation failed: %v", err)
		} else {
			if len(changes) > 0 {
				result.OperationsPerformed = true
				m.logger.Infof("Custom package state consolidation completed successfully with %d changes", len(changes))
			} else {
				m.logger.Info("Custom package state consolidation completed successfully - no changes needed")
			}
		}
	}

	// Container state consolidation (after packages)
	if m.containerManager != nil {
		m.logger.Info("Performing container state consolidation")
		currentContainers := m.currentState.Containers
		desiredContainers := desiredState.Containers
		if changes, err := m.containerManager.StateConsolidation(currentContainers, desiredContainers); err != nil {
			result.Errors["containers"] = err
			m.logger.Errorf("Container state consolidation failed: %v", err)
		} else {
			if len(changes) > 0 {
				result.OperationsPerformed = true
				m.logger.Infof("Container state consolidation completed successfully with %d changes", len(changes))
			} else {
				m.logger.Info("Container state consolidation completed successfully - no changes needed")
			}
		}
	}

	// Environment state consolidation
	if m.environmentManager != nil {
		m.logger.Info("Performing environment state consolidation")
		desiredEnv := desiredState.Env
		if err := m.environmentManager.SyncSystemEnvironment(desiredEnv); err != nil {
			result.Errors["environment"] = err
			m.logger.Errorf("Environment state consolidation failed: %v", err)
		} else {
			// Environment manager doesn't return changes, so we assume operations were performed if no error
			result.OperationsPerformed = true
			m.logger.Info("Environment state consolidation completed successfully")
		}
	}

	return result
}

// sendConsolidationFeedback sends feedback about the consolidation results to backend
// Only sends feedback if operations were actually performed
func (m *Manager) sendConsolidationFeedback(apiError error, consolidationResult *ConsolidationResult, isUpdate bool) error {
	// Only send feedback if operations were actually performed
	if !consolidationResult.OperationsPerformed {
		m.logger.Debug("No operations were performed, no feedback needed")
		return nil
	}

	// Determine API success (API call succeeded and no API-level errors)
	apiSuccess := apiError == nil

	// Send feedback using the feedback manager
	if err := m.feedbackManager.SendFeedback(apiSuccess, consolidationResult.Errors, isUpdate); err != nil {
		return fmt.Errorf("failed to send feedback: %w", err)
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
