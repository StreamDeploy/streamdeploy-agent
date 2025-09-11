package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/config"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/utils"
)

type CoreAgent struct {
	configManager    types.ConfigManager
	logger           types.Logger
	httpClient       types.HTTPClient
	mqttClient       types.MQTTClient
	metricsCollector types.MetricsCollector
	containerManager types.ContainerManager

	// Control channels
	ctx     context.Context
	cancel  context.CancelFunc
	running bool

	// Timing
	heartbeatInterval time.Duration
	updateInterval    time.Duration
}

// NewCoreAgent creates a new core agent instance
func NewCoreAgent(deviceConfigPath string) (*CoreAgent, error) {
	configManager, err := config.NewManager(deviceConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create config manager: %w", err)
	}

	logger := utils.NewLogger("AGENT")

	ctx, cancel := context.WithCancel(context.Background())

	agent := &CoreAgent{
		configManager: configManager,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		running:       false,
	}

	// Parse timing intervals
	agent.heartbeatInterval = configManager.GetHeartbeatFrequency()
	agent.updateInterval = configManager.GetUpdateFrequency()

	logger.Info("Core agent initialized successfully")

	return agent, nil
}

// SetHTTPClient sets the HTTP client implementation
func (a *CoreAgent) SetHTTPClient(client types.HTTPClient) {
	a.httpClient = client
}

// SetMQTTClient sets the MQTT client implementation
func (a *CoreAgent) SetMQTTClient(client types.MQTTClient) {
	a.mqttClient = client
}

// SetMetricsCollector sets the metrics collector implementation
func (a *CoreAgent) SetMetricsCollector(collector types.MetricsCollector) {
	a.metricsCollector = collector
}

// SetContainerManager sets the container manager implementation
func (a *CoreAgent) SetContainerManager(manager types.ContainerManager) {
	a.containerManager = manager
}

// Start starts the core agent
func (a *CoreAgent) Start() error {
	if a.running {
		a.logger.Info("Agent is already running")
		return nil
	}

	a.logger.Info("Starting StreamDeploy core agent")
	a.running = true

	// Set up config change callback
	a.configManager.SetConfigChangeCallback(a.handleConfigChange)

	// Start config monitoring
	if err := a.configManager.StartMonitoring(); err != nil {
		a.logger.Errorf("Failed to start config monitoring: %v", err)
	}

	// Start worker goroutines
	go a.heartbeatLoop()
	go a.updateLoop()

	a.logger.Info("Core agent started successfully")
	return nil
}

// Stop stops the core agent
func (a *CoreAgent) Stop() {
	if !a.running {
		return
	}

	a.logger.Info("Stopping StreamDeploy core agent")
	a.running = false

	// Cancel context to stop goroutines
	a.cancel()

	// Stop config monitoring
	a.configManager.StopMonitoring()

	a.logger.Info("Core agent stopped")
}

// IsRunning returns whether the agent is running
func (a *CoreAgent) IsRunning() bool {
	return a.running
}

// heartbeatLoop runs the heartbeat loop
func (a *CoreAgent) heartbeatLoop() {
	a.logger.Infof("Heartbeat loop started with interval: %v", a.heartbeatInterval)

	ticker := time.NewTicker(a.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Heartbeat loop stopped")
			return
		case <-ticker.C:
			if err := a.sendHeartbeat(); err != nil {
				a.logger.Errorf("Heartbeat failed: %v", err)
			}
		}
	}
}

// updateLoop runs the update loop
func (a *CoreAgent) updateLoop() {
	a.logger.Infof("Update loop started with interval: %v", a.updateInterval)

	ticker := time.NewTicker(a.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Update loop stopped")
			return
		case <-ticker.C:
			if err := a.performUpdateCheck(); err != nil {
				a.logger.Errorf("Update check failed: %v", err)
			}
		}
	}
}

// sendHeartbeat sends a heartbeat message
func (a *CoreAgent) sendHeartbeat() error {
	stateConfig := a.configManager.GetStateConfig()
	if stateConfig == nil {
		return fmt.Errorf("state config is nil")
	}

	// Collect metrics if collector is available
	var metrics map[string]interface{}
	if a.metricsCollector != nil {
		systemMetrics, err := a.metricsCollector.CollectSystemMetrics()
		if err != nil {
			a.logger.Errorf("Failed to collect system metrics: %v", err)
			metrics = make(map[string]interface{})
		} else {
			metrics = map[string]interface{}{
				"cpu_pct":  systemMetrics.CPUPercent,
				"mem_pct":  systemMetrics.MemPercent,
				"disk_pct": systemMetrics.DiskPercent,
			}

			// Add custom metrics
			customMetrics, err := a.metricsCollector.CollectCustomMetrics(stateConfig.CustomMetrics)
			if err != nil {
				a.logger.Errorf("Failed to collect custom metrics: %v", err)
			} else {
				for k, v := range customMetrics {
					metrics[k] = v
				}
			}
		}
	} else {
		metrics = make(map[string]interface{})
	}

	// Check container health
	containersHealthy := true
	if a.containerManager != nil {
		stateConfig := a.configManager.GetStateConfig()
		if stateConfig != nil && len(stateConfig.Containers) > 0 {
			// Ensure containers are running
			if err := a.containerManager.EnsureContainersRunning(stateConfig.Containers); err != nil {
				a.logger.Errorf("Failed to ensure containers are running: %v", err)
				containersHealthy = false
			}

			// Perform health checks
			for _, containerConfig := range stateConfig.Containers {
				containerInfo := &types.ContainerInfo{
					Name:       containerConfig.Name,
					Image:      containerConfig.Image,
					Port:       containerConfig.Port,
					HealthPath: containerConfig.HealthPath,
					Running:    a.containerManager.IsContainerRunning(containerConfig.Name),
				}

				if !a.containerManager.PerformHealthCheck(containerInfo) {
					containersHealthy = false
					a.logger.Errorf("Health check failed for container: %s", containerConfig.Name)
				}
			}
		}
	}

	// Determine system status
	status := "healthy"
	if a.metricsCollector != nil {
		cpuPct, _ := metrics["cpu_pct"].(float64)
		memPct, _ := metrics["mem_pct"].(float64)
		diskPct, _ := metrics["disk_pct"].(float64)
		status = a.metricsCollector.DetermineSystemStatus(cpuPct, memPct, diskPct, containersHealthy)
	}

	// Build heartbeat payload
	heartbeat := &types.HeartbeatPayload{
		Status:       status,
		AgentSetting: stateConfig.AgentSetting,
		Metrics:      metrics,
	}

	// Send heartbeat based on mode
	mode := a.configManager.GetMode()
	deviceID := a.configManager.GetDeviceID()

	switch mode {
	case "http", "https":
		if a.httpClient == nil {
			return fmt.Errorf("HTTP client not configured")
		}
		response, err := a.httpClient.SendHeartbeat(heartbeat, deviceID)
		if err != nil {
			return fmt.Errorf("failed to send HTTP heartbeat: %w", err)
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			a.logger.Info("Heartbeat sent successfully")
		} else {
			return fmt.Errorf("heartbeat failed with status: %d", response.StatusCode)
		}

	case "mqtt":
		if a.mqttClient == nil {
			return fmt.Errorf("MQTT client not configured")
		}
		if !a.mqttClient.IsConnected() {
			if err := a.mqttClient.Connect(); err != nil {
				return fmt.Errorf("failed to connect to MQTT: %w", err)
			}
		}
		if err := a.mqttClient.PublishHeartbeat(heartbeat); err != nil {
			return fmt.Errorf("failed to publish MQTT heartbeat: %w", err)
		}
		a.logger.Info("Heartbeat published successfully")

	default:
		return fmt.Errorf("unsupported mode: %s", mode)
	}

	return nil
}

// performUpdateCheck performs an update check
func (a *CoreAgent) performUpdateCheck() error {
	stateConfig := a.configManager.GetStateConfig()
	if stateConfig == nil {
		return fmt.Errorf("state config is nil")
	}

	// Build status update payload
	statusUpdate := &types.StatusUpdatePayload{
		UpdateType:   "update_check",
		CurrentState: *stateConfig,
	}

	// Send status update based on mode
	mode := a.configManager.GetMode()
	deviceID := a.configManager.GetDeviceID()

	switch mode {
	case "http", "https":
		if a.httpClient == nil {
			return fmt.Errorf("HTTP client not configured")
		}
		response, err := a.httpClient.SendStatusUpdate(statusUpdate, deviceID)
		if err != nil {
			return fmt.Errorf("failed to send HTTP status update: %w", err)
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			a.logger.Info("Status update sent successfully")

			// Parse response for new state
			if len(response.Body) > 0 {
				if err := a.handleStatusUpdateResponse(response.Body); err != nil {
					a.logger.Errorf("Failed to handle status update response: %v", err)
				}
			}
		} else {
			return fmt.Errorf("status update failed with status: %d", response.StatusCode)
		}

	case "mqtt":
		if a.mqttClient == nil {
			return fmt.Errorf("MQTT client not configured")
		}
		if !a.mqttClient.IsConnected() {
			if err := a.mqttClient.Connect(); err != nil {
				return fmt.Errorf("failed to connect to MQTT: %w", err)
			}
		}
		if err := a.mqttClient.PublishStatusUpdate(statusUpdate); err != nil {
			return fmt.Errorf("failed to publish MQTT status update: %w", err)
		}
		a.logger.Info("Status update published successfully")

	default:
		return fmt.Errorf("unsupported mode: %s", mode)
	}

	return nil
}

// handleStatusUpdateResponse handles the response from a status update
func (a *CoreAgent) handleStatusUpdateResponse(responseBody []byte) error {
	var response map[string]interface{}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	newStateData, exists := response["new_state"]
	if !exists {
		return nil // No new state
	}

	// Convert to JSON and back to StateConfig
	newStateJSON, err := json.Marshal(newStateData)
	if err != nil {
		return fmt.Errorf("failed to marshal new state: %w", err)
	}

	var newState types.StateConfig
	if err := json.Unmarshal(newStateJSON, &newState); err != nil {
		return fmt.Errorf("failed to unmarshal new state: %w", err)
	}

	// Compare with current state
	currentState := a.configManager.GetStateConfig()
	if !stateConfigsEqual(currentState, &newState) {
		a.logger.Info("Received new state configuration")

		// Sync containers if container manager is available
		if a.containerManager != nil {
			oldContainers := []types.ContainerConfig{}
			if currentState != nil {
				oldContainers = currentState.Containers
			}

			if err := a.containerManager.SyncContainers(newState.Containers, oldContainers); err != nil {
				a.logger.Errorf("Failed to sync containers: %v", err)
			} else {
				a.logger.Info("Containers synchronized successfully")
			}
		}

		if err := a.configManager.UpdateStateConfig(&newState); err != nil {
			return fmt.Errorf("failed to update state config: %w", err)
		}

		a.logger.Info("State configuration updated")
	}

	return nil
}

// handleConfigChange handles configuration file changes
func (a *CoreAgent) handleConfigChange(filePath string) {
	a.logger.Infof("Configuration changed: %s", filePath)

	// Update timing intervals
	a.heartbeatInterval = a.configManager.GetHeartbeatFrequency()
	a.updateInterval = a.configManager.GetUpdateFrequency()

	a.logger.Info("Configuration reloaded successfully")
}

// stateConfigsEqual compares two state configurations for equality
func stateConfigsEqual(a, b *types.StateConfig) bool {
	if a == nil || b == nil {
		return a == b
	}

	// Simple comparison - in a real implementation you might want more sophisticated comparison
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)

	return string(aJSON) == string(bJSON)
}
