package heartbeat

import (
	"fmt"
	"strings"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// PayloadBuilder builds heartbeat payloads
type PayloadBuilder struct {
	metricsCollector types.MetricsCollector
	containerManager types.ContainerManager
	desiredState     *types.StateConfig
}

// NewPayloadBuilder creates a new payload builder
func NewPayloadBuilder(metricsCollector types.MetricsCollector, containerManager types.ContainerManager) *PayloadBuilder {
	return &PayloadBuilder{
		metricsCollector: metricsCollector,
		containerManager: containerManager,
	}
}

// SetDesiredState sets the desired state for heartbeat payloads
func (b *PayloadBuilder) SetDesiredState(desiredState *types.StateConfig) {
	b.desiredState = desiredState
}

// BuildHeartbeatPayload builds a complete heartbeat payload
func (b *PayloadBuilder) BuildHeartbeatPayload() (*types.HeartbeatPayload, error) {
	if b.desiredState == nil {
		return nil, fmt.Errorf("desired state not set")
	}

	// Collect system metricsd
	metrics, err := b.metricsCollector.CollectSystemMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to collect system metrics: %w", err)
	}

	// Collect custom metrics
	customMetrics, err := b.metricsCollector.CollectCustomMetrics(b.desiredState.CustomMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to collect custom metrics: %w", err)
	}

	// Check container health
	containersHealthy := true
	if b.containerManager != nil && len(b.desiredState.Containers) > 0 {
		// Get current container state with health checks
		currentContainers := b.containerManager.DetectCurrentState(b.desiredState)

		// Check if any containers have failed health checks (indicated by "failed" in HealthPath)
		for _, container := range currentContainers {
			if strings.HasSuffix(container.HealthPath, "failed") {
				containersHealthy = false
				break
			}
		}
	}

	// Determine system status
	status := b.metricsCollector.DetermineSystemStatus(
		metrics.CPUPercent,
		metrics.MemPercent,
		metrics.DiskPercent,
		containersHealthy,
	)

	// Build metrics map
	metricsMap := map[string]interface{}{
		"cpu_pct":  metrics.CPUPercent,
		"mem_pct":  metrics.MemPercent,
		"disk_pct": metrics.DiskPercent,
		"swap_pct": metrics.SwapPercent,
	}

	// Add custom metrics
	for key, value := range customMetrics {
		metricsMap[key] = value
	}

	// Build heartbeat payload
	heartbeat := &types.HeartbeatPayload{
		Status:       status,
		AgentSetting: b.desiredState.AgentSetting,
		Metrics:      metricsMap,
	}

	return heartbeat, nil
}
