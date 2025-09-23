package heartbeat

import (
	"context"
	"fmt"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// ManagerInterface defines the interface for heartbeat management
type ManagerInterface interface {
	StartHeartbeatLoop(ctx context.Context, interval time.Duration, isUpdating func() bool) error
	SetDesiredState(desiredState *types.StateConfig)
	SendHeartbeatWithPayload(payload *types.HeartbeatPayload) error
	Stop()
}

// Manager provides a complete heartbeat management solution
type Manager struct {
	*HeartbeatSender
	payloadBuilder *PayloadBuilder
	desiredState   *types.StateConfig
}

// NewManager creates a new heartbeat manager
func NewManager(
	httpClient types.HTTPClient,
	mqttClient types.MQTTClient,
	deviceID string,
	mode string,
	metricsCollector types.MetricsCollector,
	containerManager types.ContainerManager,
	logger types.Logger,
) *Manager {
	baseSender := NewHeartbeatSender(httpClient, mqttClient, deviceID, mode, logger)

	return &Manager{
		HeartbeatSender: baseSender.(*HeartbeatSender),
		payloadBuilder:  NewPayloadBuilder(metricsCollector, containerManager),
	}
}

// SetDesiredState sets the desired state for heartbeat generation
func (m *Manager) SetDesiredState(desiredState *types.StateConfig) {
	m.desiredState = desiredState
	m.payloadBuilder.SetDesiredState(desiredState)
}

// StartHeartbeatLoop starts the heartbeat loop
func (m *Manager) StartHeartbeatLoop(ctx context.Context, interval time.Duration, isUpdating func() bool) error {
	if m.running {
		return fmt.Errorf("heartbeat loop is already running")
	}

	if interval <= 0 {
		m.logger.Info("Heartbeat not started: interval is non-positive (disabled)")
		return nil
	}

	m.running = true
	m.logger.Infof("Heartbeat loop started with interval: %v", interval)

	go m.heartbeatLoop(ctx, interval, isUpdating)
	return nil
}

// heartbeatLoop runs the heartbeat loop with payload building
func (m *Manager) heartbeatLoop(ctx context.Context, interval time.Duration, isUpdating func() bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			m.logger.Info("Heartbeat loop stopped")
			m.running = false
			return
		case <-ctx.Done():
			m.logger.Info("Heartbeat loop stopped due to context cancellation")
			m.running = false
			return
		case <-ticker.C:
			// Skip heartbeat if agent is updating (but allow during self-healing)
			if isUpdating() {
				m.logger.Info("Skipping heartbeat - agent is updating")
				continue
			}

			// Build heartbeat payload
			payload, err := m.payloadBuilder.BuildHeartbeatPayload()
			if err != nil {
				m.logger.Errorf("Failed to build heartbeat payload: %v", err)
				continue
			}

			if err := m.SendHeartbeat(payload); err != nil {
				m.logger.Errorf("Failed to send heartbeat: %v", err)
			}
		}
	}
}

// SendHeartbeatWithPayload sends a heartbeat with a custom payload
func (m *Manager) SendHeartbeatWithPayload(payload *types.HeartbeatPayload) error {
	return m.SendHeartbeat(payload)
}
