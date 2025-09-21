package heartbeat

import (
	"fmt"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Sender handles heartbeat sending operations
type Sender interface {
	// SendHeartbeat sends a single heartbeat
	SendHeartbeat(payload *types.HeartbeatPayload) error

	// Stop stops the heartbeat sender
	Stop()
}

// HeartbeatSender implements the Sender interface
type HeartbeatSender struct {
	httpClient types.HTTPClient
	mqttClient types.MQTTClient
	deviceID   string
	mode       string
	logger     types.Logger

	// Control
	stopChan chan struct{}
	running  bool
}

// NewHeartbeatSender creates a new heartbeat sender
func NewHeartbeatSender(
	httpClient types.HTTPClient,
	mqttClient types.MQTTClient,
	deviceID string,
	mode string,
	logger types.Logger,
) Sender {
	return &HeartbeatSender{
		httpClient: httpClient,
		mqttClient: mqttClient,
		deviceID:   deviceID,
		mode:       mode,
		logger:     logger,
		stopChan:   make(chan struct{}),
		running:    false,
	}
}

// SendHeartbeat sends a heartbeat message
func (h *HeartbeatSender) SendHeartbeat(payload *types.HeartbeatPayload) error {
	switch h.mode {
	case "http":
		if h.httpClient == nil {
			return fmt.Errorf("HTTP client not configured")
		}
		response, err := h.httpClient.SendHeartbeat(payload, h.deviceID)
		if err != nil {
			return fmt.Errorf("failed to send HTTP heartbeat: %w", err)
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			h.logger.Info("Heartbeat sent successfully")
		} else {
			return fmt.Errorf("heartbeat failed with status: %d", response.StatusCode)
		}

	case "mqtt":
		if h.mqttClient == nil {
			return fmt.Errorf("MQTT client not configured")
		}
		if !h.mqttClient.IsConnected() {
			if err := h.mqttClient.Connect(); err != nil {
				return fmt.Errorf("failed to connect to MQTT: %w", err)
			}
		}
		if err := h.mqttClient.PublishHeartbeat(payload); err != nil {
			return fmt.Errorf("failed to publish MQTT heartbeat: %w", err)
		}
		h.logger.Info("Heartbeat published successfully")

	default:
		return fmt.Errorf("unsupported communication mode: %s", h.mode)
	}

	return nil
}

// Stop stops the heartbeat sender
func (h *HeartbeatSender) Stop() {
	if h.running {
		close(h.stopChan)
		h.running = false
	}
}
