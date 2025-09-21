package statusupdate

import (
	"fmt"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// SendResult represents the result of a status update send operation
type SendResult struct {
	Success  bool
	Error    error
	Response *types.HTTPResponse
	Mode     string
}

// Sender handles status update sending operations
type Sender interface {
	// SendStatusUpdate sends a single status update
	SendStatusUpdate(payload *types.StatusUpdatePayload) error

	// SendStatusUpdateWithResult sends a status update and returns detailed result
	SendStatusUpdateWithResult(payload *types.StatusUpdatePayload) *SendResult

	// PerformSelfHeal performs self-healing operations based on send result
	PerformSelfHeal(result *SendResult, responseHandler StatusUpdateResponseHandler) *SelfHealResult

	// Stop stops the status update sender
	Stop()
}

// StatusUpdateSender implements the Sender interface
type StatusUpdateSender struct {
	httpClient types.HTTPClient
	mqttClient types.MQTTClient
	deviceID   string
	mode       string
	logger     types.Logger
}

// NewStatusUpdateSender creates a new status update sender
func NewStatusUpdateSender(
	httpClient types.HTTPClient,
	mqttClient types.MQTTClient,
	deviceID string,
	mode string,
	logger types.Logger,
) Sender {
	return &StatusUpdateSender{
		httpClient: httpClient,
		mqttClient: mqttClient,
		deviceID:   deviceID,
		mode:       mode,
		logger:     logger,
	}
}

// SendStatusUpdate sends a status update message
func (s *StatusUpdateSender) SendStatusUpdate(payload *types.StatusUpdatePayload) error {
	switch s.mode {
	case "http", "https":
		if s.httpClient == nil {
			return fmt.Errorf("HTTP client not configured")
		}
		response, err := s.httpClient.SendStatusUpdate(payload, s.deviceID)
		if err != nil {
			return fmt.Errorf("failed to send HTTP status update: %w", err)
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			s.logger.Info("Status update sent successfully")
		} else {
			return fmt.Errorf("status update failed with status: %d", response.StatusCode)
		}

	case "mqtt":
		if s.mqttClient == nil {
			return fmt.Errorf("MQTT client not configured")
		}
		if !s.mqttClient.IsConnected() {
			if err := s.mqttClient.Connect(); err != nil {
				return fmt.Errorf("failed to connect to MQTT: %w", err)
			}
		}
		if err := s.mqttClient.PublishStatusUpdate(payload); err != nil {
			return fmt.Errorf("failed to publish MQTT status update: %w", err)
		}
		s.logger.Info("Status update published successfully")

	default:
		return fmt.Errorf("unsupported communication mode: %s", s.mode)
	}

	return nil
}

// SendStatusUpdateWithResult sends a status update and returns detailed result
func (s *StatusUpdateSender) SendStatusUpdateWithResult(payload *types.StatusUpdatePayload) *SendResult {
	result := &SendResult{
		Mode: s.mode,
	}

	switch s.mode {
	case "http", "https":
		if s.httpClient == nil {
			result.Error = fmt.Errorf("HTTP client not configured")
			return result
		}
		response, err := s.httpClient.SendStatusUpdate(payload, s.deviceID)
		if err != nil {
			result.Error = fmt.Errorf("failed to send HTTP status update: %w", err)
			return result
		}
		result.Response = response
		result.Success = response.StatusCode >= 200 && response.StatusCode < 300

	case "mqtt":
		if s.mqttClient == nil {
			result.Error = fmt.Errorf("MQTT client not configured")
			return result
		}
		if !s.mqttClient.IsConnected() {
			if err := s.mqttClient.Connect(); err != nil {
				result.Error = fmt.Errorf("failed to connect to MQTT: %w", err)
				return result
			}
		}
		if err := s.mqttClient.PublishStatusUpdate(payload); err != nil {
			result.Error = fmt.Errorf("failed to publish MQTT status update: %w", err)
			return result
		}
		result.Success = true

	default:
		result.Error = fmt.Errorf("unsupported communication mode: %s", s.mode)
	}

	return result
}

// PerformSelfHeal performs self-healing operations based on send result
func (s *StatusUpdateSender) PerformSelfHeal(
	result *SendResult,
	responseHandler StatusUpdateResponseHandler,
) *SelfHealResult {
	// Process self-healing operations using the response handler
	return responseHandler.ProcessStatusUpdateSelfHeal(
		result.Success,
		result.Error,
		result.Response,
		responseHandler,
	)
}

// Stop stops the status update sender
func (s *StatusUpdateSender) Stop() {
	// Status update sender doesn't need cleanup like heartbeat sender
}
