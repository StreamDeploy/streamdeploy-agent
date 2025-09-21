package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
	"github.com/gorilla/websocket"
)

const (
	MaxBufferSize = 512 * 1024 // 512KB buffer per channel
	PingInterval  = 25 * time.Second
	PongTimeout   = 30 * time.Second
	AllowedHost   = "127.0.0.1"
	AllowedPort   = 22
)

type SSHTunnelManager struct {
	logger        types.Logger
	configManager types.ConfigManager
	httpClient    types.HTTPClient
	mqttClient    types.MQTTClient

	// Tunnel state
	wsConn        *websocket.Conn
	channels      map[string]*types.TunnelChannel
	channelsMutex sync.RWMutex
	isActive      bool
	user          string
	expires       time.Time
	sessionID     string

	// Control
	ctx           context.Context
	cancel        context.CancelFunc
	pingTicker    *time.Ticker
	reconnectChan chan struct{}

	// Back-pressure control
	sendQueue  chan []byte
	queueMutex sync.Mutex
	queueFull  bool
}

func NewSSHTunnelManager(
	logger types.Logger,
	configManager types.ConfigManager,
	httpClient types.HTTPClient,
	mqttClient types.MQTTClient,
) *SSHTunnelManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &SSHTunnelManager{
		logger:        logger,
		configManager: configManager,
		httpClient:    httpClient,
		mqttClient:    mqttClient,
		channels:      make(map[string]*types.TunnelChannel),
		ctx:           ctx,
		cancel:        cancel,
		reconnectChan: make(chan struct{}, 1),
		sendQueue:     make(chan []byte, 1000), // Buffer for outgoing messages
	}
}

func (stm *SSHTunnelManager) StartTunnel(user string, expires time.Time) error {
	stm.logger.Infof("Starting SSH tunnel for user: %s, expires: %s", user, expires)

	stm.user = user
	stm.expires = expires
	stm.sessionID = generateSessionID()

	// Check if we should use MQTT or HTTP mode
	mode := stm.configManager.GetMode()

	if mode == "mqtt" {
		return stm.startMQTTTunnel()
	} else {
		return stm.startHTTPTunnel()
	}
}

func (stm *SSHTunnelManager) startMQTTTunnel() error {
	stm.logger.Info("Starting SSH tunnel via MQTT")

	// Reuse existing MQTT connection and add tunnel service
	// This would require extending the MQTT client to support tunnel messages
	// For now, we'll implement the HTTP tunnel approach

	return stm.startHTTPTunnel()
}

func (stm *SSHTunnelManager) startHTTPTunnel() error {
	stm.logger.Info("Starting SSH tunnel via HTTP WebSocket")

	deviceConfig := stm.configManager.GetDeviceConfig()
	tunnelURL := fmt.Sprintf("wss://%s/v1-device/tunnel", deviceConfig.HTTPSMTLSEndpoint)

	// Connect to tunnel WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(tunnelURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to tunnel: %w", err)
	}

	stm.wsConn = conn
	stm.isActive = true

	// Start ping ticker
	stm.pingTicker = time.NewTicker(PingInterval)

	// Start goroutines
	go stm.handleIncomingMessages()
	go stm.handleOutgoingMessages()
	go stm.pingLoop()
	go stm.cleanupExpiredChannels()
	go stm.handleReconnect()
	go stm.handleExpiration()

	stm.logger.Info("SSH tunnel started successfully")
	return nil
}

func (stm *SSHTunnelManager) StopTunnel() error {
	stm.logger.Info("Stopping SSH tunnel")

	stm.isActive = false

	if stm.pingTicker != nil {
		stm.pingTicker.Stop()
	}

	// Close all channels
	stm.channelsMutex.Lock()
	for _, channel := range stm.channels {
		if channel.LocalConn != nil {
			(*channel.LocalConn).Close()
		}
		channel.IsActive = false
	}
	stm.channels = make(map[string]*types.TunnelChannel)
	stm.channelsMutex.Unlock()

	// Close WebSocket connection
	if stm.wsConn != nil {
		stm.wsConn.Close()
	}

	stm.cancel()
	stm.logger.Info("SSH tunnel stopped")
	return nil
}

func (stm *SSHTunnelManager) IsTunnelActive() bool {
	return stm.isActive && stm.wsConn != nil
}

func (stm *SSHTunnelManager) HandleTunnelMessage(msg *types.TunnelMessage) error {
	switch msg.Type {
	case "open":
		return stm.handleOpenChannel(msg)
	case "data":
		return stm.handleChannelData(msg)
	case "eof":
		return stm.handleChannelEOF(msg)
	case "close":
		return stm.handleChannelClose(msg)
	case "resume":
		return stm.handleResumeSession(msg)
	default:
		stm.logger.Errorf("Unknown tunnel message type: %s", msg.Type)
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

func (stm *SSHTunnelManager) handleOpenChannel(msg *types.TunnelMessage) error {
	// Validate host and port (only allow 127.0.0.1:22)
	if msg.Host != AllowedHost || msg.Port != AllowedPort {
		stm.logger.Errorf("Rejected tunnel connection to %s:%d (only %s:%d allowed)",
			msg.Host, msg.Port, AllowedHost, AllowedPort)
		return stm.sendChannelClose(msg.Channel, "host/port not allowed")
	}

	// Connect to local SSH daemon
	localAddr := net.JoinHostPort(msg.Host, fmt.Sprintf("%d", msg.Port))
	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		stm.logger.Errorf("Failed to connect to local SSH: %v", err)
		return stm.sendChannelClose(msg.Channel, "failed to connect to local SSH")
	}

	// Create channel
	channel := &types.TunnelChannel{
		ID:           msg.Channel,
		LocalConn:    &conn,
		Buffer:       make([]byte, 0, MaxBufferSize),
		BufferSize:   0,
		IsActive:     true,
		LastActivity: time.Now(),
	}

	stm.channelsMutex.Lock()
	stm.channels[msg.Channel] = channel
	stm.channelsMutex.Unlock()

	// Start data forwarding
	go stm.forwardLocalToRemote(channel)
	go stm.forwardRemoteToLocal(channel)

	stm.logger.Infof("Opened tunnel channel %s to %s:%d", msg.Channel, msg.Host, msg.Port)
	return nil
}

func (stm *SSHTunnelManager) handleChannelData(msg *types.TunnelMessage) error {
	stm.channelsMutex.RLock()
	channel, exists := stm.channels[msg.Channel]
	stm.channelsMutex.RUnlock()

	if !exists {
		return fmt.Errorf("channel %s not found", msg.Channel)
	}

	// Decode base64 data
	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		return fmt.Errorf("failed to decode data: %w", err)
	}

	// Write to local connection
	if channel.LocalConn != nil {
		_, err = (*channel.LocalConn).Write(data)
		if err != nil {
			stm.logger.Errorf("Failed to write to local connection: %v", err)
			return stm.sendChannelClose(msg.Channel, "write failed")
		}
		channel.LastActivity = time.Now()
	}

	return nil
}

func (stm *SSHTunnelManager) handleChannelEOF(msg *types.TunnelMessage) error {
	stm.channelsMutex.RLock()
	channel, exists := stm.channels[msg.Channel]
	stm.channelsMutex.RUnlock()

	if !exists {
		return fmt.Errorf("channel %s not found", msg.Channel)
	}

	// Close local connection
	if channel.LocalConn != nil {
		(*channel.LocalConn).Close()
	}

	channel.IsActive = false
	stm.logger.Infof("Channel %s received EOF", msg.Channel)
	return nil
}

func (stm *SSHTunnelManager) handleChannelClose(msg *types.TunnelMessage) error {
	stm.channelsMutex.Lock()
	defer stm.channelsMutex.Unlock()

	channel, exists := stm.channels[msg.Channel]
	if !exists {
		return fmt.Errorf("channel %s not found", msg.Channel)
	}

	// Close local connection
	if channel.LocalConn != nil {
		(*channel.LocalConn).Close()
	}

	// Remove channel
	delete(stm.channels, msg.Channel)
	stm.logger.Infof("Channel %s closed: %s", msg.Channel, msg.Reason)
	return nil
}

func (stm *SSHTunnelManager) handleResumeSession(msg *types.TunnelMessage) error {
	stm.logger.Infof("Resuming session %s with channels: %v", msg.Session, msg.ChList)

	// Reconnect channels that were active
	for _, chID := range msg.ChList {
		// Reopen channel to local SSH
		conn, err := net.Dial("tcp", net.JoinHostPort(AllowedHost, fmt.Sprintf("%d", AllowedPort)))
		if err != nil {
			stm.logger.Errorf("Failed to resume channel %s: %v", chID, err)
			continue
		}

		channel := &types.TunnelChannel{
			ID:           chID,
			LocalConn:    &conn,
			Buffer:       make([]byte, 0, MaxBufferSize),
			BufferSize:   0,
			IsActive:     true,
			LastActivity: time.Now(),
		}

		stm.channelsMutex.Lock()
		stm.channels[chID] = channel
		stm.channelsMutex.Unlock()

		// Restart data forwarding
		go stm.forwardLocalToRemote(channel)
		go stm.forwardRemoteToLocal(channel)
	}

	return nil
}

func (stm *SSHTunnelManager) forwardLocalToRemote(channel *types.TunnelChannel) {
	buffer := make([]byte, 4096)

	for {
		select {
		case <-stm.ctx.Done():
			return
		default:
			if !channel.IsActive {
				return
			}

			// Read from local connection
			n, err := (*channel.LocalConn).Read(buffer)
			if err != nil {
				stm.logger.Errorf("Failed to read from local connection: %v", err)
				stm.sendChannelEOF(channel.ID)
				return
			}

			// Encode and send to remote
			data := base64.StdEncoding.EncodeToString(buffer[:n])
			msg := &types.TunnelMessage{
				Service: "tunnel",
				Type:    "data",
				Channel: channel.ID,
				Data:    data,
			}

			if err := stm.sendMessage(msg); err != nil {
				stm.logger.Errorf("Failed to send data to remote: %v", err)
				return
			}

			channel.LastActivity = time.Now()
		}
	}
}

func (stm *SSHTunnelManager) forwardRemoteToLocal(channel *types.TunnelChannel) {
	// This function is intentionally empty because remote-to-local data flow
	// is handled directly in handleChannelData when tunnel messages are received.
	// The WebSocket message handling loop calls handleChannelData which
	// writes the decoded data directly to the local connection.
	//
	// This design avoids the complexity of having a separate goroutine
	// that would need to coordinate with the message handling loop.
}

func (stm *SSHTunnelManager) handleIncomingMessages() {
	for {
		select {
		case <-stm.ctx.Done():
			return
		default:
			if stm.wsConn == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			var msg types.TunnelMessage
			err := stm.wsConn.ReadJSON(&msg)
			if err != nil {
				stm.logger.Errorf("Failed to read tunnel message: %v", err)
				stm.reconnectChan <- struct{}{}
				return
			}

			// Handle heartbeat
			if msg.Service == "hb" {
				if msg.Type == "ping" {
					stm.sendHeartbeat("pong")
				}
				continue
			}

			// Handle tunnel messages
			if msg.Service == "tunnel" {
				if err := stm.HandleTunnelMessage(&msg); err != nil {
					stm.logger.Errorf("Failed to handle tunnel message: %v", err)
				}
			}
		}
	}
}

func (stm *SSHTunnelManager) handleOutgoingMessages() {
	for {
		select {
		case <-stm.ctx.Done():
			return
		case msg := <-stm.sendQueue:
			if stm.wsConn == nil {
				continue
			}

			if err := stm.wsConn.WriteMessage(websocket.TextMessage, msg); err != nil {
				stm.logger.Errorf("Failed to send message: %v", err)
				stm.reconnectChan <- struct{}{}
				return
			}
		}
	}
}

func (stm *SSHTunnelManager) pingLoop() {
	for {
		select {
		case <-stm.ctx.Done():
			return
		case <-stm.pingTicker.C:
			if err := stm.sendHeartbeat("ping"); err != nil {
				stm.logger.Errorf("Failed to send ping: %v", err)
				stm.reconnectChan <- struct{}{}
			}
		}
	}
}

func (stm *SSHTunnelManager) cleanupExpiredChannels() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stm.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			stm.channelsMutex.Lock()

			for id, channel := range stm.channels {
				if now.Sub(channel.LastActivity) > 5*time.Minute {
					stm.logger.Infof("Cleaning up inactive channel: %s", id)
					if channel.LocalConn != nil {
						(*channel.LocalConn).Close()
					}
					delete(stm.channels, id)
				}
			}

			stm.channelsMutex.Unlock()
		}
	}
}

func (stm *SSHTunnelManager) handleReconnect() {
	for {
		select {
		case <-stm.ctx.Done():
			return
		case <-stm.reconnectChan:
			stm.logger.Info("Reconnection requested")
			if err := stm.Reconnect(); err != nil {
				stm.logger.Errorf("Failed to reconnect: %v", err)
				// Wait a bit before trying again
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func (stm *SSHTunnelManager) handleExpiration() {
	// Check for expiration every minute
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stm.ctx.Done():
			return
		case <-ticker.C:
			if time.Now().After(stm.expires) {
				stm.logger.Info("SSH tunnel expired, stopping tunnel")
				stm.StopTunnel()
				return
			}
		}
	}
}

func (stm *SSHTunnelManager) SendHeartbeat() error {
	return stm.sendHeartbeat("ping")
}

func (stm *SSHTunnelManager) sendHeartbeat(msgType string) error {
	msg := &types.TunnelMessage{
		Service: "hb",
		Type:    msgType,
	}
	return stm.sendMessage(msg)
}

func (stm *SSHTunnelManager) sendMessage(msg *types.TunnelMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	select {
	case stm.sendQueue <- data:
		// Reset back-pressure flag if it was set
		stm.queueMutex.Lock()
		if stm.queueFull {
			stm.queueFull = false
		}
		stm.queueMutex.Unlock()
		return nil
	default:
		// Queue is full, implement back-pressure
		stm.queueMutex.Lock()
		stm.queueFull = true
		stm.queueMutex.Unlock()
		return fmt.Errorf("send queue full")
	}
}

func (stm *SSHTunnelManager) sendChannelClose(channelID, reason string) error {
	msg := &types.TunnelMessage{
		Service: "tunnel",
		Type:    "close",
		Channel: channelID,
		Reason:  reason,
	}
	return stm.sendMessage(msg)
}

func (stm *SSHTunnelManager) sendChannelEOF(channelID string) error {
	msg := &types.TunnelMessage{
		Service: "tunnel",
		Type:    "eof",
		Channel: channelID,
	}
	return stm.sendMessage(msg)
}

func (stm *SSHTunnelManager) Reconnect() error {
	stm.logger.Info("Reconnecting SSH tunnel")

	// Close existing connection
	if stm.wsConn != nil {
		stm.wsConn.Close()
	}

	// Restart tunnel
	return stm.startHTTPTunnel()
}

func (stm *SSHTunnelManager) ResumeSession(sessionID string, channels []string) error {
	msg := &types.TunnelMessage{
		Service: "tunnel",
		Type:    "resume",
		Session: sessionID,
		ChList:  channels,
	}
	return stm.sendMessage(msg)
}

func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// HandleCustomCommand handles custom commands (those starting with "custom ")
func (stm *SSHTunnelManager) HandleCustomCommand(command string) error {
	// Parse command: "custom ssh user_456 2024-01-01T12:00:00Z"
	parts := strings.Fields(command)

	if len(parts) < 2 {
		return fmt.Errorf("invalid custom command format: %s", command)
	}

	// Check for SSH tunnel command
	if parts[1] == "ssh" {
		return stm.HandleSSHTunnelCommand(command)
	}

	// Add other custom command types here in the future
	return fmt.Errorf("unknown custom command type: %s", parts[1])
}

// HandleSSHTunnelCommand handles SSH tunnel commands
func (stm *SSHTunnelManager) HandleSSHTunnelCommand(command string) error {
	// Parse command: "custom ssh user_456 2024-01-01T12:00:00Z" or "ssh user123"
	parts := strings.Fields(command)

	var user string
	var expires time.Time
	var err error

	if len(parts) == 2 {
		// Format: "ssh user123" - use default expiration (1 hour from now)
		user = parts[1]
		expires = time.Now().Add(1 * time.Hour)
		stm.logger.Infof("Using default expiration time: %s", expires.Format(time.RFC3339))
	} else if len(parts) == 4 {
		// Format: "custom ssh user_456 2024-01-01T12:00:00Z"
		user = parts[2]
		expiresStr := parts[3]

		// Parse expiration time
		expires, err = time.Parse(time.RFC3339, expiresStr)
		if err != nil {
			return fmt.Errorf("invalid expiration time format: %s", expiresStr)
		}
	} else {
		return fmt.Errorf("invalid SSH tunnel command format: %s (expected 'ssh user123' or 'custom ssh user_456 2024-01-01T12:00:00Z')", command)
	}

	// Check if tunnel is already active
	if stm.IsTunnelActive() {
		stm.logger.Info("SSH tunnel already active, stopping existing tunnel")
		stm.StopTunnel()
	}

	// Start new tunnel
	stm.logger.Infof("Starting SSH tunnel for user: %s, expires: %s", user, expires)

	if err := stm.StartTunnel(user, expires); err != nil {
		return fmt.Errorf("failed to start SSH tunnel: %w", err)
	}

	stm.logger.Info("SSH tunnel started successfully")
	return nil
}
