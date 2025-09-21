package types

import (
	"context"
	"net"
	"time"
)

// DeviceConfig represents the device configuration
type DeviceConfig struct {
	DeviceID           string `json:"device_id"`
	EnrollBaseURL      string `json:"enroll_base_url"`
	HTTPSMTLSEndpoint  string `json:"https_mtls_endpoint"`
	MQTTWSMTLSEndpoint string `json:"mqtt_ws_mtls_endpoint"`
	PKIDir             string `json:"pki_dir"`
	OSName             string `json:"os_name"`
	OSVersion          string `json:"os_version"`
	Architecture       string `json:"architecture"`
	MachineType        string `json:"machine_type"`
}

// PackageManagerConfig represents package manager configuration
type PackageManagerConfig struct {
	Type       string `json:"type"`
	InstallCmd string `json:"install_cmd"`
	CheckCmd   string `json:"check_cmd"`
	RemoveCmd  string `json:"remove_cmd"`
}

// StateConfig represents the state configuration
type StateConfig struct {
	SchemaVersion  string                   `json:"schemaVersion"`
	AgentSetting   AgentSetting             `json:"agent_setting"`
	Containers     []ContainerConfig        `json:"containers"`
	Env            map[string]string        `json:"env"`
	Packages       []string                 `json:"packages"`
	CustomMetrics  map[string]string        `json:"custom_metrics"`
	CustomPackages map[string]CustomPackage `json:"custom_packages"`
}

// AgentSetting represents agent configuration settings
type AgentSetting struct {
	HeartbeatFrequency string `json:"heartbeat_frequency"`
	UpdateFrequency    string `json:"update_frequency"`
	Mode               string `json:"mode"` // "http" or "mqtt"
	AgentVer           string `json:"agent_ver"`
	LoggingLevel       string `json:"logging_level"`
}

// ContainerConfig represents a container configuration
type ContainerConfig struct {
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	Port       int               `json:"port"`
	HealthPath string            `json:"health_path"`
	Env        map[string]string `json:"env"`
}

// CustomPackage represents a custom package installation
type CustomPackage struct {
	Install   string `json:"install"`
	Check     string `json:"check"`
	Uninstall string `json:"uninstall"`
}

// SystemMetrics represents system metrics
type SystemMetrics struct {
	CPUPercent  float64                `json:"cpu_pct"`
	MemPercent  float64                `json:"mem_pct"`
	DiskPercent float64                `json:"disk_pct"`
	SwapPercent float64                `json:"swap_pct,omitempty"`
	Custom      map[string]interface{} `json:"custom,omitempty"`
}

// HeartbeatPayload represents the heartbeat message
type HeartbeatPayload struct {
	Status       string                 `json:"status"`
	AgentSetting AgentSetting           `json:"agent_setting"`
	Metrics      map[string]interface{} `json:"metrics"`
}

// StatusUpdatePayload represents a status update message
type StatusUpdatePayload struct {
	UpdateType   string      `json:"update_type"`
	CurrentState StateConfig `json:"current_state"`
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode int
	Body       []byte
	Headers    map[string]string
}

// ContainerInfo represents container runtime information
type ContainerInfo struct {
	Name       string
	Image      string
	Port       int
	HealthPath string
	Running    bool
	Healthy    bool
}

// CertificateInfo represents certificate information
type CertificateInfo struct {
	CertPath   string
	KeyPath    string
	CACertPath string
	ExpiresAt  time.Time
}

// Logger interface for logging
type Logger interface {
	Info(msg string)
	Error(msg string)
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// ConfigManager interface for configuration management
type ConfigManager interface {
	GetDeviceConfig() *DeviceConfig
	GetStateConfig() *StateConfig
	UpdateStateConfig(config *StateConfig) error
	SaveStateConfig() error
	StartMonitoring() error
	StopMonitoring()
	SetConfigChangeCallback(callback func(string))
	GetMode() string
	GetDeviceID() string
	GetHeartbeatFrequency() time.Duration
	GetStatusFrequency() time.Duration
	ReloadStateConfig() error
	GetDeviceConfigPath() string
	RestartMonitoring()
	IsStateConfigEmpty(config *StateConfig) bool
	HandleConfigChange(filePath string)
	SetAgent(agent interface{})
	HandleStateConfigChange(isError bool)
}

// MetricsCollector interface for metrics collection
type MetricsCollector interface {
	CollectSystemMetrics() (*SystemMetrics, error)
	CollectCustomMetrics(commands map[string]string) (map[string]interface{}, error)
	DetermineSystemStatus(cpuPct, memPct, diskPct float64, containersHealthy bool) string
}

// HTTPClient interface for HTTP communication
type HTTPClient interface {
	SendHeartbeat(payload *HeartbeatPayload, deviceID string) (*HTTPResponse, error)
	SendStatusUpdate(payload *StatusUpdatePayload, deviceID string) (*HTTPResponse, error)
	Post(url string, data []byte, headers map[string]string) (*HTTPResponse, error)
	Get(url string, headers map[string]string) (*HTTPResponse, error)
}

// MQTTClient interface for MQTT communication
type MQTTClient interface {
	Connect() error
	Disconnect()
	IsConnected() bool
	PublishHeartbeat(payload *HeartbeatPayload) error
	PublishStatusUpdate(payload *StatusUpdatePayload) error
	Subscribe(topic string, callback func([]byte)) error
}

// ContainerManager interface for container management
type ContainerManager interface {
	IsContainerRunning(name string) bool
	StartContainer(config *ContainerConfig) error
	StopContainer(name string) error
	EnsureContainersRunning(configs []ContainerConfig) error
	PerformHealthCheck(container *ContainerInfo) bool
	SyncContainers(newConfigs, oldConfigs []ContainerConfig) (bool, error)
	CheckContainerDrift(configs []ContainerConfig) (bool, []ContainerConfig)
	GetRunningContainers() ([]ContainerConfig, error)
	GetCurrentContainerState(desiredState *StateConfig) []ContainerConfig
}

// SystemPackageManager interface for system package management
type SystemPackageManager interface {
	DetectCurrentState(desiredState *StateConfig) []string
	CompareStates(currentState, desiredState []string) ([]string, []string)
	Destroy(packages []string) error
	Create(packages []string) error
	StateConsolidation(currentState, desiredState []string) ([]string, error)
}

// CustomPackageManager interface for custom package management
type CustomPackageManager interface {
	DetectCurrentState(desiredState *StateConfig) map[string]CustomPackage
	CompareStates(currentState, desiredState map[string]CustomPackage) (map[string]CustomPackage, map[string]CustomPackage)
	Destroy(packages map[string]CustomPackage) ([]string, error)
	Create(packages map[string]CustomPackage) ([]string, error)
	StateConsolidation(currentState, desiredState map[string]CustomPackage) (map[string]CustomPackage, error)
}

// CertificateManager interface for certificate management
type CertificateManager interface {
	GetCertificateInfo() (*CertificateInfo, error)
	IsCertificateExpiringSoon(days int) bool
	RenewCertificate(deviceID, enrollEndpoint string) error
	GetCACertificatePath() string
	GetCertificatePath() string
	GetPrivateKeyPath() string
	StartCertificateCheckLoop(ctx context.Context, interval time.Duration)
}

// EnvironmentManager interface for system environment management
type EnvironmentManager interface {
	SyncSystemEnvironment(envVars map[string]string) error
	GetCurrentSystemEnvironment() (map[string]string, error)
	RemoveSystemEnvironment() error
}

// SSH Tunnel related types
type SSHTunnelCommand struct {
	Command string `json:"command"`
	User    string `json:"user"`
	Expires string `json:"expires"`
}

type TunnelMessage struct {
	Service string   `json:"svc"`
	Type    string   `json:"t"`
	Channel string   `json:"ch,omitempty"`
	Host    string   `json:"host,omitempty"`
	Port    int      `json:"port,omitempty"`
	Data    string   `json:"b64,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Session string   `json:"session,omitempty"`
	ChList  []string `json:"ch_list,omitempty"`
}

type TunnelChannel struct {
	ID           string
	LocalConn    *net.Conn
	RemoteConn   interface{} // Will be *websocket.Conn in implementation
	Buffer       []byte
	BufferSize   int
	IsActive     bool
	LastActivity time.Time
}

// SSHTunnelManager interface for SSH tunnel management
type SSHTunnelManager interface {
	StartTunnel(user string, expires time.Time) error
	StopTunnel() error
	IsTunnelActive() bool
	HandleTunnelMessage(msg *TunnelMessage) error
	SendHeartbeat() error
	Reconnect() error
	ResumeSession(sessionID string, channels []string) error
	HandleCustomCommand(command string) error
	HandleSSHTunnelCommand(command string) error
}
