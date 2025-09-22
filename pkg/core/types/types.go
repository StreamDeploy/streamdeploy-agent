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

// VolumeMount represents a volume mount configuration
type VolumeMount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode,omitempty"` // "ro" for read-only, empty for read-write
}

// PortMapping represents a port mapping configuration
type PortMapping struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol,omitempty"` // "tcp", "udp", empty defaults to "tcp"
}

// ResourceLimit represents resource limit configuration
type ResourceLimit struct {
	Memory     string `json:"memory,omitempty"`      // e.g., "512m", "1g"
	CPUs       string `json:"cpus,omitempty"`        // e.g., "1.5", "2"
	MemorySwap string `json:"memory_swap,omitempty"` // e.g., "1g", "-1" for unlimited
	ShmSize    string `json:"shm_size,omitempty"`    // e.g., "64m"
}

// Ulimit represents a ulimit configuration
type Ulimit struct {
	Name string `json:"name"` // e.g., "nofile", "nproc"
	Soft int    `json:"soft"`
	Hard int    `json:"hard"`
}

// Device represents a device mapping configuration
type Device struct {
	PathOnHost      string `json:"path_on_host"`
	PathInContainer string `json:"path_in_container"`
	Permissions     string `json:"permissions,omitempty"` // e.g., "rwm"
}

// ContainerConfig represents a container configuration
type ContainerConfig struct {
	Name       string            `json:"name"`                  // Required: Container name
	Image      string            `json:"image"`                 // Required: Container image
	Ports      []PortMapping     `json:"ports,omitempty"`       // Optional: Multiple port support
	HealthPath string            `json:"health_path,omitempty"` // Optional: Health check path
	Env        map[string]string `json:"env,omitempty"`         // Optional: Environment variables
	EnvFile    string            `json:"env_file,omitempty"`    // Optional: Path to env file
	Volumes    []VolumeMount     `json:"volumes,omitempty"`     // Optional: Volume mounts
	WorkingDir string            `json:"working_dir,omitempty"` // Optional: Working directory
	User       string            `json:"user,omitempty"`        // Optional: User to run as
	Entrypoint []string          `json:"entrypoint,omitempty"`  // Optional: Entrypoint override
	Hostname   string            `json:"hostname,omitempty"`    // Optional: Container hostname
	Network    string            `json:"network,omitempty"`     // Optional: Network mode
	Restart    string            `json:"restart,omitempty"`     // Optional: Restart policy
	Resources  *ResourceLimit    `json:"resources,omitempty"`   // Optional: Resource limits
	Labels     map[string]string `json:"labels,omitempty"`      // Optional: Container labels
	Runtime    string            `json:"runtime,omitempty"`     // Optional: Container runtime
	IPC        string            `json:"ipc,omitempty"`         // Optional: IPC mode
	Ulimits    []Ulimit          `json:"ulimits,omitempty"`     // Optional: Ulimit settings
	Devices    []Device          `json:"devices,omitempty"`     // Optional: Device mappings
	Sysctls    map[string]string `json:"sysctls,omitempty"`     // Optional: Sysctl settings
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

// ContainerInfo represents container runtime information for health checks
type ContainerInfo struct {
	Name       string
	Port       int
	HealthPath string
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
	Debug(msg string)
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
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
	HandleDeviceConfigChange(isError bool)
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
	DetectCurrentState(desiredState *StateConfig) []ContainerConfig
	CompareStates(currentState, desiredState []ContainerConfig) ([]ContainerConfig, []ContainerConfig)
	Destroy(containers []ContainerConfig) error
	Create(containers []ContainerConfig) error
	StateConsolidation(currentState, desiredState []ContainerConfig) ([]ContainerConfig, error)
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
