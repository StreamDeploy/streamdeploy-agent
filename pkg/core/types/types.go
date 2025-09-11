package types

import (
	"time"
)

// DeviceConfig represents the device configuration
type DeviceConfig struct {
	DeviceID           string               `json:"device_id"`
	EnrollBaseURL      string               `json:"enroll_base_url"`
	HTTPSMTLSEndpoint  string               `json:"https_mtls_endpoint"`
	MQTTWSMTLSEndpoint string               `json:"mqtt_ws_mtls_endpoint"`
	PKIDir             string               `json:"pki_dir"`
	OSName             string               `json:"os_name"`
	OSVersion          string               `json:"os_version"`
	Architecture       string               `json:"architecture"`
	PackageManager     PackageManagerConfig `json:"package_manager"`
}

// PackageManagerConfig represents package manager configuration
type PackageManagerConfig struct {
	Type       string `json:"type"`
	InstallCmd string `json:"install_cmd"`
	CheckCmd   string `json:"check_cmd"`
	RemoveCmd  string `json:"remove_cmd"`
	UpdateCmd  string `json:"update_cmd"`
}

// StateConfig represents the state configuration
type StateConfig struct {
	SchemaVersion  string                   `json:"schemaVersion"`
	AgentSetting   AgentSetting             `json:"agent_setting"`
	Containers     []ContainerConfig        `json:"containers"`
	ContainerLogin string                   `json:"containerLogin"`
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
	GetUpdateFrequency() time.Duration
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
	SyncContainers(newConfigs, oldConfigs []ContainerConfig) error
}

// PackageManager interface for package management
type PackageManager interface {
	IsPackageInstalled(packageName string) bool
	InstallPackage(packageName string) error
	RemovePackage(packageName string) error
	EnsurePackagesInstalled(packages []string) error
	EnsureCustomPackagesInstalled(packages map[string]CustomPackage) error
	SyncPackages(newPackages, oldPackages []string) error
	SyncCustomPackages(newPackages, oldPackages map[string]CustomPackage) error
}

// CertificateManager interface for certificate management
type CertificateManager interface {
	GetCertificateInfo() (*CertificateInfo, error)
	IsCertificateExpiringSoon(days int) bool
	RenewCertificate(deviceID, enrollEndpoint string) error
	GetCACertificatePath() string
	GetCertificatePath() string
	GetPrivateKeyPath() string
}
