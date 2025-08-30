#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <nlohmann/json.hpp>

class HttpClient;

struct AgentConfig {
    // Identity & endpoints
    std::string deviceId;
    std::string deviceClass;     // "orin" | "xavier"| "pi"| "rk3588" | "coral" | "esp32"
    std::string baseUrl;         // e.g. https://api.streamdeploy.io
    std::string statusPath;      // /v1-device/status-update
    std::string heartbeatPath;   // /v1-device/heartbeat

    // Enrollment bootstrap + device plane
    std::string enrollBaseUrl;   // e.g. https://api.streamdeploy.com (plain TLS for enroll)
    std::string deviceBaseUrl;   // e.g. https://device.streamdeploy.com (mTLS device plane)
    std::string pkiDir = "/etc/streamdeploy/pki";
    bool        autoEnroll = true;

    // mTLS
    std::string caCertPath;      // CA bundle path
    std::string clientCertPath;  // PEM
    std::string clientKeyPath;   // PEM
    std::string clientKeyPass;   // optional

    // Logging (batched into status update)
    size_t      maxLogBuffer = 200;

    // App/service ports + health
    int         appPort  = 8080;   // current live app port inside container
    int         nextPort = 8081;   // staging port for new container
    std::string healthPath = "/healthz";
    int         healthWaitSeconds = 25;

    // Poll/heartbeat + enrollment
    int         heartbeatIntervalSeconds = 90;
    std::string bootstrapToken;   // optional; used until enrolled

    // Docker knobs
    std::string containerName = "sd-app";
    std::string extraDockerArgs = "--gpus all"; // Orin default; override per board
    std::string stateFile = "/var/lib/streamdeploy/state.json";

    // SSH tunnel configuration
    std::string sshBastionHost = "34.170.221.16";
    std::string sshBastionUser = "tonyloehr";
    int         sshBastionPort = 22;
    bool        sshTunnelEnabled = true;
    int         sshTunnelPort = 0; // Assigned by platform during enrollment
    std::string sshKeyPath;        // Device-specific SSH private key
    std::string sshPubKeyPath;     // Device-specific SSH public key

    // Secret file paths (for provisioning-time secret injection)
    std::string sshBastionHostFile;     // /etc/streamdeploy/secrets/ssh_bastion_host
    std::string sshBastionUserFile;     // /etc/streamdeploy/secrets/ssh_bastion_user
    std::string bootstrapTokenFile;     // /etc/streamdeploy/secrets/bootstrap_token
    std::string enrollBaseUrlFile;      // /etc/streamdeploy/secrets/enroll_base_url
    std::string deviceBaseUrlFile;      // /etc/streamdeploy/secrets/device_base_url

    static AgentConfig load(const std::string& path);

private:
    // Helper methods for secure secret loading
    static std::string loadSecretFromFile(const std::string& filePath, const std::string& fallbackValue, const std::string& secretName);
    static std::string readSecureFile(const std::string& filePath);
};

class Agent {
public:
    explicit Agent(const std::string& configPath);
    ~Agent();

    void tick(); // one full cycle
    void logInfo(const std::string& m);
    void logError(const std::string& m);
    int heartbeatIntervalSeconds() const { return cfg.heartbeatIntervalSeconds; }

private:
    AgentConfig cfg;
    std::string cfgPath;
    HttpClient* http;

    // buffered logs shipped in /v1-device/status-update
    std::vector<nlohmann::json> logBuf;
    std::chrono::steady_clock::time_point lastLogFlush;

    // helpers
    void flushLogsInto(nlohmann::json& statusPayload);
    nlohmann::json loadState();
    void saveState(const nlohmann::json& st);
    static std::string run(const std::string& cmd);
    bool urlHealthy(const std::string& url, int timeoutMs);
    void reinitHttp();
    void saveConfigJson();
    void performEnrollmentIfNeeded();
    void appendLogFile(const std::string& level, const std::string& m);

    // payload builders
    nlohmann::json buildDeviceFacts();
    nlohmann::json buildStatusUpdatePayload();
    
    // metrics collection
    nlohmann::json collectSystemMetrics();
    nlohmann::json collectContainerMetrics();
    nlohmann::json collectCustomMetrics();
    nlohmann::json collectEnvironmentVariables();
    nlohmann::json collectScripts();
    
    // heartbeat storage
    void saveHeartbeatData(const nlohmann::json& heartbeat);
    nlohmann::json loadLastHeartbeat();

    // actions from desired state
    void actOnDesired(const nlohmann::json& desired);
    void deployContainerAB(const std::string& image, const std::string& version,
                           const nlohmann::json& env, const std::string& args);
    void sendHeartbeat();

    // SSH tunnel management
    void setupSSHKeys();
    void establishSSHTunnel();
    void monitorSSHTunnelHealth();
    bool isSSHTunnelHealthy();
    void executeSSHCommand(const std::string& command);
    nlohmann::json getSSHStatus();
    void updateSSHState(nlohmann::json& currentState);

private:
    // SSH tunnel state
    bool sshTunnelActive = false;
    std::chrono::steady_clock::time_point lastSSHCheck;
    std::string sshTunnelPid;
};
