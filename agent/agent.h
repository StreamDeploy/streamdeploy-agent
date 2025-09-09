#pragma once

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <nlohmann/json.hpp>

// Forward declarations
class ConfigManager;
class MetricsCollector;
class ContainerManager;
class PackageManager;
class HttpsClient;
class MqttClient;
class CertificateManager;

class Agent {
public:
    explicit Agent(const std::string& deviceConfigPath);
    ~Agent();

    void start();
    void stop();
    bool isRunning() const { return running_; }

private:
    // Core components
    std::unique_ptr<ConfigManager> config_manager_;
    std::unique_ptr<MetricsCollector> metrics_collector_;
    std::unique_ptr<ContainerManager> container_manager_;
    std::unique_ptr<PackageManager> package_manager_;
    std::unique_ptr<HttpsClient> https_client_;
    std::unique_ptr<MqttClient> mqtt_client_;
    std::unique_ptr<CertificateManager> cert_manager_;

    // Threading
    std::atomic<bool> running_;
    std::thread heartbeat_thread_;
    std::thread update_thread_;
    std::thread config_monitor_thread_;

    // Timing
    std::chrono::seconds heartbeat_interval_;
    std::chrono::seconds update_interval_;

    // Thread functions
    void heartbeatLoop();
    void updateLoop();
    void configMonitorLoop();

    // Core operations
    void sendHeartbeat();
    void performUpdateCheck();
    void handleConfigChange();
    void renewCertificateIfNeeded();
    void applyStateChanges(const nlohmann::json& old_state, const nlohmann::json& new_state);

    // Utility
    std::chrono::seconds parseFrequency(const std::string& freq);
    void logInfo(const std::string& message);
    void logError(const std::string& message);
};
