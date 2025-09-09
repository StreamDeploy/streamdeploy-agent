#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <nlohmann/json.hpp>

class ConfigManager {
public:
    using ConfigChangeCallback = std::function<void(const std::string& file_path)>;

    explicit ConfigManager(const std::string& device_config_path);
    ~ConfigManager();

    // Configuration access
    const nlohmann::json& getDeviceConfig() const { return device_config_; }
    const nlohmann::json& getStateConfig() const { return state_config_; }

    // Configuration updates
    void updateStateConfig(const nlohmann::json& new_state);
    void saveStateConfig();

    // Monitoring
    void startMonitoring();
    void stopMonitoring();
    void setConfigChangeCallback(ConfigChangeCallback callback);

    // Utility methods
    std::string getDeviceId() const;
    std::string getMode() const; // "http" or "mqtt"
    std::string getHeartbeatFrequency() const;
    std::string getUpdateFrequency() const;
    std::string getPkiDir() const;
    std::string getHttpsEndpoint() const;
    std::string getMqttEndpoint() const;

private:
    std::string device_config_path_;
    std::string state_config_path_;
    nlohmann::json device_config_;
    nlohmann::json state_config_;

    // inotify monitoring
    std::atomic<bool> monitoring_;
    std::thread monitor_thread_;
    int inotify_fd_;
    int device_watch_fd_;
    int state_watch_fd_;
    ConfigChangeCallback config_change_callback_;

    // Private methods
    void loadDeviceConfig();
    void loadStateConfig();
    void monitorLoop();
    void handleFileChange(const std::string& file_path);
    std::string getStateConfigPath() const;
};
