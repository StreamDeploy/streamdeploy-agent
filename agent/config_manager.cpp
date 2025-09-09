#include "config_manager.h"
#include <fstream>
#include <filesystem>
#include <sys/inotify.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

namespace fs = std::filesystem;

ConfigManager::ConfigManager(const std::string& device_config_path)
    : device_config_path_(device_config_path)
    , monitoring_(false)
    , inotify_fd_(-1)
    , device_watch_fd_(-1)
    , state_watch_fd_(-1) {
    
    // Determine state config path based on device config location
    state_config_path_ = getStateConfigPath();
    
    // Load initial configurations
    loadDeviceConfig();
    loadStateConfig();
}

ConfigManager::~ConfigManager() {
    stopMonitoring();
}

void ConfigManager::loadDeviceConfig() {
    try {
        std::ifstream file(device_config_path_);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open device config: " + device_config_path_);
        }
        
        file >> device_config_;
        std::cout << "[ConfigManager] Loaded device config from " << device_config_path_ << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ConfigManager] Error loading device config: " << e.what() << std::endl;
        device_config_ = nlohmann::json::object();
    }
}

void ConfigManager::loadStateConfig() {
    try {
        if (!fs::exists(state_config_path_)) {
            std::cout << "[ConfigManager] State config not found, creating default: " << state_config_path_ << std::endl;
            state_config_ = nlohmann::json::object();
            saveStateConfig();
            return;
        }
        
        std::ifstream file(state_config_path_);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open state config: " + state_config_path_);
        }
        
        file >> state_config_;
        std::cout << "[ConfigManager] Loaded state config from " << state_config_path_ << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ConfigManager] Error loading state config: " << e.what() << std::endl;
        state_config_ = nlohmann::json::object();
    }
}

void ConfigManager::updateStateConfig(const nlohmann::json& new_state) {
    state_config_ = new_state;
    saveStateConfig();
}

void ConfigManager::saveStateConfig() {
    try {
        // Ensure directory exists
        fs::create_directories(fs::path(state_config_path_).parent_path());
        
        // Write atomically using temporary file
        std::string temp_path = state_config_path_ + ".tmp";
        {
            std::ofstream file(temp_path);
            if (!file.is_open()) {
                throw std::runtime_error("Cannot create temp state config: " + temp_path);
            }
            file << state_config_.dump(2);
        }
        
        // Atomic rename
        fs::rename(temp_path, state_config_path_);
        std::cout << "[ConfigManager] Saved state config to " << state_config_path_ << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ConfigManager] Error saving state config: " << e.what() << std::endl;
    }
}

void ConfigManager::startMonitoring() {
    if (monitoring_) {
        return;
    }
    
    // Initialize inotify
    inotify_fd_ = inotify_init1(IN_NONBLOCK);
    if (inotify_fd_ == -1) {
        std::cerr << "[ConfigManager] Failed to initialize inotify: " << strerror(errno) << std::endl;
        return;
    }
    
    // Watch device config file
    device_watch_fd_ = inotify_add_watch(inotify_fd_, device_config_path_.c_str(), 
                                        IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
    if (device_watch_fd_ == -1) {
        std::cerr << "[ConfigManager] Failed to watch device config: " << strerror(errno) << std::endl;
    }
    
    // Watch state config file (create parent directory if needed)
    fs::create_directories(fs::path(state_config_path_).parent_path());
    state_watch_fd_ = inotify_add_watch(inotify_fd_, state_config_path_.c_str(), 
                                       IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
    if (state_watch_fd_ == -1) {
        std::cerr << "[ConfigManager] Failed to watch state config: " << strerror(errno) << std::endl;
    }
    
    monitoring_ = true;
    monitor_thread_ = std::thread(&ConfigManager::monitorLoop, this);
    
    std::cout << "[ConfigManager] Started monitoring config files" << std::endl;
}

void ConfigManager::stopMonitoring() {
    if (!monitoring_) {
        return;
    }
    
    monitoring_ = false;
    
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    
    if (inotify_fd_ != -1) {
        close(inotify_fd_);
        inotify_fd_ = -1;
    }
    
    std::cout << "[ConfigManager] Stopped monitoring config files" << std::endl;
}

void ConfigManager::setConfigChangeCallback(ConfigChangeCallback callback) {
    config_change_callback_ = callback;
}

void ConfigManager::monitorLoop() {
    const size_t EVENT_SIZE = sizeof(struct inotify_event);
    const size_t BUF_LEN = 1024 * (EVENT_SIZE + 16);
    char buffer[BUF_LEN];
    
    while (monitoring_) {
        ssize_t length = read(inotify_fd_, buffer, BUF_LEN);
        
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No events available, sleep briefly
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            } else {
                std::cerr << "[ConfigManager] Error reading inotify events: " << strerror(errno) << std::endl;
                break;
            }
        }
        
        // Process events
        ssize_t i = 0;
        while (i < length) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];
            
            if (event->wd == device_watch_fd_) {
                std::cout << "[ConfigManager] Device config file changed" << std::endl;
                handleFileChange(device_config_path_);
            } else if (event->wd == state_watch_fd_) {
                std::cout << "[ConfigManager] State config file changed" << std::endl;
                handleFileChange(state_config_path_);
            }
            
            i += EVENT_SIZE + event->len;
        }
    }
}

void ConfigManager::handleFileChange(const std::string& file_path) {
    // Reload the changed file
    if (file_path == device_config_path_) {
        loadDeviceConfig();
    } else if (file_path == state_config_path_) {
        loadStateConfig();
    }
    
    // Notify callback if set
    if (config_change_callback_) {
        config_change_callback_(file_path);
    }
}

std::string ConfigManager::getStateConfigPath() const {
    // If device config is in /etc/streamdeploy/, put state config there too
    fs::path device_path(device_config_path_);
    fs::path parent_dir = device_path.parent_path();
    
    if (parent_dir == "/etc/streamdeploy") {
        return "/etc/streamdeploy/state.json";
    }
    
    // Otherwise, put it in the same directory as device config
    return (parent_dir / "state.json").string();
}

// Utility methods
std::string ConfigManager::getDeviceId() const {
    return device_config_.value("device_id", "unknown");
}

std::string ConfigManager::getMode() const {
    return state_config_.value("agent_setting", nlohmann::json::object()).value("mode", "http");
}

std::string ConfigManager::getHeartbeatFrequency() const {
    return state_config_.value("agent_setting", nlohmann::json::object()).value("heartbeat_frequency", "15s");
}

std::string ConfigManager::getUpdateFrequency() const {
    return state_config_.value("agent_setting", nlohmann::json::object()).value("update_frequency", "30s");
}

std::string ConfigManager::getPkiDir() const {
    return device_config_.value("pki_dir", "/etc/streamdeploy/pki");
}

std::string ConfigManager::getHttpsEndpoint() const {
    return device_config_.value("https_mtls_endpoint", "https://device.streamdeploy.com");
}

std::string ConfigManager::getMqttEndpoint() const {
    return device_config_.value("mqtt_ws_mtls_endpoint", "https://mqtt.streamdeploy.com");
}
