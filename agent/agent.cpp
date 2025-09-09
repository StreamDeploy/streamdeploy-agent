#include "agent.h"
#include "config_manager.h"
#include "metrics_collector.h"
#include "container_manager.h"
#include "package_manager.h"
#include "https_client.h"
#include "mqtt_client.h"
#include "certificate_manager.h"
#include <iostream>
#include <regex>
#include <map>

Agent::Agent(const std::string& deviceConfigPath) 
    : running_(false) {
    
    try {
        // Initialize core components
        config_manager_ = std::make_unique<ConfigManager>(deviceConfigPath);
        metrics_collector_ = std::make_unique<MetricsCollector>();
        container_manager_ = std::make_unique<ContainerManager>();
        package_manager_ = std::make_unique<PackageManager>(config_manager_->getDeviceConfig());
        cert_manager_ = std::make_unique<CertificateManager>(config_manager_->getPkiDir());
        
        // Initialize communication clients based on mode
        std::string mode = config_manager_->getMode();
        if (mode == "http" || mode == "https") {
            https_client_ = std::make_unique<HttpsClient>(
                config_manager_->getHttpsEndpoint(),
                cert_manager_->getCACertificatePath(),
                cert_manager_->getCertificatePath(),
                cert_manager_->getPrivateKeyPath()
            );
        } else if (mode == "mqtt") {
            mqtt_client_ = std::make_unique<MqttClient>(
                config_manager_->getMqttEndpoint(),
                cert_manager_->getCACertificatePath(),
                cert_manager_->getCertificatePath(),
                cert_manager_->getPrivateKeyPath(),
                config_manager_->getDeviceId()
            );
        }
        
        // Parse timing intervals
        heartbeat_interval_ = parseFrequency(config_manager_->getHeartbeatFrequency());
        update_interval_ = parseFrequency(config_manager_->getUpdateFrequency());
        
        // Set up config change callback
        config_manager_->setConfigChangeCallback([this](const std::string& file_path) {
            handleConfigChange();
        });
        
        logInfo("Agent initialized successfully");
        
    } catch (const std::exception& e) {
        logError("Failed to initialize agent: " + std::string(e.what()));
        throw;
    }
}

Agent::~Agent() {
    stop();
}

void Agent::start() {
    if (running_) {
        logInfo("Agent is already running");
        return;
    }
    
    logInfo("Starting StreamDeploy agent");
    running_ = true;
    
    // Start config monitoring
    config_manager_->startMonitoring();
    
    // Start worker threads
    heartbeat_thread_ = std::thread(&Agent::heartbeatLoop, this);
    update_thread_ = std::thread(&Agent::updateLoop, this);
    config_monitor_thread_ = std::thread(&Agent::configMonitorLoop, this);
    
    logInfo("Agent started successfully");
}

void Agent::stop() {
    if (!running_) {
        return;
    }
    
    logInfo("Stopping StreamDeploy agent");
    running_ = false;
    
    // Stop config monitoring
    config_manager_->stopMonitoring();
    
    // Wait for threads to finish
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    if (update_thread_.joinable()) {
        update_thread_.join();
    }
    if (config_monitor_thread_.joinable()) {
        config_monitor_thread_.join();
    }
    
    logInfo("Agent stopped");
}

void Agent::heartbeatLoop() {
    logInfo("Heartbeat loop started with interval: " + std::to_string(heartbeat_interval_.count()) + "s");
    
    while (running_) {
        try {
            sendHeartbeat();
        } catch (const std::exception& e) {
            logError("Heartbeat failed: " + std::string(e.what()));
        }
        
        // Sleep for the heartbeat interval
        auto start = std::chrono::steady_clock::now();
        while (running_ && (std::chrono::steady_clock::now() - start) < heartbeat_interval_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    logInfo("Heartbeat loop stopped");
}

void Agent::updateLoop() {
    logInfo("Update loop started with interval: " + std::to_string(update_interval_.count()) + "s");
    
    while (running_) {
        try {
            performUpdateCheck();
            renewCertificateIfNeeded();
        } catch (const std::exception& e) {
            logError("Update check failed: " + std::string(e.what()));
        }
        
        // Sleep for the update interval
        auto start = std::chrono::steady_clock::now();
        while (running_ && (std::chrono::steady_clock::now() - start) < update_interval_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    logInfo("Update loop stopped");
}

void Agent::configMonitorLoop() {
    logInfo("Config monitor loop started");
    
    while (running_) {
        // This loop just keeps the thread alive
        // Actual config monitoring is handled by inotify in ConfigManager
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    logInfo("Config monitor loop stopped");
}

void Agent::sendHeartbeat() {
    try {
        // Collect system metrics
        auto system_metrics = metrics_collector_->collectSystemMetrics();
        auto custom_metrics = metrics_collector_->collectCustomMetrics(
            config_manager_->getStateConfig().value("custom_metrics", nlohmann::json::object())
        );
        
        // Check container health
        auto containers_config = config_manager_->getStateConfig().value("containers", nlohmann::json::array());
        bool containers_healthy = true;
        
        for (const auto& container_json : containers_config) {
            if (container_json.contains("name") && container_json.contains("health_path")) {
                std::string name = container_json["name"];
                std::string health_path = container_json["health_path"];
                
                if (!container_manager_->isContainerRunning(name)) {
                    containers_healthy = false;
                    break;
                }
                
                // Perform health check if health_path is provided
                if (!health_path.empty()) {
                    // Build container info for health check
                    ContainerInfo container;
                    container.name = name;
                    container.health_path = health_path;
                    container.port = container_json.value("port", 80);
                    
                    if (!container_manager_->performHealthCheck(container)) {
                        containers_healthy = false;
                        break;
                    }
                }
            }
        }
        
        // Determine system status
        std::string status = metrics_collector_->determineSystemStatus(
            system_metrics.value("cpu_pct", 0.0),
            system_metrics.value("mem_pct", 0.0),
            system_metrics.value("disk_pct", 0.0),
            containers_healthy
        );
        
        // Build heartbeat payload
        nlohmann::json heartbeat;
        heartbeat["status"] = status;
        heartbeat["agent_setting"] = config_manager_->getStateConfig().value("agent_setting", nlohmann::json::object());
        
        nlohmann::json metrics;
        metrics["cpu_pct"] = system_metrics.value("cpu_pct", 0.0);
        metrics["mem_pct"] = system_metrics.value("mem_pct", 0.0);
        metrics["disk_pct"] = system_metrics.value("disk_pct", 0.0);
        
        // Add custom metrics
        for (const auto& [key, value] : custom_metrics.items()) {
            metrics[key] = value;
        }
        
        heartbeat["metrics"] = metrics;
        
        // Send heartbeat based on mode
        std::string mode = config_manager_->getMode();
        if (mode == "http" || mode == "https") {
            if (https_client_) {
                auto response = https_client_->sendHeartbeat(heartbeat, config_manager_->getDeviceId());
                if (response.status_code >= 200 && response.status_code < 300) {
                    logInfo("Heartbeat sent successfully");
                } else {
                    logError("Heartbeat failed with status: " + std::to_string(response.status_code));
                }
            }
        } else if (mode == "mqtt") {
            if (mqtt_client_ && mqtt_client_->isConnected()) {
                if (mqtt_client_->publishHeartbeat(heartbeat)) {
                    logInfo("Heartbeat published successfully");
                } else {
                    logError("Failed to publish heartbeat");
                }
            }
        }
        
    } catch (const std::exception& e) {
        logError("Error in sendHeartbeat: " + std::string(e.what()));
    }
}

void Agent::performUpdateCheck() {
    try {
        auto state_config = config_manager_->getStateConfig();
        
        // 1. Ensure containers are running
        auto containers_config = state_config.value("containers", nlohmann::json::array());
        container_manager_->ensureContainersRunning(containers_config);
        
        // 2. Ensure packages are installed
        auto packages = state_config.value("packages", nlohmann::json::array());
        std::vector<std::string> package_list;
        for (const auto& pkg : packages) {
            if (pkg.is_string()) {
                package_list.push_back(pkg.get<std::string>());
            }
        }
        package_manager_->ensurePackagesInstalled(package_list);
        
        // 3. Ensure custom packages are installed
        auto custom_packages = state_config.value("custom_packages", nlohmann::json::object());
        package_manager_->ensureCustomPackagesInstalled(custom_packages);
        
        // 4. Send status update to get new state
        nlohmann::json status_update;
        status_update["update_type"] = "update_check";
        status_update["current_state"] = state_config;
        
        std::string mode = config_manager_->getMode();
        if (mode == "http" || mode == "https") {
            if (https_client_) {
                auto response = https_client_->sendStatusUpdate(status_update, config_manager_->getDeviceId());
                if (response.status_code >= 200 && response.status_code < 300) {
                    logInfo("Status update sent successfully");
                    
                    // Parse response for new state
                    if (!response.body.empty()) {
                        try {
                            auto response_json = nlohmann::json::parse(response.body);
                            if (response_json.contains("new_state")) {
                                auto new_state = response_json["new_state"];
                                
                                // Compare and update state if different
                                if (new_state != state_config) {
                                    logInfo("Received new state configuration");
                                    config_manager_->updateStateConfig(new_state);
                                    
                                    // Apply changes
                                    applyStateChanges(state_config, new_state);
                                }
                            }
                        } catch (const std::exception& e) {
                            logError("Error parsing status update response: " + std::string(e.what()));
                        }
                    }
                } else {
                    logError("Status update failed with status: " + std::to_string(response.status_code));
                }
            }
        } else if (mode == "mqtt") {
            if (mqtt_client_ && mqtt_client_->isConnected()) {
                if (mqtt_client_->publishStatusUpdate(status_update)) {
                    logInfo("Status update published successfully");
                } else {
                    logError("Failed to publish status update");
                }
            }
        }
        
    } catch (const std::exception& e) {
        logError("Error in performUpdateCheck: " + std::string(e.what()));
    }
}

void Agent::applyStateChanges(const nlohmann::json& old_state, const nlohmann::json& new_state) {
    try {
        // Compare containers
        auto old_containers = old_state.value("containers", nlohmann::json::array());
        auto new_containers = new_state.value("containers", nlohmann::json::array());
        if (old_containers != new_containers) {
            logInfo("Container configuration changed, syncing...");
            container_manager_->syncContainers(new_containers, old_containers);
        }
        
        // Compare packages
        auto old_packages = old_state.value("packages", nlohmann::json::array());
        auto new_packages = new_state.value("packages", nlohmann::json::array());
        if (old_packages != new_packages) {
            logInfo("Package configuration changed, syncing...");
            std::vector<std::string> old_pkg_list, new_pkg_list;
            for (const auto& pkg : old_packages) {
                if (pkg.is_string()) old_pkg_list.push_back(pkg.get<std::string>());
            }
            for (const auto& pkg : new_packages) {
                if (pkg.is_string()) new_pkg_list.push_back(pkg.get<std::string>());
            }
            package_manager_->syncPackages(new_pkg_list, old_pkg_list);
        }
        
        // Compare custom packages
        auto old_custom = old_state.value("custom_packages", nlohmann::json::object());
        auto new_custom = new_state.value("custom_packages", nlohmann::json::object());
        if (old_custom != new_custom) {
            logInfo("Custom package configuration changed, syncing...");
            package_manager_->syncCustomPackages(new_custom, old_custom);
        }
        
    } catch (const std::exception& e) {
        logError("Error applying state changes: " + std::string(e.what()));
    }
}

void Agent::handleConfigChange() {
    try {
        logInfo("Configuration changed, reloading...");
        
        // Update timing intervals
        heartbeat_interval_ = parseFrequency(config_manager_->getHeartbeatFrequency());
        update_interval_ = parseFrequency(config_manager_->getUpdateFrequency());
        
        // Reinitialize clients if needed
        std::string mode = config_manager_->getMode();
        if (mode == "http" || mode == "https") {
            if (!https_client_) {
                https_client_ = std::make_unique<HttpsClient>(
                    config_manager_->getHttpsEndpoint(),
                    cert_manager_->getCACertificatePath(),
                    cert_manager_->getCertificatePath(),
                    cert_manager_->getPrivateKeyPath()
                );
            } else {
                https_client_->updateCertificates(
                    cert_manager_->getCACertificatePath(),
                    cert_manager_->getCertificatePath(),
                    cert_manager_->getPrivateKeyPath()
                );
            }
        } else if (mode == "mqtt") {
            if (!mqtt_client_) {
                mqtt_client_ = std::make_unique<MqttClient>(
                    config_manager_->getMqttEndpoint(),
                    cert_manager_->getCACertificatePath(),
                    cert_manager_->getCertificatePath(),
                    cert_manager_->getPrivateKeyPath(),
                    config_manager_->getDeviceId()
                );
            }
        }
        
        logInfo("Configuration reloaded successfully");
        
    } catch (const std::exception& e) {
        logError("Error handling config change: " + std::string(e.what()));
    }
}

void Agent::renewCertificateIfNeeded() {
    try {
        if (cert_manager_->isCertificateExpiringSoon(30)) { // 30 days threshold
            logInfo("Certificate is expiring soon, attempting renewal...");
            
            std::string device_id = config_manager_->getDeviceId();
            std::string enroll_endpoint = config_manager_->getHttpsEndpoint() + "/v1-device/enroll/renew";
            
            if (cert_manager_->renewCertificate(device_id, enroll_endpoint)) {
                logInfo("Certificate renewed successfully");
                
                // Update HTTPS client with new certificates
                if (https_client_) {
                    https_client_->updateCertificates(
                        cert_manager_->getCACertificatePath(),
                        cert_manager_->getCertificatePath(),
                        cert_manager_->getPrivateKeyPath()
                    );
                }
            } else {
                logError("Certificate renewal failed");
            }
        }
    } catch (const std::exception& e) {
        logError("Error checking certificate renewal: " + std::string(e.what()));
    }
}

std::chrono::seconds Agent::parseFrequency(const std::string& freq) {
    static const std::map<char, int> multipliers = {
        {'s', 1},        // seconds
        {'m', 60},       // minutes
        {'h', 3600},     // hours
        {'d', 86400},    // days
        {'w', 604800},   // weeks
        {'M', 2592000},  // months (30 days)
        {'y', 31536000}  // years (365 days)
    };
    
    std::regex freq_regex(R"((\d+)([smhdwMy]))");
    std::smatch match;
    
    if (std::regex_match(freq, match, freq_regex)) {
        int value = std::stoi(match[1].str());
        char unit = match[2].str()[0];
        
        auto it = multipliers.find(unit);
        if (it != multipliers.end()) {
            return std::chrono::seconds(value * it->second);
        }
    }
    
    // Default fallback
    logError("Invalid frequency format: " + freq + ", using default 15s");
    return std::chrono::seconds(15);
}

void Agent::logInfo(const std::string& message) {
    std::cout << "[INFO] " << message << std::endl;
}

void Agent::logError(const std::string& message) {
    std::cerr << "[ERROR] " << message << std::endl;
}
