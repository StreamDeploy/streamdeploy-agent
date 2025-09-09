#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

struct ContainerInfo {
    std::string name;
    std::string image;
    int port;
    std::string health_path;
    nlohmann::json env;
    std::string status; // "running", "stopped", "unhealthy"
};

class ContainerManager {
public:
    ContainerManager();
    ~ContainerManager();

    // Container operations
    bool startContainer(const ContainerInfo& container);
    bool stopContainer(const std::string& name);
    bool restartContainer(const std::string& name);
    bool removeContainer(const std::string& name);

    // Container status and health
    std::vector<ContainerInfo> getRunningContainers();
    bool isContainerRunning(const std::string& name);
    bool isContainerHealthy(const ContainerInfo& container);
    std::string getContainerStatus(const std::string& name);

    // Health checks
    bool performHealthCheck(const ContainerInfo& container);
    bool areAllContainersHealthy(const std::vector<ContainerInfo>& containers);

    // Container management from state
    void ensureContainersRunning(const nlohmann::json& containers_config);
    void syncContainers(const nlohmann::json& desired_containers, 
                       const nlohmann::json& current_containers);

private:
    // Utility methods
    std::string executeDockerCommand(const std::string& command);
    bool httpHealthCheck(const std::string& url, int timeout_ms = 5000);
    std::string buildDockerRunCommand(const ContainerInfo& container);
    ContainerInfo parseContainerFromJson(const nlohmann::json& container_json);
    
    // Retry logic
    bool retryOperation(std::function<bool()> operation, int max_retries = 2);
};
