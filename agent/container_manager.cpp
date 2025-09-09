#include "container_manager.h"
#include <iostream>
#include <sstream>
#include <array>
#include <memory>
#include <curl/curl.h>
#include <algorithm>
#include <thread>
#include <chrono>

ContainerManager::ContainerManager() {
}

ContainerManager::~ContainerManager() {
}

bool ContainerManager::startContainer(const ContainerInfo& container) {
    try {
        std::string run_command = buildDockerRunCommand(container);
        std::string result = executeDockerCommand(run_command);
        
        if (result.find("Error") != std::string::npos || result.find("error") != std::string::npos) {
            std::cerr << "[ContainerManager] Error starting container " << container.name << ": " << result << std::endl;
            return false;
        }
        
        std::cout << "[ContainerManager] Started container: " << container.name << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[ContainerManager] Exception starting container " << container.name << ": " << e.what() << std::endl;
        return false;
    }
}

bool ContainerManager::stopContainer(const std::string& name) {
    try {
        std::string command = "docker stop " + name;
        std::string result = executeDockerCommand(command);
        
        std::cout << "[ContainerManager] Stopped container: " << name << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[ContainerManager] Error stopping container " << name << ": " << e.what() << std::endl;
        return false;
    }
}

bool ContainerManager::restartContainer(const std::string& name) {
    try {
        std::string command = "docker restart " + name;
        std::string result = executeDockerCommand(command);
        
        std::cout << "[ContainerManager] Restarted container: " << name << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[ContainerManager] Error restarting container " << name << ": " << e.what() << std::endl;
        return false;
    }
}

bool ContainerManager::removeContainer(const std::string& name) {
    try {
        // Stop first, then remove
        executeDockerCommand("docker stop " + name + " 2>/dev/null || true");
        std::string command = "docker rm -f " + name;
        std::string result = executeDockerCommand(command);
        
        std::cout << "[ContainerManager] Removed container: " << name << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[ContainerManager] Error removing container " << name << ": " << e.what() << std::endl;
        return false;
    }
}

std::vector<ContainerInfo> ContainerManager::getRunningContainers() {
    std::vector<ContainerInfo> containers;
    
    try {
        std::string command = "docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'";
        std::string result = executeDockerCommand(command);
        
        std::istringstream stream(result);
        std::string line;
        
        while (std::getline(stream, line)) {
            if (line.empty()) continue;
            
            std::istringstream line_stream(line);
            std::string name, image, status, ports;
            
            if (std::getline(line_stream, name, '\t') &&
                std::getline(line_stream, image, '\t') &&
                std::getline(line_stream, status, '\t') &&
                std::getline(line_stream, ports, '\t')) {
                
                ContainerInfo container;
                container.name = name;
                container.image = image;
                container.status = (status.find("Up") != std::string::npos) ? "running" : "stopped";
                
                // Extract port from ports string (simplified)
                if (!ports.empty() && ports.find("->") != std::string::npos) {
                    size_t arrow_pos = ports.find("->");
                    if (arrow_pos != std::string::npos) {
                        std::string port_part = ports.substr(0, arrow_pos);
                        size_t colon_pos = port_part.find_last_of(':');
                        if (colon_pos != std::string::npos) {
                            try {
                                container.port = std::stoi(port_part.substr(colon_pos + 1));
                            } catch (...) {
                                container.port = 80; // default
                            }
                        }
                    }
                } else {
                    container.port = 80; // default
                }
                
                containers.push_back(container);
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ContainerManager] Error getting running containers: " << e.what() << std::endl;
    }
    
    return containers;
}

bool ContainerManager::isContainerRunning(const std::string& name) {
    try {
        std::string command = "docker ps -q -f name=" + name;
        std::string result = executeDockerCommand(command);
        
        // Remove whitespace
        result.erase(std::remove_if(result.begin(), result.end(), ::isspace), result.end());
        
        return !result.empty();
        
    } catch (const std::exception& e) {
        std::cerr << "[ContainerManager] Error checking if container is running " << name << ": " << e.what() << std::endl;
        return false;
    }
}

bool ContainerManager::isContainerHealthy(const ContainerInfo& container) {
    if (!isContainerRunning(container.name)) {
        return false;
    }
    
    return performHealthCheck(container);
}

std::string ContainerManager::getContainerStatus(const std::string& name) {
    try {
        std::string command = "docker ps -a -f name=" + name + " --format '{{.Status}}'";
        std::string result = executeDockerCommand(command);
        
        if (result.empty()) {
            return "not_found";
        }
        
        if (result.find("Up") != std::string::npos) {
            return "running";
        } else if (result.find("Exited") != std::string::npos) {
            return "stopped";
        } else {
            return "unknown";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ContainerManager] Error getting container status " << name << ": " << e.what() << std::endl;
        return "error";
    }
}

bool ContainerManager::performHealthCheck(const ContainerInfo& container) {
    if (container.health_path.empty()) {
        // No health check configured, assume healthy if running
        return isContainerRunning(container.name);
    }
    
    // Build health check URL
    std::string health_url = "http://localhost:" + std::to_string(container.port) + container.health_path;
    
    return httpHealthCheck(health_url, 5000); // 5 second timeout
}

bool ContainerManager::areAllContainersHealthy(const std::vector<ContainerInfo>& containers) {
    for (const auto& container : containers) {
        if (!isContainerHealthy(container)) {
            return false;
        }
    }
    return true;
}

void ContainerManager::ensureContainersRunning(const nlohmann::json& containers_config) {
    if (!containers_config.is_array()) {
        return;
    }
    
    for (const auto& container_json : containers_config) {
        try {
            ContainerInfo container = parseContainerFromJson(container_json);
            
            if (!isContainerRunning(container.name)) {
                std::cout << "[ContainerManager] Container " << container.name << " is not running, attempting to start..." << std::endl;
                
                // Try to start the container (with retry)
                bool started = retryOperation([this, &container]() {
                    return startContainer(container);
                }, 2);
                
                if (!started) {
                    std::cerr << "[ContainerManager] Failed to start container " << container.name << " after retries" << std::endl;
                }
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[ContainerManager] Error ensuring container is running: " << e.what() << std::endl;
        }
    }
}

void ContainerManager::syncContainers(const nlohmann::json& desired_containers, 
                                     const nlohmann::json& current_containers) {
    try {
        // Parse desired containers
        std::vector<ContainerInfo> desired;
        if (desired_containers.is_array()) {
            for (const auto& container_json : desired_containers) {
                desired.push_back(parseContainerFromJson(container_json));
            }
        }
        
        // Parse current containers
        std::vector<ContainerInfo> current;
        if (current_containers.is_array()) {
            for (const auto& container_json : current_containers) {
                current.push_back(parseContainerFromJson(container_json));
            }
        }
        
        // Find containers to remove (in current but not in desired)
        for (const auto& curr : current) {
            bool found = false;
            for (const auto& des : desired) {
                if (curr.name == des.name) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                std::cout << "[ContainerManager] Removing container: " << curr.name << std::endl;
                removeContainer(curr.name);
            }
        }
        
        // Find containers to add or update (in desired but not in current, or different)
        for (const auto& des : desired) {
            bool found = false;
            bool needs_update = false;
            
            for (const auto& curr : current) {
                if (curr.name == des.name) {
                    found = true;
                    // Check if image or other properties changed
                    if (curr.image != des.image) {
                        needs_update = true;
                    }
                    break;
                }
            }
            
            if (!found || needs_update) {
                if (needs_update) {
                    std::cout << "[ContainerManager] Updating container: " << des.name << std::endl;
                    removeContainer(des.name);
                }
                std::cout << "[ContainerManager] Adding container: " << des.name << std::endl;
                startContainer(des);
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ContainerManager] Error syncing containers: " << e.what() << std::endl;
    }
}

std::string ContainerManager::executeDockerCommand(const std::string& command) {
    std::array<char, 512> buffer;
    std::string result;
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed for command: " + command);
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

bool ContainerManager::httpHealthCheck(const std::string& url, int timeout_ms) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }
    
    // Set up curl options
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void*, size_t size, size_t nmemb, void*) -> size_t {
        return size * nmemb; // Discard response body
    });
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD request
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    curl_easy_cleanup(curl);
    
    // Consider 2xx responses as healthy
    return (res == CURLE_OK && response_code >= 200 && response_code < 300);
}

std::string ContainerManager::buildDockerRunCommand(const ContainerInfo& container) {
    std::ostringstream cmd;
    
    cmd << "docker run -d --restart=always";
    cmd << " --name " << container.name;
    
    // Add port mapping if specified
    if (container.port > 0) {
        cmd << " -p " << container.port << ":" << container.port;
    }
    
    // Add environment variables
    if (container.env.is_object()) {
        for (const auto& [key, value] : container.env.items()) {
            if (value.is_string()) {
                cmd << " -e " << key << "=\"" << value.get<std::string>() << "\"";
            } else {
                cmd << " -e " << key << "=\"" << value.dump() << "\"";
            }
        }
    }
    
    cmd << " " << container.image;
    
    return cmd.str();
}

ContainerInfo ContainerManager::parseContainerFromJson(const nlohmann::json& container_json) {
    ContainerInfo container;
    
    container.name = container_json.value("name", "");
    container.image = container_json.value("image", "");
    container.port = container_json.value("port", 80);
    container.health_path = container_json.value("health_path", "");
    container.env = container_json.value("env", nlohmann::json::object());
    container.status = "unknown";
    
    return container;
}

bool ContainerManager::retryOperation(std::function<bool()> operation, int max_retries) {
    for (int i = 0; i <= max_retries; ++i) {
        if (operation()) {
            return true;
        }
        
        if (i < max_retries) {
            std::cout << "[ContainerManager] Operation failed, retrying... (" << (i + 1) << "/" << max_retries << ")" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    
    return false;
}
