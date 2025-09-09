#include "metrics_collector.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <array>
#include <cstdio>
#include <memory>
#include <stdexcept>

MetricsCollector::MetricsCollector() {
}

MetricsCollector::~MetricsCollector() {
}

nlohmann::json MetricsCollector::collectSystemMetrics() {
    nlohmann::json metrics;
    
    try {
        metrics["cpu_pct"] = getCpuUsage();
        metrics["mem_pct"] = getMemoryUsage();
        metrics["disk_pct"] = getDiskUsage("/");
        
        // Add timestamp
        metrics["timestamp"] = std::time(nullptr);
        
    } catch (const std::exception& e) {
        std::cerr << "[MetricsCollector] Error collecting system metrics: " << e.what() << std::endl;
        metrics["cpu_pct"] = 0.0;
        metrics["mem_pct"] = 0.0;
        metrics["disk_pct"] = 0.0;
        metrics["error"] = e.what();
    }
    
    return metrics;
}

nlohmann::json MetricsCollector::collectCustomMetrics(const nlohmann::json& custom_metrics_config) {
    nlohmann::json custom_metrics;
    
    if (!custom_metrics_config.is_object()) {
        return custom_metrics;
    }
    
    for (const auto& [key, value] : custom_metrics_config.items()) {
        try {
            if (value.is_string()) {
                std::string command = value.get<std::string>();
                std::string result = executeCommand(command);
                
                // Remove trailing newline if present
                if (!result.empty() && result.back() == '\n') {
                    result.pop_back();
                }
                
                // Try to parse as number, otherwise keep as string
                try {
                    if (result.find('.') != std::string::npos) {
                        custom_metrics[key] = std::stod(result);
                    } else {
                        custom_metrics[key] = std::stoll(result);
                    }
                } catch (...) {
                    custom_metrics[key] = result;
                }
            } else {
                custom_metrics[key] = value;
            }
        } catch (const std::exception& e) {
            std::cerr << "[MetricsCollector] Error collecting custom metric '" << key << "': " << e.what() << std::endl;
            custom_metrics[key] = "error";
        }
    }
    
    return custom_metrics;
}

double MetricsCollector::getCpuUsage() {
    try {
        // Use top command to get CPU usage
        std::string result = executeCommand("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | sed 's/%us,//' | head -1");
        if (result.empty()) {
            // Fallback: try different top format
            result = executeCommand("top -bn1 | grep '%Cpu' | awk '{print $2}' | sed 's/%us,//' | head -1");
        }
        if (result.empty()) {
            // Another fallback: use /proc/stat
            result = executeCommand("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$3+$4+$5)} END {print usage}'");
        }
        
        if (!result.empty()) {
            return parsePercentage(result);
        }
    } catch (const std::exception& e) {
        std::cerr << "[MetricsCollector] Error getting CPU usage: " << e.what() << std::endl;
    }
    
    return 0.0;
}

double MetricsCollector::getMemoryUsage() {
    try {
        // Read memory info from /proc/meminfo
        std::ifstream meminfo("/proc/meminfo");
        if (!meminfo.is_open()) {
            throw std::runtime_error("Cannot open /proc/meminfo");
        }
        
        std::string line;
        long mem_total = 0, mem_available = 0;
        
        while (std::getline(meminfo, line)) {
            if (line.find("MemTotal:") == 0) {
                std::istringstream iss(line);
                std::string label, value, unit;
                iss >> label >> value >> unit;
                mem_total = std::stol(value);
            } else if (line.find("MemAvailable:") == 0) {
                std::istringstream iss(line);
                std::string label, value, unit;
                iss >> label >> value >> unit;
                mem_available = std::stol(value);
            }
            
            if (mem_total > 0 && mem_available > 0) {
                break;
            }
        }
        
        if (mem_total > 0) {
            double used_pct = ((double)(mem_total - mem_available) / mem_total) * 100.0;
            return used_pct;
        }
    } catch (const std::exception& e) {
        std::cerr << "[MetricsCollector] Error getting memory usage: " << e.what() << std::endl;
    }
    
    return 0.0;
}

double MetricsCollector::getDiskUsage(const std::string& path) {
    try {
        std::string command = "df -h " + path + " | awk 'NR==2 {print $5}' | sed 's/%//'";
        std::string result = executeCommand(command);
        
        if (!result.empty()) {
            return parsePercentage(result);
        }
    } catch (const std::exception& e) {
        std::cerr << "[MetricsCollector] Error getting disk usage for " << path << ": " << e.what() << std::endl;
    }
    
    return 0.0;
}

std::string MetricsCollector::determineSystemStatus(double cpu_pct, double mem_pct, double disk_pct, bool containers_healthy) {
    // Check if any metric exceeds threshold or containers are unhealthy
    if (cpu_pct > CPU_THRESHOLD || 
        mem_pct > MEMORY_THRESHOLD || 
        disk_pct > DISK_THRESHOLD || 
        !containers_healthy) {
        return "degraded";
    }
    
    return "normal";
}

std::string MetricsCollector::executeCommand(const std::string& command) {
    std::array<char, 512> buffer;
    std::string result;
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen((command + " 2>/dev/null").c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed for command: " + command);
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

double MetricsCollector::parsePercentage(const std::string& value) {
    try {
        std::string trimmed = value;
        
        // Remove whitespace
        trimmed.erase(0, trimmed.find_first_not_of(" \t\n\r"));
        trimmed.erase(trimmed.find_last_not_of(" \t\n\r") + 1);
        
        // Remove % sign if present
        if (!trimmed.empty() && trimmed.back() == '%') {
            trimmed.pop_back();
        }
        
        if (trimmed.empty()) {
            return 0.0;
        }
        
        return std::stod(trimmed);
    } catch (const std::exception& e) {
        std::cerr << "[MetricsCollector] Error parsing percentage '" << value << "': " << e.what() << std::endl;
        return 0.0;
    }
}
