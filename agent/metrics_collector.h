#pragma once

#include <string>
#include <map>
#include <nlohmann/json.hpp>

class MetricsCollector {
public:
    MetricsCollector();
    ~MetricsCollector();

    // System metrics collection
    nlohmann::json collectSystemMetrics();
    nlohmann::json collectCustomMetrics(const nlohmann::json& custom_metrics_config);
    
    // Individual metric collection
    double getCpuUsage();
    double getMemoryUsage();
    double getDiskUsage(const std::string& path = "/");
    
    // Status determination
    std::string determineSystemStatus(double cpu_pct, double mem_pct, double disk_pct, 
                                    bool containers_healthy);

private:
    // Utility methods
    std::string executeCommand(const std::string& command);
    double parsePercentage(const std::string& value);
    
    // Thresholds for degraded status
    static constexpr double CPU_THRESHOLD = 90.0;
    static constexpr double MEMORY_THRESHOLD = 90.0;
    static constexpr double DISK_THRESHOLD = 90.0;
};
