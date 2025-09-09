#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

struct PackageInfo {
    std::string name;
    std::string install_command;
    std::string check_command;
    std::string uninstall_command;
};

class PackageManager {
public:
    explicit PackageManager(const nlohmann::json& agent_config);
    ~PackageManager();

    // Package operations
    bool installPackage(const std::string& package_name);
    bool isPackageInstalled(const std::string& package_name);
    bool uninstallPackage(const std::string& package_name);

    // Custom package operations
    bool installCustomPackage(const std::string& name, const PackageInfo& package_info);
    bool isCustomPackageInstalled(const std::string& name, const PackageInfo& package_info);
    bool uninstallCustomPackage(const std::string& name, const PackageInfo& package_info);

    // Bulk operations
    void ensurePackagesInstalled(const std::vector<std::string>& packages);
    void ensureCustomPackagesInstalled(const nlohmann::json& custom_packages);
    
    // Package synchronization
    void syncPackages(const std::vector<std::string>& desired_packages,
                     const std::vector<std::string>& current_packages);
    void syncCustomPackages(const nlohmann::json& desired_custom_packages,
                           const nlohmann::json& current_custom_packages);

private:
    // Package manager configuration from agent.json
    std::string install_cmd_;
    std::string check_cmd_;
    std::string remove_cmd_;
    std::string update_cmd_;
    std::string package_manager_type_;

    // Utility methods
    std::string executeCommand(const std::string& command);
    bool retryOperation(std::function<bool()> operation, int max_retries = 2);
    PackageInfo parseCustomPackage(const std::string& name, const nlohmann::json& package_json);
    std::vector<std::string> getCurrentPackages();
};
