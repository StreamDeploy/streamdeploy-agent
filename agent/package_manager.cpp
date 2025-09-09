#include "package_manager.h"
#include <iostream>
#include <sstream>
#include <array>
#include <memory>
#include <algorithm>
#include <functional>
#include <thread>
#include <chrono>

PackageManager::PackageManager(const nlohmann::json& agent_config) {
    // Extract package manager configuration from agent config
    if (agent_config.contains("package_manager")) {
        const auto& pm_config = agent_config["package_manager"];
        
        package_manager_type_ = pm_config.value("type", "apt");
        install_cmd_ = pm_config.value("install_cmd", "apt install -y");
        check_cmd_ = pm_config.value("check_cmd", "dpkg -l");
        remove_cmd_ = pm_config.value("remove_cmd", "apt remove -y");
        update_cmd_ = pm_config.value("update_cmd", "apt update");
    } else {
        // Default to APT package manager
        package_manager_type_ = "apt";
        install_cmd_ = "apt install -y";
        check_cmd_ = "dpkg -l";
        remove_cmd_ = "apt remove -y";
        update_cmd_ = "apt update";
    }
    
    std::cout << "[PackageManager] Initialized with package manager: " << package_manager_type_ << std::endl;
}

PackageManager::~PackageManager() {
}

bool PackageManager::installPackage(const std::string& package_name) {
    if (package_name.empty()) {
        std::cerr << "[PackageManager] Package name cannot be empty" << std::endl;
        return false;
    }
    
    std::string command = install_cmd_ + " " + package_name;
    std::string result = executeCommand(command);
    
    if (result.find("Error") != std::string::npos || result.find("error") != std::string::npos) {
        std::cerr << "[PackageManager] Failed to install package " << package_name << ": " << result << std::endl;
        return false;
    }
    
    std::cout << "[PackageManager] Successfully installed package: " << package_name << std::endl;
    return true;
}

bool PackageManager::isPackageInstalled(const std::string& package_name) {
    if (package_name.empty()) {
        return false;
    }
    
    std::string command;
    if (package_manager_type_ == "apt") {
        command = "dpkg -l | grep -E '^ii\\s+" + package_name + "\\s'";
    } else if (package_manager_type_ == "yum") {
        command = "rpm -q " + package_name;
    } else if (package_manager_type_ == "dnf") {
        command = "dnf list installed | grep " + package_name;
    } else {
        // Generic check using the configured check command
        command = check_cmd_ + " | grep " + package_name;
    }
    
    std::string result = executeCommand(command);
    return !result.empty();
}

bool PackageManager::uninstallPackage(const std::string& package_name) {
    if (package_name.empty()) {
        std::cerr << "[PackageManager] Package name cannot be empty" << std::endl;
        return false;
    }
    
    std::string command = remove_cmd_ + " " + package_name;
    std::string result = executeCommand(command);
    
    if (result.find("Error") != std::string::npos || result.find("error") != std::string::npos) {
        std::cerr << "[PackageManager] Failed to uninstall package " << package_name << ": " << result << std::endl;
        return false;
    }
    
    std::cout << "[PackageManager] Successfully uninstalled package: " << package_name << std::endl;
    return true;
}

bool PackageManager::installCustomPackage(const std::string& name, const PackageInfo& package_info) {
    if (name.empty() || package_info.install_command.empty()) {
        std::cerr << "[PackageManager] Invalid custom package configuration" << std::endl;
        return false;
    }
    
    std::string result = executeCommand(package_info.install_command);
    
    if (result.find("Error") != std::string::npos || result.find("error") != std::string::npos) {
        std::cerr << "[PackageManager] Failed to install custom package " << name << ": " << result << std::endl;
        return false;
    }
    
    std::cout << "[PackageManager] Successfully installed custom package: " << name << std::endl;
    return true;
}

bool PackageManager::isCustomPackageInstalled(const std::string& name, const PackageInfo& package_info) {
    if (name.empty() || package_info.check_command.empty()) {
        return false;
    }
    
    std::string result = executeCommand(package_info.check_command);
    return !result.empty();
}

bool PackageManager::uninstallCustomPackage(const std::string& name, const PackageInfo& package_info) {
    if (name.empty() || package_info.uninstall_command.empty()) {
        std::cerr << "[PackageManager] Invalid custom package configuration for uninstall" << std::endl;
        return false;
    }
    
    std::string result = executeCommand(package_info.uninstall_command);
    
    if (result.find("Error") != std::string::npos || result.find("error") != std::string::npos) {
        std::cerr << "[PackageManager] Failed to uninstall custom package " << name << ": " << result << std::endl;
        return false;
    }
    
    std::cout << "[PackageManager] Successfully uninstalled custom package: " << name << std::endl;
    return true;
}

void PackageManager::ensurePackagesInstalled(const std::vector<std::string>& packages) {
    for (const auto& package : packages) {
        if (!isPackageInstalled(package)) {
            std::cout << "[PackageManager] Package " << package << " not installed, installing..." << std::endl;
            
            bool success = retryOperation([this, &package]() {
                return installPackage(package);
            }, 2);
            
            if (!success) {
                std::cerr << "[PackageManager] Failed to install package " << package << " after retries" << std::endl;
            }
        } else {
            std::cout << "[PackageManager] Package " << package << " is already installed" << std::endl;
        }
    }
}

void PackageManager::ensureCustomPackagesInstalled(const nlohmann::json& custom_packages) {
    if (!custom_packages.is_object()) {
        return;
    }
    
    for (const auto& [name, package_json] : custom_packages.items()) {
        try {
            PackageInfo package_info = parseCustomPackage(name, package_json);
            
            if (!isCustomPackageInstalled(name, package_info)) {
                std::cout << "[PackageManager] Custom package " << name << " not installed, installing..." << std::endl;
                
                bool success = retryOperation([this, &name, &package_info]() {
                    return installCustomPackage(name, package_info);
                }, 2);
                
                if (!success) {
                    std::cerr << "[PackageManager] Failed to install custom package " << name << " after retries" << std::endl;
                }
            } else {
                std::cout << "[PackageManager] Custom package " << name << " is already installed" << std::endl;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[PackageManager] Error processing custom package " << name << ": " << e.what() << std::endl;
        }
    }
}

void PackageManager::syncPackages(const std::vector<std::string>& desired_packages,
                                 const std::vector<std::string>& current_packages) {
    // Find packages to remove (in current but not in desired)
    for (const auto& current_package : current_packages) {
        bool found = false;
        for (const auto& desired_package : desired_packages) {
            if (current_package == desired_package) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            std::cout << "[PackageManager] Removing package: " << current_package << std::endl;
            uninstallPackage(current_package);
        }
    }
    
    // Find packages to install (in desired but not in current)
    for (const auto& desired_package : desired_packages) {
        bool found = false;
        for (const auto& current_package : current_packages) {
            if (desired_package == current_package) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            std::cout << "[PackageManager] Installing package: " << desired_package << std::endl;
            installPackage(desired_package);
        }
    }
}

void PackageManager::syncCustomPackages(const nlohmann::json& desired_custom_packages,
                                       const nlohmann::json& current_custom_packages) {
    if (!desired_custom_packages.is_object() || !current_custom_packages.is_object()) {
        return;
    }
    
    // Find custom packages to remove
    for (const auto& [name, current_package_json] : current_custom_packages.items()) {
        if (!desired_custom_packages.contains(name)) {
            std::cout << "[PackageManager] Removing custom package: " << name << std::endl;
            try {
                PackageInfo package_info = parseCustomPackage(name, current_package_json);
                uninstallCustomPackage(name, package_info);
            } catch (const std::exception& e) {
                std::cerr << "[PackageManager] Error removing custom package " << name << ": " << e.what() << std::endl;
            }
        }
    }
    
    // Find custom packages to install or update
    for (const auto& [name, desired_package_json] : desired_custom_packages.items()) {
        try {
            PackageInfo desired_info = parseCustomPackage(name, desired_package_json);
            
            if (current_custom_packages.contains(name)) {
                // Package exists, check if it needs updating
                PackageInfo current_info = parseCustomPackage(name, current_custom_packages[name]);
                
                // Simple comparison - in practice, you might want more sophisticated version checking
                if (desired_info.install_command != current_info.install_command) {
                    std::cout << "[PackageManager] Updating custom package: " << name << std::endl;
                    uninstallCustomPackage(name, current_info);
                    installCustomPackage(name, desired_info);
                }
            } else {
                // Package doesn't exist, install it
                std::cout << "[PackageManager] Installing custom package: " << name << std::endl;
                installCustomPackage(name, desired_info);
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[PackageManager] Error processing custom package " << name << ": " << e.what() << std::endl;
        }
    }
}

std::string PackageManager::executeCommand(const std::string& command) {
    std::array<char, 512> buffer;
    std::string result;
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        return "Error: popen() failed";
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

bool PackageManager::retryOperation(std::function<bool()> operation, int max_retries) {
    for (int i = 0; i <= max_retries; ++i) {
        if (operation()) {
            return true;
        }
        
        if (i < max_retries) {
            std::cout << "[PackageManager] Operation failed, retrying... (" << (i + 1) << "/" << max_retries << ")" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    
    return false;
}

PackageInfo PackageManager::parseCustomPackage(const std::string& name, const nlohmann::json& package_json) {
    PackageInfo package_info;
    package_info.name = name;
    
    if (package_json.contains("install_command")) {
        package_info.install_command = package_json["install_command"];
    }
    
    if (package_json.contains("check_command")) {
        package_info.check_command = package_json["check_command"];
    }
    
    if (package_json.contains("uninstall_command")) {
        package_info.uninstall_command = package_json["uninstall_command"];
    }
    
    return package_info;
}

std::vector<std::string> PackageManager::getCurrentPackages() {
    std::vector<std::string> packages;
    
    std::string command;
    if (package_manager_type_ == "apt") {
        command = "dpkg -l | grep '^ii' | awk '{print $2}'";
    } else if (package_manager_type_ == "yum") {
        command = "rpm -qa";
    } else if (package_manager_type_ == "dnf") {
        command = "dnf list installed | grep -v '^Installed Packages' | awk '{print $1}'";
    } else {
        command = check_cmd_;
    }
    
    std::string result = executeCommand(command);
    std::istringstream stream(result);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (!line.empty()) {
            // Clean up package name (remove version info for some package managers)
            if (package_manager_type_ == "apt") {
                // APT package names are clean
                packages.push_back(line);
            } else if (package_manager_type_ == "yum" || package_manager_type_ == "dnf") {
                // RPM packages include version, extract just the name
                size_t dash_pos = line.find_last_of('-');
                if (dash_pos != std::string::npos) {
                    size_t second_dash = line.find_last_of('-', dash_pos - 1);
                    if (second_dash != std::string::npos) {
                        packages.push_back(line.substr(0, second_dash));
                    } else {
                        packages.push_back(line.substr(0, dash_pos));
                    }
                } else {
                    packages.push_back(line);
                }
            } else {
                packages.push_back(line);
            }
        }
    }
    
    return packages;
}
