#include "certificate_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <cstdlib>
#include <filesystem>

CertificateManager::CertificateManager(const std::string& pki_dir) 
    : pki_dir_(pki_dir) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Set up file paths
    cert_path_ = pki_dir_ + "/client.crt";
    key_path_ = pki_dir_ + "/client.key";
    ca_cert_path_ = pki_dir_ + "/ca.crt";
    csr_path_ = pki_dir_ + "/client.csr";
    
    // Create PKI directory if it doesn't exist
    std::filesystem::create_directories(pki_dir_);
}

CertificateManager::~CertificateManager() {
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
}

bool CertificateManager::areCertificatesValid() {
    return fileExists(cert_path_) && fileExists(key_path_) && fileExists(ca_cert_path_);
}

bool CertificateManager::isCertificateExpiringSoon(int days_threshold) {
    if (!fileExists(cert_path_)) {
        return true; // No certificate means it's "expired"
    }
    
    auto expiration = getCertificateExpirationTime();
    auto now = std::chrono::system_clock::now();
    auto time_until_expiry = expiration - now;
    auto days_until_expiry = std::chrono::duration_cast<std::chrono::hours>(time_until_expiry).count() / 24;
    
    return days_until_expiry <= days_threshold;
}

std::chrono::system_clock::time_point CertificateManager::getCertificateExpirationTime() {
    if (!fileExists(cert_path_)) {
        return std::chrono::system_clock::now(); // Return current time if no cert
    }
    
    std::string command = "openssl x509 -in " + cert_path_ + " -noout -enddate";
    std::string result = executeOpenSSLCommand(command);
    
    if (result.empty()) {
        return std::chrono::system_clock::now();
    }
    
    // Parse the date string (format: notAfter=Dec 31 23:59:59 2023 GMT)
    size_t eq_pos = result.find('=');
    if (eq_pos != std::string::npos) {
        std::string date_str = result.substr(eq_pos + 1);
        return parseX509Date(date_str);
    }
    
    return std::chrono::system_clock::now();
}

bool CertificateManager::renewCertificate(const std::string& device_id, const std::string& enroll_endpoint) {
    try {
        // Generate new key and CSR
        if (!generateKeyAndCSR(device_id)) {
            std::cerr << "[CertificateManager] Failed to generate key and CSR" << std::endl;
            return false;
        }
        
        // Read CSR and encode as base64
        std::string csr_content = readFile(csr_path_);
        if (csr_content.empty()) {
            std::cerr << "[CertificateManager] Failed to read CSR file" << std::endl;
            return false;
        }
        
        std::string csr_base64 = base64Encode(csr_content);
        
        // TODO: Send CSR to enrollment endpoint
        // This would typically involve an HTTP request to the enroll_endpoint
        // For now, we'll just log what would be sent
        std::cout << "[CertificateManager] Would send CSR to: " << enroll_endpoint << std::endl;
        std::cout << "[CertificateManager] CSR (base64): " << csr_base64.substr(0, 100) << "..." << std::endl;
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[CertificateManager] Exception during certificate renewal: " << e.what() << std::endl;
        return false;
    }
}

bool CertificateManager::generateKeyAndCSR(const std::string& device_id) {
    try {
        // Generate private key
        std::string key_command = "openssl genrsa -out " + key_path_ + " 2048";
        std::string key_result = executeOpenSSLCommand(key_command);
        
        if (!key_result.empty() && key_result.find("Error") != std::string::npos) {
            std::cerr << "[CertificateManager] Failed to generate private key: " << key_result << std::endl;
            return false;
        }
        
        // Generate CSR
        std::string csr_command = "openssl req -new -key " + key_path_ + 
                                 " -out " + csr_path_ + 
                                 " -subj \"/CN=" + device_id + "\"";
        std::string csr_result = executeOpenSSLCommand(csr_command);
        
        if (!csr_result.empty() && csr_result.find("Error") != std::string::npos) {
            std::cerr << "[CertificateManager] Failed to generate CSR: " << csr_result << std::endl;
            return false;
        }
        
        std::cout << "[CertificateManager] Generated key and CSR for device: " << device_id << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[CertificateManager] Exception generating key and CSR: " << e.what() << std::endl;
        return false;
    }
}

bool CertificateManager::saveCertificateResponse(const nlohmann::json& cert_response) {
    try {
        // Extract certificate from response
        if (!cert_response.contains("certificate") || !cert_response.contains("ca_certificate")) {
            std::cerr << "[CertificateManager] Invalid certificate response format" << std::endl;
            return false;
        }
        
        std::string cert_pem = cert_response["certificate"];
        std::string ca_cert_pem = cert_response["ca_certificate"];
        
        // Save certificate
        if (!writeFile(cert_path_, cert_pem)) {
            std::cerr << "[CertificateManager] Failed to save certificate" << std::endl;
            return false;
        }
        
        // Save CA certificate
        if (!writeFile(ca_cert_path_, ca_cert_pem)) {
            std::cerr << "[CertificateManager] Failed to save CA certificate" << std::endl;
            return false;
        }
        
        std::cout << "[CertificateManager] Saved certificate and CA certificate" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[CertificateManager] Exception saving certificate response: " << e.what() << std::endl;
        return false;
    }
}

std::string CertificateManager::getCertificatePath() const {
    return cert_path_;
}

std::string CertificateManager::getPrivateKeyPath() const {
    return key_path_;
}

std::string CertificateManager::getCACertificatePath() const {
    return ca_cert_path_;
}

std::string CertificateManager::getCSRPath() const {
    return csr_path_;
}

std::string CertificateManager::getCertificateSubject() {
    if (!fileExists(cert_path_)) {
        return "";
    }
    
    std::string command = "openssl x509 -in " + cert_path_ + " -noout -subject";
    std::string result = executeOpenSSLCommand(command);
    
    if (result.empty()) {
        return "";
    }
    
    // Extract subject from result (format: subject= /CN=device123)
    size_t eq_pos = result.find('=');
    if (eq_pos != std::string::npos) {
        return result.substr(eq_pos + 1);
    }
    
    return result;
}

std::string CertificateManager::getCertificateIssuer() {
    if (!fileExists(cert_path_)) {
        return "";
    }
    
    std::string command = "openssl x509 -in " + cert_path_ + " -noout -issuer";
    std::string result = executeOpenSSLCommand(command);
    
    if (result.empty()) {
        return "";
    }
    
    // Extract issuer from result
    size_t eq_pos = result.find('=');
    if (eq_pos != std::string::npos) {
        return result.substr(eq_pos + 1);
    }
    
    return result;
}

std::vector<std::string> CertificateManager::getCertificateSANs() {
    std::vector<std::string> sans;
    
    if (!fileExists(cert_path_)) {
        return sans;
    }
    
    std::string command = "openssl x509 -in " + cert_path_ + " -noout -text | grep -A1 'Subject Alternative Name'";
    std::string result = executeOpenSSLCommand(command);
    
    if (result.empty()) {
        return sans;
    }
    
    // Parse SANs from the output
    // This is a simplified parser - in practice, you'd want more robust parsing
    std::istringstream stream(result);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.find("DNS:") != std::string::npos) {
            size_t dns_pos = line.find("DNS:");
            if (dns_pos != std::string::npos) {
                std::string dns_name = line.substr(dns_pos + 4);
                // Remove any trailing commas or spaces
                dns_name.erase(std::remove_if(dns_name.begin(), dns_name.end(), 
                    [](char c) { return c == ',' || c == ' '; }), dns_name.end());
                if (!dns_name.empty()) {
                    sans.push_back(dns_name);
                }
            }
        }
    }
    
    return sans;
}

std::string CertificateManager::executeOpenSSLCommand(const std::string& command) {
    std::array<char, 512> buffer;
    std::string result;
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        return "";
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

bool CertificateManager::fileExists(const std::string& path) {
    return std::filesystem::exists(path);
}

std::string CertificateManager::readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }
    
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool CertificateManager::writeFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return file.good();
}

std::string CertificateManager::base64Encode(const std::string& input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    std::string result(buffer_ptr->data, buffer_ptr->length);
    
    BIO_free_all(bio);
    
    return result;
}

std::string CertificateManager::base64Decode(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.c_str(), input.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    bio = BIO_push(b64, bio);
    
    char* buffer = new char[input.length()];
    int decoded_length = BIO_read(bio, buffer, input.length());
    
    std::string result(buffer, decoded_length);
    
    delete[] buffer;
    BIO_free_all(bio);
    
    return result;
}

std::chrono::system_clock::time_point CertificateManager::parseX509Date(const std::string& date_str) {
    // Parse date in format: "Dec 31 23:59:59 2023 GMT"
    std::tm tm = {};
    std::istringstream ss(date_str);
    
    ss >> std::get_time(&tm, "%b %d %H:%M:%S %Y");
    
    if (ss.fail()) {
        // Fallback to current time if parsing fails
        return std::chrono::system_clock::now();
    }
    
    // Convert to time_t and then to system_clock::time_point
    std::time_t time = std::mktime(&tm);
    return std::chrono::system_clock::from_time_t(time);
}

std::string CertificateManager::extractCertificateField(const std::string& field_name) {
    if (!fileExists(cert_path_)) {
        return "";
    }
    
    std::string command = "openssl x509 -in " + cert_path_ + " -noout -" + field_name;
    return executeOpenSSLCommand(command);
}
