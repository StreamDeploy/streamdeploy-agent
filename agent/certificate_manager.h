#pragma once

#include <string>
#include <chrono>
#include <nlohmann/json.hpp>

class CertificateManager {
public:
    explicit CertificateManager(const std::string& pki_dir);
    ~CertificateManager();

    // Certificate validation
    bool areCertificatesValid();
    bool isCertificateExpiringSoon(int days_threshold = 30);
    std::chrono::system_clock::time_point getCertificateExpirationTime();

    // Certificate renewal
    bool renewCertificate(const std::string& device_id, 
                         const std::string& enroll_endpoint);
    
    // Certificate operations
    bool generateKeyAndCSR(const std::string& device_id);
    bool saveCertificateResponse(const nlohmann::json& cert_response);
    
    // Certificate paths
    std::string getCertificatePath() const;
    std::string getPrivateKeyPath() const;
    std::string getCACertificatePath() const;
    std::string getCSRPath() const;

    // Certificate information
    std::string getCertificateSubject();
    std::string getCertificateIssuer();
    std::vector<std::string> getCertificateSANs();

private:
    std::string pki_dir_;
    std::string cert_path_;
    std::string key_path_;
    std::string ca_cert_path_;
    std::string csr_path_;

    // Private methods
    std::string executeOpenSSLCommand(const std::string& command);
    bool fileExists(const std::string& path);
    std::string readFile(const std::string& path);
    bool writeFile(const std::string& path, const std::string& content);
    std::string base64Encode(const std::string& input);
    std::string base64Decode(const std::string& input);
    
    // Certificate parsing
    std::chrono::system_clock::time_point parseX509Date(const std::string& date_str);
    std::string extractCertificateField(const std::string& field_name);
};
