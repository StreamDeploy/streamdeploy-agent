#pragma once

#include <string>
#include <map>
#include <nlohmann/json.hpp>

struct HttpResponse {
    int status_code;
    std::string body;
    std::map<std::string, std::string> headers;
};

class HttpsClient {
public:
    HttpsClient(const std::string& base_url, 
                const std::string& ca_cert_path,
                const std::string& client_cert_path,
                const std::string& client_key_path);
    ~HttpsClient();

    // HTTP operations
    HttpResponse get(const std::string& path, 
                    const std::map<std::string, std::string>& headers = {});
    
    HttpResponse post(const std::string& path, 
                     const std::string& body,
                     const std::map<std::string, std::string>& headers = {});
    
    HttpResponse postJson(const std::string& path, 
                         const nlohmann::json& json_body,
                         const std::map<std::string, std::string>& headers = {});

    // Specific API endpoints
    HttpResponse sendHeartbeat(const nlohmann::json& heartbeat_data, 
                              const std::string& device_id);
    
    HttpResponse sendStatusUpdate(const nlohmann::json& status_data, 
                                 const std::string& device_id);
    
    HttpResponse renewCertificate(const std::string& csr_base64);

    // Configuration
    void updateCertificates(const std::string& ca_cert_path,
                           const std::string& client_cert_path,
                           const std::string& client_key_path);
    
    bool verifyCertificates();

private:
    std::string base_url_;
    std::string ca_cert_path_;
    std::string client_cert_path_;
    std::string client_key_path_;
    
    // CURL handle (opaque pointer to avoid including curl headers)
    void* curl_handle_;
    
    // Private methods
    void initializeCurl();
    void cleanupCurl();
    HttpResponse performRequest(const std::string& method,
                               const std::string& path,
                               const std::string& body,
                               const std::map<std::string, std::string>& headers);
    
    // Callback for CURL
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
    static size_t headerCallback(void* contents, size_t size, size_t nmemb, void* userp);
};
