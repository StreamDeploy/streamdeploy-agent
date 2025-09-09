#include "https_client.h"
#include <iostream>
#include <sstream>
#include <curl/curl.h>
#include <cstring>

// Callback function to write response data
size_t HttpsClient::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), total_size);
    return total_size;
}

// Callback function to write headers
size_t HttpsClient::headerCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    std::string header_line(static_cast<char*>(contents), total_size);
    
    // Parse header line (format: "Header-Name: value\r\n")
    size_t colon_pos = header_line.find(':');
    if (colon_pos != std::string::npos) {
        std::string name = header_line.substr(0, colon_pos);
        std::string value = header_line.substr(colon_pos + 1);
        
        // Remove leading/trailing whitespace
        value.erase(0, value.find_first_not_of(" \t\r\n"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);
        
        std::map<std::string, std::string>* headers = static_cast<std::map<std::string, std::string>*>(userp);
        (*headers)[name] = value;
    }
    
    return total_size;
}

HttpsClient::HttpsClient(const std::string& base_url, 
                         const std::string& ca_cert_path,
                         const std::string& client_cert_path,
                         const std::string& client_key_path)
    : base_url_(base_url)
    , ca_cert_path_(ca_cert_path)
    , client_cert_path_(client_cert_path)
    , client_key_path_(client_key_path)
    , curl_handle_(nullptr) {
    
    initializeCurl();
}

HttpsClient::~HttpsClient() {
    cleanupCurl();
}

HttpResponse HttpsClient::get(const std::string& path, 
                             const std::map<std::string, std::string>& headers) {
    return performRequest("GET", path, "", headers);
}

HttpResponse HttpsClient::post(const std::string& path, 
                              const std::string& body,
                              const std::map<std::string, std::string>& headers) {
    return performRequest("POST", path, body, headers);
}

HttpResponse HttpsClient::postJson(const std::string& path, 
                                  const nlohmann::json& json_body,
                                  const std::map<std::string, std::string>& headers) {
    std::map<std::string, std::string> json_headers = headers;
    json_headers["Content-Type"] = "application/json";
    
    return performRequest("POST", path, json_body.dump(), json_headers);
}

HttpResponse HttpsClient::sendHeartbeat(const nlohmann::json& heartbeat_data, 
                                       const std::string& device_id) {
    std::string path = "/api/v1/devices/" + device_id + "/heartbeat";
    return postJson(path, heartbeat_data);
}

HttpResponse HttpsClient::sendStatusUpdate(const nlohmann::json& status_data, 
                                          const std::string& device_id) {
    std::string path = "/api/v1/devices/" + device_id + "/status";
    return postJson(path, status_data);
}

HttpResponse HttpsClient::renewCertificate(const std::string& csr_base64) {
    nlohmann::json request_data;
    request_data["csr"] = csr_base64;
    
    return postJson("/api/v1/certificates/renew", request_data);
}

void HttpsClient::updateCertificates(const std::string& ca_cert_path,
                                     const std::string& client_cert_path,
                                     const std::string& client_key_path) {
    ca_cert_path_ = ca_cert_path;
    client_cert_path_ = client_cert_path;
    client_key_path_ = client_key_path;
    
    // Reinitialize CURL with new certificates
    cleanupCurl();
    initializeCurl();
}

bool HttpsClient::verifyCertificates() {
    if (!curl_handle_) {
        return false;
    }
    
    // Test connection to verify certificates
    HttpResponse response = get("/api/v1/health");
    return response.status_code == 200;
}

void HttpsClient::initializeCurl() {
    curl_handle_ = curl_easy_init();
    if (!curl_handle_) {
        std::cerr << "[HttpsClient] Failed to initialize CURL" << std::endl;
        return;
    }
    
    // Set basic options
    curl_easy_setopt(curl_handle_, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl_handle_, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl_handle_, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl_handle_, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl_handle_, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_handle_, CURLOPT_MAXREDIRS, 3L);
    
    // Set user agent
    curl_easy_setopt(curl_handle_, CURLOPT_USERAGENT, "StreamDeploy-Agent/1.0");
    
    // Set certificate paths
    if (!ca_cert_path_.empty()) {
        curl_easy_setopt(curl_handle_, CURLOPT_CAINFO, ca_cert_path_.c_str());
    }
    
    if (!client_cert_path_.empty() && !client_key_path_.empty()) {
        curl_easy_setopt(curl_handle_, CURLOPT_SSLCERT, client_cert_path_.c_str());
        curl_easy_setopt(curl_handle_, CURLOPT_SSLKEY, client_key_path_.c_str());
    }
    
    // Set callbacks
    curl_easy_setopt(curl_handle_, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl_handle_, CURLOPT_HEADERFUNCTION, headerCallback);
    
    std::cout << "[HttpsClient] Initialized with base URL: " << base_url_ << std::endl;
}

void HttpsClient::cleanupCurl() {
    if (curl_handle_) {
        curl_easy_cleanup(curl_handle_);
        curl_handle_ = nullptr;
    }
}

HttpResponse HttpsClient::performRequest(const std::string& method,
                                        const std::string& path,
                                        const std::string& body,
                                        const std::map<std::string, std::string>& headers) {
    HttpResponse response;
    
    if (!curl_handle_) {
        std::cerr << "[HttpsClient] CURL handle not initialized" << std::endl;
        response.status_code = -1;
        return response;
    }
    
    // Build full URL
    std::string url = base_url_ + path;
    curl_easy_setopt(curl_handle_, CURLOPT_URL, url.c_str());
    
    // Set HTTP method
    if (method == "GET") {
        curl_easy_setopt(curl_handle_, CURLOPT_HTTPGET, 1L);
    } else if (method == "POST") {
        curl_easy_setopt(curl_handle_, CURLOPT_POST, 1L);
        if (!body.empty()) {
            curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDS, body.c_str());
            curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDSIZE, body.length());
        }
    } else if (method == "PUT") {
        curl_easy_setopt(curl_handle_, CURLOPT_CUSTOMREQUEST, "PUT");
        if (!body.empty()) {
            curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDS, body.c_str());
            curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDSIZE, body.length());
        }
    } else if (method == "DELETE") {
        curl_easy_setopt(curl_handle_, CURLOPT_CUSTOMREQUEST, "DELETE");
    }
    
    // Set headers
    struct curl_slist* header_list = nullptr;
    for (const auto& [name, value] : headers) {
        std::string header = name + ": " + value;
        header_list = curl_slist_append(header_list, header.c_str());
    }
    
    if (header_list) {
        curl_easy_setopt(curl_handle_, CURLOPT_HTTPHEADER, header_list);
    }
    
    // Set response data containers
    std::string response_body;
    std::map<std::string, std::string> response_headers;
    
    curl_easy_setopt(curl_handle_, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(curl_handle_, CURLOPT_HEADERDATA, &response_headers);
    
    // Perform the request
    CURLcode result = curl_easy_perform(curl_handle_);
    
    // Clean up headers
    if (header_list) {
        curl_slist_free_all(header_list);
    }
    
    if (result != CURLE_OK) {
        std::cerr << "[HttpsClient] CURL request failed: " << curl_easy_strerror(result) << std::endl;
        response.status_code = -1;
        response.body = curl_easy_strerror(result);
        return response;
    }
    
    // Get response code
    long response_code;
    curl_easy_getinfo(curl_handle_, CURLINFO_RESPONSE_CODE, &response_code);
    
    // Build response
    response.status_code = static_cast<int>(response_code);
    response.body = response_body;
    response.headers = response_headers;
    
    std::cout << "[HttpsClient] " << method << " " << path << " -> " << response_code << std::endl;
    
    return response;
}
