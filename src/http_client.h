#pragma once
#include <string>
#include <vector>
#include <utility>
#include <map>
#include <nlohmann/json.hpp>

struct HttpResponse {
    long status = 0;
    std::string body;
    std::map<std::string,std::string> headers; // lowercase keys
};

class HttpClient {
public:
    HttpClient(const std::string& baseUrl,
               const std::string& caPath,
               const std::string& certPath,
               const std::string& keyPath,
               const std::string& keyPass = "");

    // Relative to base URL
    std::string postJson(const std::string& path, const nlohmann::json& j,
                         const std::vector<std::pair<std::string,std::string>>& extraHeaders = {},
                         long timeoutMs = 15000);

    HttpResponse postJsonWithMeta(const std::string& path, const nlohmann::json& j,
                                  const std::vector<std::pair<std::string,std::string>>& extraHeaders = {},
                                  long timeoutMs = 15000);

    // Absolute URL helpers
    std::string getAbs(const std::string& url,
                       const std::vector<std::pair<std::string,std::string>>& extraHeaders = {},
                       long timeoutMs = 5000);

private:
    std::string base;
    std::string ca;
    std::string cert;
    std::string key;
    std::string pass;
};
