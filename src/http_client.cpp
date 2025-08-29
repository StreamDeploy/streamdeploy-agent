#include "http_client.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <stdexcept>
#include <map>
#include <algorithm>
#include <cctype>

using json = nlohmann::json;

static size_t appendCb(void* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* s = static_cast<std::string*>(userdata);
    s->append(static_cast<char*>(ptr), size*nmemb);
    return size*nmemb;
}

static inline std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

static inline std::string trim(std::string s) {
    auto notSpace = [](int ch) { return !std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

struct HeaderCtx {
    std::map<std::string,std::string>* headers;
};

static size_t headerCb(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t len = size * nitems;
    std::string line(buffer, len);
    auto* ctx = static_cast<HeaderCtx*>(userdata);
    auto pos = line.find(':');
    if (pos != std::string::npos && ctx && ctx->headers) {
        std::string key = toLower(trim(line.substr(0, pos)));
        std::string val = trim(line.substr(pos + 1));
        // strip trailing CRLF if present
        if (!val.empty() && (val.back() == '\r' || val.back() == '\n')) {
            while (!val.empty() && (val.back() == '\r' || val.back() == '\n')) val.pop_back();
        }
        (*ctx->headers)[key] = val;
    }
    return len;
}

static std::string curlReqJson(const std::string& method, const std::string& url,
                               const std::string& body,
                               const std::vector<std::pair<std::string,std::string>>& headers,
                               long timeoutMs,
                               const std::string& ca, const std::string& cert,
                               const std::string& key, const std::string& pass) {
    CURL* c = curl_easy_init();
    if (!c) throw std::runtime_error("curl_easy_init failed");

    std::string resp;
    struct curl_slist* hdr = nullptr;
    for (auto& h: headers) {
        std::string line = h.first + ": " + h.second;
        hdr = curl_slist_append(hdr, line.c_str());
    }

    // JSON default header
    hdr = curl_slist_append(hdr, "Content-Type: application/json");

    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, appendCb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, timeoutMs);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);

    // TLS + mTLS
    if (!ca.empty())   curl_easy_setopt(c, CURLOPT_CAINFO, ca.c_str());
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    if (!cert.empty()) curl_easy_setopt(c, CURLOPT_SSLCERT, cert.c_str());
    if (!key.empty())  curl_easy_setopt(c, CURLOPT_SSLKEY, key.c_str());
    if (!pass.empty()) curl_easy_setopt(c, CURLOPT_KEYPASSWD, pass.c_str());

    if (method == "POST") {
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, body.size());
    }

    auto rc = curl_easy_perform(c);
    long code = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(c);

    if (rc != CURLE_OK || (code >= 400 && code != 0)) {
        throw std::runtime_error("HTTP " + std::to_string(code) + " (" + std::to_string(rc) + ") for " + url);
    }
    return resp;
}

// Same as curlReqJson but captures status + headers and does NOT throw on 304
static HttpResponse curlReqJsonMeta(const std::string& method, const std::string& url,
                                    const std::string& body,
                                    const std::vector<std::pair<std::string,std::string>>& headers,
                                    long timeoutMs,
                                    const std::string& ca, const std::string& cert,
                                    const std::string& key, const std::string& pass) {
    CURL* c = curl_easy_init();
    if (!c) throw std::runtime_error("curl_easy_init failed");

    HttpResponse respObj;
    std::string respBody;
    std::map<std::string,std::string> respHeaders;

    struct curl_slist* hdr = nullptr;
    for (auto& h: headers) {
        std::string line = h.first + ": " + h.second;
        hdr = curl_slist_append(hdr, line.c_str());
    }
    hdr = curl_slist_append(hdr, "Content-Type: application/json");

    HeaderCtx hctx{&respHeaders};

    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, appendCb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &respBody);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, timeoutMs);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, headerCb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &hctx);

    // TLS + mTLS
    if (!ca.empty())   curl_easy_setopt(c, CURLOPT_CAINFO, ca.c_str());
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    if (!cert.empty()) curl_easy_setopt(c, CURLOPT_SSLCERT, cert.c_str());
    if (!key.empty())  curl_easy_setopt(c, CURLOPT_SSLKEY, key.c_str());
    if (!pass.empty()) curl_easy_setopt(c, CURLOPT_KEYPASSWD, pass.c_str());

    if (method == "POST") {
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, body.size());
    }

    auto rc = curl_easy_perform(c);
    long code = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(c);

    respObj.status = code;
    respObj.body = respBody;
    respObj.headers = std::move(respHeaders);

    if (rc != CURLE_OK) {
        throw std::runtime_error("CURL error (" + std::to_string(rc) + ") for " + url);
    }
    // Do not throw on 304; caller will handle. Throw on other 4xx/5xx.
    if (code >= 400 && code != 304) {
        throw std::runtime_error("HTTP " + std::to_string(code) + " for " + url);
    }
    return respObj;
}

HttpClient::HttpClient(const std::string& baseUrl,
                       const std::string& caPath,
                       const std::string& certPath,
                       const std::string& keyPath,
                       const std::string& keyPass)
: base(baseUrl), ca(caPath), cert(certPath), key(keyPath), pass(keyPass) {}

std::string HttpClient::postJson(const std::string& path, const json& j,
                                 const std::vector<std::pair<std::string,std::string>>& extraHeaders,
                                 long timeoutMs) {
    return curlReqJson("POST", base + path, j.dump(), extraHeaders, timeoutMs, ca, cert, key, pass);
}

HttpResponse HttpClient::postJsonWithMeta(const std::string& path, const json& j,
                                          const std::vector<std::pair<std::string,std::string>>& extraHeaders,
                                          long timeoutMs) {
    return curlReqJsonMeta("POST", base + path, j.dump(), extraHeaders, timeoutMs, ca, cert, key, pass);
}

std::string HttpClient::getAbs(const std::string& url,
                               const std::vector<std::pair<std::string,std::string>>& extraHeaders,
                               long timeoutMs) {
    return curlReqJson("GET", url, "", extraHeaders, timeoutMs, "", "", "", "");
}
