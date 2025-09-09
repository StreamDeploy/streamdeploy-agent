#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <json/json.h>

class StreamDeployInstaller {
private:
    std::string bootstrap_token;
    std::string device_id;
    std::string os_name;
    std::string os_version;
    std::string architecture;
    std::map<std::string, std::string> package_manager;
    
    // System dependencies to install
    const std::vector<std::string> REQUIRED_PACKAGES = {
        "libcurl4",           // For HTTPS communication with StreamDeploy API
        "libmosquitto1",      // For MQTT communication
        "openssl",            // For TLS/SSL operations and certificate management
        "ca-certificates",    // For SSL certificate validation
        "systemd",            // For service management
        "docker.io"           // For container management operations
    };
    
    // Configuration paths
    const std::string INSTALL_DIR = "/usr/local/bin";
    const std::string CONFIG_DIR = "/etc/streamdeploy";
    const std::string PKI_DIR = "/etc/streamdeploy/pki";
    const std::string SERVICE_FILE = "/etc/systemd/system/streamdeploy-agent.service";
    const std::string API_BASE = "https://api.streamdeploy.com";
    const std::string HTTPS_MTLS_ENDPOINT = "https://device.streamdeploy.com";
    const std::string MQTT_WS_MTLS_ENDPOINT = "https://mqtt.streamdeploy.com";

public:
    StreamDeployInstaller() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    
    ~StreamDeployInstaller() {
        curl_global_cleanup();
    }
    
    bool run(int argc, char* argv[]) {
        std::cout << "[INFO] StreamDeploy Agent Installer Starting..." << std::endl;
        
        if (!check_root()) {
            std::cerr << "[ERROR] This installer must be run as root (use sudo)" << std::endl;
            return false;
        }
        
        if (!get_bootstrap_token(argc, argv)) {
            std::cerr << "[ERROR] Bootstrap token is required" << std::endl;
            std::cerr << "[INFO] Usage: sudo ./streamdeploy-installer <token>" << std::endl;
            std::cerr << "[INFO] Or: export SD_BOOTSTRAP_TOKEN=\"your-token\" && sudo ./streamdeploy-installer" << std::endl;
            return false;
        }
        
        if (!extract_device_id_from_jwt()) {
            std::cerr << "[ERROR] Failed to extract device_id from bootstrap token" << std::endl;
            return false;
        }
        
        if (!detect_system()) {
            std::cerr << "[ERROR] Failed to detect system information" << std::endl;
            return false;
        }
        
        if (!install_dependencies()) {
            std::cerr << "[ERROR] Failed to install system dependencies" << std::endl;
            return false;
        }
        
        if (!download_or_build_agent()) {
            std::cerr << "[ERROR] Failed to install StreamDeploy agent binary" << std::endl;
            return false;
        }
        
        if (!create_config()) {
            std::cerr << "[ERROR] Failed to create agent configuration" << std::endl;
            return false;
        }
        
        if (!perform_certificate_exchange()) {
            std::cerr << "[ERROR] Failed to perform certificate exchange" << std::endl;
            return false;
        }
        
        if (!create_systemd_service()) {
            std::cerr << "[ERROR] Failed to create systemd service" << std::endl;
            return false;
        }
        
        if (!start_service()) {
            std::cerr << "[ERROR] Failed to start service" << std::endl;
            return false;
        }
        
        std::cout << "[SUCCESS] StreamDeploy agent installation completed!" << std::endl;
        std::cout << "[INFO] Check status with: systemctl status streamdeploy-agent" << std::endl;
        std::cout << "[INFO] View logs with: journalctl -u streamdeploy-agent -f" << std::endl;
        
        return true;
    }

private:
    bool check_root() {
        return geteuid() == 0;
    }
    
    bool get_bootstrap_token(int argc, char* argv[]) {
        // First check command line argument
        if (argc >= 2 && strlen(argv[1]) > 0) {
            bootstrap_token = argv[1];
            std::cout << "[INFO] Bootstrap token provided via command line" << std::endl;
            return true;
        }
        
        // Fallback to environment variable
        const char* token = getenv("SD_BOOTSTRAP_TOKEN");
        if (token && strlen(token) > 0) {
            bootstrap_token = token;
            std::cout << "[INFO] Bootstrap token found in environment variable" << std::endl;
            return true;
        }
        
        return false;
    }
    
    bool extract_device_id_from_jwt() {
        // JWT has 3 parts separated by dots: header.payload.signature
        size_t first_dot = bootstrap_token.find('.');
        size_t second_dot = bootstrap_token.find('.', first_dot + 1);
        
        if (first_dot == std::string::npos || second_dot == std::string::npos) {
            return false;
        }
        
        std::string payload = bootstrap_token.substr(first_dot + 1, second_dot - first_dot - 1);
        
        // Add padding if needed for base64 decoding
        while (payload.length() % 4) {
            payload += "=";
        }
        
        // Decode base64 payload
        std::string decoded = base64_decode(payload);
        if (decoded.empty()) {
            return false;
        }
        
        // Parse JSON to extract device_id
        Json::Value root;
        Json::Reader reader;
        if (!reader.parse(decoded, root)) {
            return false;
        }
        
        if (!root.isMember("device_id") || !root["device_id"].isString()) {
            return false;
        }
        
        device_id = root["device_id"].asString();
        std::cout << "[INFO] Device ID extracted from JWT: " << device_id << std::endl;
        return true;
    }
    
    std::string base64_decode(const std::string& input) {
        BIO *bio, *b64;
        char* buffer = new char[input.length()];
        
        bio = BIO_new_mem_buf(input.c_str(), input.length());
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        int length = BIO_read(bio, buffer, input.length());
        BIO_free_all(bio);
        
        std::string result;
        if (length > 0) {
            result = std::string(buffer, length);
        }
        
        delete[] buffer;
        return result;
    }
    
    bool detect_system() {
        std::cout << "[INFO] Detecting system information..." << std::endl;
        
        // Detect architecture
        struct utsname uts;
        if (uname(&uts) != 0) {
            return false;
        }
        architecture = uts.machine;
        
        // Normalize architecture names
        if (architecture == "x86_64" || architecture == "amd64") {
            architecture = "x86_64";
        } else if (architecture == "aarch64" || architecture == "arm64") {
            architecture = "aarch64";
        } else if (architecture == "armv7l" || architecture == "armv6l") {
            architecture = "arm";
        }
        
        // Detect OS from /etc/os-release
        std::ifstream os_release("/etc/os-release");
        std::string line;
        std::map<std::string, std::string> os_info;
        
        while (std::getline(os_release, line)) {
            size_t eq_pos = line.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = line.substr(0, eq_pos);
                std::string value = line.substr(eq_pos + 1);
                // Remove quotes
                if (value.front() == '"' && value.back() == '"') {
                    value = value.substr(1, value.length() - 2);
                }
                os_info[key] = value;
            }
        }
        
        if (os_info.find("ID") != os_info.end()) {
            os_name = os_info["ID"];
        }
        if (os_info.find("VERSION_ID") != os_info.end()) {
            os_version = os_info["VERSION_ID"];
        }
        
        // Detect package manager and set commands
        if (system("command -v apt-get >/dev/null 2>&1") == 0) {
            package_manager["type"] = "apt";
            package_manager["install_cmd"] = "apt-get install -y";
            package_manager["check_cmd"] = "dpkg -l";
            package_manager["remove_cmd"] = "apt-get remove -y";
            package_manager["update_cmd"] = "apt-get update";
        } else if (system("command -v yum >/dev/null 2>&1") == 0) {
            package_manager["type"] = "yum";
            package_manager["install_cmd"] = "yum install -y";
            package_manager["check_cmd"] = "rpm -qa";
            package_manager["remove_cmd"] = "yum remove -y";
            package_manager["update_cmd"] = "yum update";
        } else if (system("command -v apk >/dev/null 2>&1") == 0) {
            package_manager["type"] = "apk";
            package_manager["install_cmd"] = "apk add";
            package_manager["check_cmd"] = "apk list --installed";
            package_manager["remove_cmd"] = "apk del";
            package_manager["update_cmd"] = "apk update";
        } else if (system("command -v pacman >/dev/null 2>&1") == 0) {
            package_manager["type"] = "pacman";
            package_manager["install_cmd"] = "pacman -S --noconfirm";
            package_manager["check_cmd"] = "pacman -Q";
            package_manager["remove_cmd"] = "pacman -R --noconfirm";
            package_manager["update_cmd"] = "pacman -Sy";
        } else {
            std::cerr << "[WARN] Unknown package manager" << std::endl;
            package_manager["type"] = "unknown";
        }
        
        std::cout << "[INFO] Detected OS: " << os_name << " " << os_version << std::endl;
        std::cout << "[INFO] Architecture: " << architecture << std::endl;
        std::cout << "[INFO] Package Manager: " << package_manager["type"] << std::endl;
        
        return true;
    }
    
    bool install_dependencies() {
        std::cout << "[INFO] Installing system dependencies..." << std::endl;
        
        if (package_manager["type"] == "unknown") {
            std::cout << "[WARN] Cannot install dependencies automatically" << std::endl;
            return true;
        }
        
        // Update package list
        std::string update_cmd = package_manager["update_cmd"];
        if (system(update_cmd.c_str()) != 0) {
            std::cout << "[WARN] Failed to update package list" << std::endl;
        }
        
        // Install required dependencies from the constant list
        for (const auto& pkg : REQUIRED_PACKAGES) {
            std::string install_cmd = package_manager["install_cmd"] + " " + pkg;
            if (system(install_cmd.c_str()) != 0) {
                std::cout << "[WARN] Failed to install " << pkg << std::endl;
            }
        }
        
        // Try to install systemd if not present
        if (package_manager["type"] != "apk") { // Alpine uses OpenRC
            std::string systemd_cmd = package_manager["install_cmd"] + " systemd";
            system(systemd_cmd.c_str()); // Don't fail if this doesn't work
        }
        
        return true;
    }
    
    bool download_or_build_agent() {
        std::cout << "[INFO] Installing StreamDeploy agent binary..." << std::endl;
        
        // For now, we'll assume the binary is provided or built separately
        // This is a placeholder for the actual binary installation logic
        std::cout << "[INFO] Agent binary installation placeholder" << std::endl;
        
        return true;
    }
    
    bool create_config() {
        std::cout << "[INFO] Creating agent configuration..." << std::endl;
        
        // Create directories
        if (mkdir(CONFIG_DIR.c_str(), 0755) != 0 && errno != EEXIST) {
            return false;
        }
        if (mkdir(PKI_DIR.c_str(), 0755) != 0 && errno != EEXIST) {
            return false;
        }
        if (mkdir("/var/lib/streamdeploy", 0755) != 0 && errno != EEXIST) {
            return false;
        }
        
        // Create agent.json with flat structure
        Json::Value config;
        config["device_id"] = device_id;
        config["enroll_base_url"] = API_BASE;
        config["https_mtls_endpoint"] = HTTPS_MTLS_ENDPOINT;
        config["mqtt_ws_mtls_endpoint"] = MQTT_WS_MTLS_ENDPOINT;
        config["pki_dir"] = PKI_DIR;
        config["os_name"] = os_name;
        config["os_version"] = os_version;
        config["architecture"] = architecture;
        
        // Add package manager commands
        Json::Value pkg_mgr;
        for (const auto& pair : package_manager) {
            pkg_mgr[pair.first] = pair.second;
        }
        config["package_manager"] = pkg_mgr;
        
        // Write configuration file
        std::ofstream config_file(CONFIG_DIR + "/agent.json");
        if (!config_file.is_open()) {
            return false;
        }
        
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "  ";
        std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
        writer->write(config, &config_file);
        config_file.close();
        
        // Set proper permissions
        chmod((CONFIG_DIR + "/agent.json").c_str(), 0644);
        
        // Create state.json with empty custom fields
        if (!create_state_json()) {
            return false;
        }
        
        std::cout << "[SUCCESS] Configuration created" << std::endl;
        return true;
    }
    
    bool perform_certificate_exchange() {
        std::cout << "[INFO] Performing certificate exchange..." << std::endl;
        
        std::string nonce, ca_bundle;
        
        // Step 1: Enroll start → get nonce and CA bundle
        if (!enroll_start(nonce, ca_bundle)) {
            std::cerr << "[ERROR] Failed to start enrollment" << std::endl;
            return false;
        }
        
        // Step 2: Generate EC P-256 key + CSR with SPIFFE SAN
        std::string private_key, csr;
        if (!generate_key_and_csr(private_key, csr)) {
            std::cerr << "[ERROR] Failed to generate key and CSR" << std::endl;
            return false;
        }
        
        // Step 3: Submit CSR and receive certificate
        std::string cert_pem, cert_chain;
        if (!enroll_csr(nonce, csr, cert_pem, cert_chain)) {
            std::cerr << "[ERROR] Failed to enroll CSR" << std::endl;
            return false;
        }
        
        // Step 4: Save certificates and key
        if (!save_certificates(private_key, cert_pem, cert_chain, ca_bundle)) {
            std::cerr << "[ERROR] Failed to save certificates" << std::endl;
            return false;
        }
        
        std::cout << "[SUCCESS] Certificate exchange completed" << std::endl;
        return true;
    }
    
    // HTTP response structure
    struct HttpResponse {
        std::string data;
        long response_code;
    };
    
    // Callback for curl to write response data
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, HttpResponse* response) {
        size_t total_size = size * nmemb;
        response->data.append((char*)contents, total_size);
        return total_size;
    }
    
    bool enroll_start(std::string& nonce, std::string& ca_bundle) {
        std::cout << "[INFO] Starting enrollment..." << std::endl;
        
        CURL* curl = curl_easy_init();
        if (!curl) return false;
        
        HttpResponse response;
        std::string url = API_BASE + "/v1-app/enroll/start";
        
        // Create JSON payload
        Json::Value payload;
        payload["enrollment_token"] = bootstrap_token;
        
        Json::StreamWriterBuilder builder;
        std::string json_data = Json::writeString(builder, payload);
        
        // Set curl options
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        
        // Set headers
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        // Perform request
        CURLcode res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.response_code);
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK || response.response_code != 200) {
            std::cerr << "[ERROR] Enrollment start failed: " << response.response_code << std::endl;
            return false;
        }
        
        // Parse response
        Json::Value root;
        Json::Reader reader;
        if (!reader.parse(response.data, root)) {
            return false;
        }
        
        if (!root.isMember("nonce") || !root.isMember("ca_bundle")) {
            return false;
        }
        
        nonce = root["nonce"].asString();
        ca_bundle = root["ca_bundle"].asString();
        
        std::cout << "[SUCCESS] Received nonce and CA bundle" << std::endl;
        return true;
    }
    
    bool generate_key_and_csr(std::string& private_key, std::string& csr) {
        std::cout << "[INFO] Generating EC P-256 key and CSR..." << std::endl;
        
        // Generate EC P-256 private key
        std::string key_file = PKI_DIR + "/device.key";
        std::string csr_file = PKI_DIR + "/device.csr";
        std::string config_file = PKI_DIR + "/san.cnf";
        
        // Create SAN config file
        std::ofstream config(config_file);
        config << "[ req ]\n";
        config << "distinguished_name = dn\n";
        config << "req_extensions = v3_req\n";
        config << "prompt = no\n";
        config << "[ dn ]\n";
        config << "CN = " << device_id << "\n";
        config << "[ v3_req ]\n";
        config << "subjectAltName = URI:spiffe://streamdeploy/device/" << device_id << "\n";
        config.close();
        
        // Generate private key
        std::string key_cmd = "openssl ecparam -name prime256v1 -genkey -noout -out " + key_file;
        if (system(key_cmd.c_str()) != 0) {
            return false;
        }
        
        // Generate CSR
        std::string csr_cmd = "openssl req -new -key " + key_file + " -out " + csr_file + " -config " + config_file;
        if (system(csr_cmd.c_str()) != 0) {
            return false;
        }
        
        // Read private key
        std::ifstream key_stream(key_file);
        if (!key_stream.is_open()) return false;
        private_key = std::string((std::istreambuf_iterator<char>(key_stream)),
                                  std::istreambuf_iterator<char>());
        key_stream.close();
        
        // Read CSR
        std::ifstream csr_stream(csr_file);
        if (!csr_stream.is_open()) return false;
        csr = std::string((std::istreambuf_iterator<char>(csr_stream)),
                          std::istreambuf_iterator<char>());
        csr_stream.close();
        
        // Set proper permissions
        chmod(key_file.c_str(), 0600);
        chmod(csr_file.c_str(), 0644);
        
        std::cout << "[SUCCESS] Generated key and CSR" << std::endl;
        return true;
    }
    
    bool enroll_csr(const std::string& nonce, const std::string& csr, 
                    std::string& cert_pem, std::string& cert_chain) {
        std::cout << "[INFO] Enrolling CSR..." << std::endl;
        
        CURL* curl = curl_easy_init();
        if (!curl) return false;
        
        HttpResponse response;
        std::string url = API_BASE + "/v1-app/enroll/csr";
        
        // Encode CSR to base64
        std::string csr_base64 = base64_encode(csr);
        
        // Create JSON payload
        Json::Value payload;
        payload["token"] = bootstrap_token;
        payload["nonce"] = nonce;
        payload["csr_base64"] = csr_base64;
        
        Json::StreamWriterBuilder builder;
        std::string json_data = Json::writeString(builder, payload);
        
        // Set curl options
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        
        // Set headers
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        // Perform request
        CURLcode res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.response_code);
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK || response.response_code != 200) {
            std::cerr << "[ERROR] CSR enrollment failed: " << response.response_code << std::endl;
            return false;
        }
        
        // Parse response
        Json::Value root;
        Json::Reader reader;
        if (!reader.parse(response.data, root)) {
            return false;
        }
        
        if (!root.isMember("cert_pem") || !root.isMember("chain")) {
            return false;
        }
        
        cert_pem = root["cert_pem"].asString();
        
        // Build certificate chain
        const Json::Value& chain = root["chain"];
        for (const auto& cert : chain) {
            cert_chain += cert.asString() + "\n";
        }
        
        std::cout << "[SUCCESS] Received signed certificate" << std::endl;
        return true;
    }
    
    std::string base64_encode(const std::string& input) {
        BIO *bio, *b64;
        BUF_MEM *buffer_ptr;
        
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, input.c_str(), input.length());
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &buffer_ptr);
        
        std::string result(buffer_ptr->data, buffer_ptr->length);
        BIO_free_all(bio);
        
        return result;
    }
    
    bool save_certificates(const std::string& private_key, const std::string& cert_pem,
                          const std::string& cert_chain, const std::string& ca_bundle) {
        std::cout << "[INFO] Saving certificates..." << std::endl;
        
        // Save private key
        std::string key_file = PKI_DIR + "/device.key";
        std::ofstream key_stream(key_file);
        if (!key_stream.is_open()) return false;
        key_stream << private_key;
        key_stream.close();
        chmod(key_file.c_str(), 0600);
        
        // Save certificate with full chain
        std::string cert_file = PKI_DIR + "/device.crt";
        std::ofstream cert_stream(cert_file);
        if (!cert_stream.is_open()) return false;
        cert_stream << cert_pem << "\n" << cert_chain;
        cert_stream.close();
        chmod(cert_file.c_str(), 0644);
        
        // Save CA bundle
        std::string ca_file = PKI_DIR + "/ca.crt";
        std::ofstream ca_stream(ca_file);
        if (!ca_stream.is_open()) return false;
        ca_stream << ca_bundle;
        ca_stream.close();
        chmod(ca_file.c_str(), 0644);
        
        std::cout << "[SUCCESS] Certificates saved to " << PKI_DIR << std::endl;
        return true;
    }
    
    bool create_systemd_service() {
        std::cout << "[INFO] Creating systemd service..." << std::endl;
        
        std::ofstream service_file(SERVICE_FILE);
        if (!service_file.is_open()) {
            return false;
        }
        
        service_file << "[Unit]\n";
        service_file << "Description=StreamDeploy Agent\n";
        service_file << "After=network.target\n\n";
        service_file << "[Service]\n";
        service_file << "Type=simple\n";
        service_file << "User=root\n";
        service_file << "ExecStart=" << INSTALL_DIR << "/streamdeploy-agent " << CONFIG_DIR << "/agent.json\n";
        service_file << "Restart=always\n";
        service_file << "RestartSec=10\n\n";
        service_file << "[Install]\n";
        service_file << "WantedBy=multi-user.target\n";
        
        service_file.close();
        chmod(SERVICE_FILE.c_str(), 0644);
        
        std::cout << "[SUCCESS] Systemd service created" << std::endl;
        return true;
    }
    
    bool start_service() {
        std::cout << "[INFO] Starting StreamDeploy agent service..." << std::endl;
        
        if (system("command -v systemctl >/dev/null 2>&1") != 0) {
            std::cout << "[WARN] systemctl not available" << std::endl;
            return true;
        }
        
        system("systemctl daemon-reload");
        system("systemctl enable streamdeploy-agent");
        
        if (system("systemctl start streamdeploy-agent") == 0) {
            std::cout << "[SUCCESS] StreamDeploy agent service started" << std::endl;
        } else {
            std::cout << "[WARN] Service may have issues, check: systemctl status streamdeploy-agent" << std::endl;
        }
        
        return true;
    }
    
    bool create_state_json() {
        std::cout << "[INFO] Creating state.json with empty custom fields..." << std::endl;
        
        // Create state.json structure based on the existing config/state.json
        // but with empty custom_packages, custom_metrics, and containers
        Json::Value state;
        
        // Schema version
        state["schemaVersion"] = "1.0";
        
        // Agent settings
        Json::Value agent_setting;
        agent_setting["heartbeat_frequency"] = "15s";
        agent_setting["update_frequency"] = "30s";
        agent_setting["mode"] = "http";
        agent_setting["agent_ver"] = "1";
        state["agent_setting"] = agent_setting;
        
        // Empty containers array
        state["containers"] = Json::Value(Json::arrayValue);
        
        // Empty container login
        state["containerLogin"] = "";
        
        // Empty environment variables
        state["env"] = Json::Value(Json::objectValue);
        
        // Basic required packages from REQUIRED_PACKAGES plus systemd and docker
        Json::Value packages(Json::arrayValue);
        for (const auto& pkg : REQUIRED_PACKAGES) {
            packages.append(pkg);
        }

        state["packages"] = packages;
        
        // Empty custom_metrics object
        state["custom_metrics"] = Json::Value(Json::objectValue);
        
        // Empty custom_packages object
        state["custom_packages"] = Json::Value(Json::objectValue);
        
        // Write state.json file
        std::string state_file = CONFIG_DIR + "/state.json";
        std::ofstream state_stream(state_file);
        if (!state_stream.is_open()) {
            std::cerr << "[ERROR] Failed to create state.json file" << std::endl;
            return false;
        }
        
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "  ";
        std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
        writer->write(state, &state_stream);
        state_stream.close();
        
        // Set proper permissions
        chmod(state_file.c_str(), 0644);
        
        std::cout << "[SUCCESS] Created state.json with empty custom fields" << std::endl;
        return true;
    }
};

int main(int argc, char* argv[]) {
    StreamDeployInstaller installer;
    return installer.run(argc, argv) ? 0 : 1;
}
