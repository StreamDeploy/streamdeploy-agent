#include "agent.h"
#include "http_client.h"
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <thread>
#include <array>
#include <sstream>

using json = nlohmann::json;
namespace fs = std::filesystem;

/*==================  AgentConfig  ==================*/

AgentConfig AgentConfig::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open config: " + path);
    json j; in >> j;

    AgentConfig c;
    c.deviceId        = j.at("device_id").get<std::string>();
    c.deviceClass     = j.value("device_class","sbc");
    c.baseUrl         = j.at("base_url").get<std::string>();
    c.statusPath      = j.value("status_path","/v1-device/status-update");
    c.heartbeatPath   = j.value("heartbeat_path","/v1-device/heartbeat");
    // Enrollment + device plane (optional)
    c.enrollBaseUrl   = j.value("enroll_base_url", "");
    c.deviceBaseUrl   = j.value("device_base_url", "");
    c.pkiDir          = j.value("pki_dir","/etc/streamdeploy/pki");
    c.autoEnroll      = j.value("auto_enroll", true);

    c.caCertPath      = j.value("ca_cert_path","/etc/ssl/certs/ca-certificates.crt");
    c.clientCertPath  = j.at("client_cert_path").get<std::string>();
    c.clientKeyPath   = j.at("client_key_path").get<std::string>();
    c.clientKeyPass   = j.value("client_key_pass","");

    c.maxLogBuffer    = j.value("max_log_buffer",200);

    c.appPort         = j.value("app_port",8080);
    c.nextPort        = j.value("next_port",8081);
    c.healthPath      = j.value("health_path","/healthz");
    c.healthWaitSeconds = j.value("health_wait_seconds",25);
    c.heartbeatIntervalSeconds = j.value("heartbeat_interval_seconds",90);
    c.bootstrapToken   = j.value("bootstrap_token","");

    c.containerName   = j.value("container_name","sd-app");
    c.extraDockerArgs = j.value("extra_docker_args","--gpus all");
    c.stateFile       = j.value("state_file","/var/lib/streamdeploy/state.json");

    // SSH tunnel configuration
    c.sshBastionHost  = j.value("ssh_bastion_host", "34.170.221.16");
    c.sshBastionUser  = j.value("ssh_bastion_user", "tonyloehr");
    c.sshBastionPort  = j.value("ssh_bastion_port", 22);
    c.sshTunnelEnabled = j.value("ssh_tunnel_enabled", true);
    c.sshTunnelPort   = j.value("ssh_tunnel_port", 0);
    c.sshKeyPath      = j.value("ssh_key_path", c.pkiDir + "/ssh_" + c.deviceId);
    c.sshPubKeyPath   = j.value("ssh_pubkey_path", c.pkiDir + "/ssh_" + c.deviceId + ".pub");

    // Secret file paths (for provisioning-time secret injection)
    c.sshBastionHostFile = j.value("ssh_bastion_host_file", "/etc/streamdeploy/secrets/ssh_bastion_host");
    c.sshBastionUserFile = j.value("ssh_bastion_user_file", "/etc/streamdeploy/secrets/ssh_bastion_user");
    c.bootstrapTokenFile = j.value("bootstrap_token_file", "/etc/streamdeploy/secrets/bootstrap_token");
    c.enrollBaseUrlFile  = j.value("enroll_base_url_file", "/etc/streamdeploy/secrets/enroll_base_url");
    c.deviceBaseUrlFile  = j.value("device_base_url_file", "/etc/streamdeploy/secrets/device_base_url");

    // Apply secret file precedence: file > config > default
    c.sshBastionHost = loadSecretFromFile(c.sshBastionHostFile, c.sshBastionHost, "ssh_bastion_host");
    c.sshBastionUser = loadSecretFromFile(c.sshBastionUserFile, c.sshBastionUser, "ssh_bastion_user");
    c.bootstrapToken = loadSecretFromFile(c.bootstrapTokenFile, c.bootstrapToken, "bootstrap_token");
    c.enrollBaseUrl  = loadSecretFromFile(c.enrollBaseUrlFile, c.enrollBaseUrl, "enroll_base_url");
    c.deviceBaseUrl  = loadSecretFromFile(c.deviceBaseUrlFile, c.deviceBaseUrl, "device_base_url");

    return c;
}

/*==================  Utilities  ==================*/

std::string Agent::run(const std::string& cmd) {
    std::array<char, 512> buf{};
    std::string out;
    FILE* pipe = popen((cmd + " 2>&1").c_str(), "r");
    if (!pipe) return out;
    while (fgets(buf.data(), buf.size(), pipe)) out += buf.data();
    pclose(pipe);
    return out;
}

bool Agent::urlHealthy(const std::string& url, int timeoutMs) {
    try {
        // 2xx returns body; we only need success code
        (void) http->getAbs(url, {}, timeoutMs);
        return true;
    } catch (...) { return false; }
}

json Agent::loadState() {
    std::ifstream in(cfg.stateFile);
    if (!in) return json::object();
    json j; in >> j; return j;
}

void Agent::saveState(const json& st) {
    fs::create_directories(fs::path(cfg.stateFile).parent_path());
    std::ofstream out(cfg.stateFile);
    out << st.dump(2);
}

/*==================  Agent core  ==================*/

Agent::Agent(const std::string& configPath) : cfg(AgentConfig::load(configPath)), cfgPath(configPath) {
    http = new HttpClient(cfg.baseUrl, cfg.caCertPath, cfg.clientCertPath,
                          cfg.clientKeyPath, cfg.clientKeyPass);
    lastLogFlush = std::chrono::steady_clock::now();
    fs::create_directories(fs::path(cfg.stateFile).parent_path());
}

Agent::~Agent() { delete http; }

void Agent::reinitHttp() {
    delete http;
    http = new HttpClient(cfg.baseUrl, cfg.caCertPath, cfg.clientCertPath, cfg.clientKeyPath, cfg.clientKeyPass);
}

void Agent::saveConfigJson() {
    try {
        std::ifstream in(cfgPath);
        if (!in) return;
        json j; in >> j;
        j["base_url"]         = cfg.baseUrl;
        j["ca_cert_path"]     = cfg.caCertPath;
        j["client_cert_path"] = cfg.clientCertPath;
        j["client_key_path"]  = cfg.clientKeyPath;
        j["client_key_pass"]  = cfg.clientKeyPass;
        std::string tmp = cfgPath + ".tmp";
        { std::ofstream out(tmp); out << j.dump(2); }
        fs::rename(tmp, cfgPath);
    } catch (...) {
        // best-effort; do not throw from agent loop
    }
}

void Agent::performEnrollmentIfNeeded() {
    if (!cfg.autoEnroll) return;
    auto st = loadState();
    if (st.value("enrolled", false)) return;
    if (cfg.bootstrapToken.empty()) return;

    // If certs already present, assume enrolled
    if (!cfg.clientCertPath.empty() && fs::exists(cfg.clientCertPath) &&
        !cfg.clientKeyPath.empty()  && fs::exists(cfg.clientKeyPath)) {
        return;
    }

    try {
        fs::create_directories(cfg.pkiDir);
        const std::string key = cfg.pkiDir + "/device.key";
        const std::string csr = cfg.pkiDir + "/device.csr";
        const std::string crt = cfg.pkiDir + "/device.crt";
        const std::string ca  = cfg.pkiDir + "/ca.pem";

        if (!fs::exists(key)) {
            run("openssl ecparam -genkey -name prime256v1 -noout -out " + key);
            run("chmod 600 " + key);
        }

        // Generate CSR with SPIFFE + DNS SAN
        const std::string subj = "/CN=" + cfg.deviceId;
        const std::string san  = "subjectAltName=DNS:" + cfg.deviceId + ",URI:spiffe://streamdeploy/device/" + cfg.deviceId;
        run("openssl req -new -key " + key + " -out " + csr + " -subj '" + subj + "' -addext '" + san + "'");

        // Bootstrap via enroll base (fallback to baseUrl)
        const std::string enrollBase = cfg.enrollBaseUrl.empty() ? cfg.baseUrl : cfg.enrollBaseUrl;
        HttpClient eh(enrollBase, "", "", "", "");

        json startReq = {{"enrollment_token", cfg.bootstrapToken}};
        json start    = json::parse(eh.postJson("/v1-app/enroll/start", startReq));
        const std::string nonce     = start.at("nonce").get<std::string>();
        const std::string ca_bundle = start.at("ca_bundle").get<std::string>();
        { std::ofstream out(ca); out << ca_bundle; }
        run("chmod 644 " + ca);

        // Submit CSR (base64 encoded as expected by platform)
        const std::string csrPem = run("cat " + csr);
        const std::string csrBase64 = run("echo '" + csrPem + "' | base64 -w 0");
        json csrReq = {{"token", cfg.bootstrapToken}, {"nonce", nonce}, {"csr_base64", csrBase64}};
        json csrOut = json::parse(eh.postJson("/v1-app/enroll/csr", csrReq));

        { std::ofstream out(crt);
          out << csrOut.at("cert_pem").get<std::string>() << "\n";
          for (auto& c : csrOut.at("chain")) out << c.get<std::string>() << "\n";
        }
        run("chmod 644 " + crt);

        // Point agent to mTLS device plane
        cfg.caCertPath     = ca;
        cfg.clientKeyPath  = key;
        cfg.clientCertPath = crt;
        if (!cfg.deviceBaseUrl.empty()) cfg.baseUrl = cfg.deviceBaseUrl;

        saveConfigJson();
        reinitHttp();

        st["enrolled"] = true;
        saveState(st);
        logInfo("Enrollment complete; switched to mTLS");

        // Setup SSH keys and tunnel after successful enrollment
        if (cfg.sshTunnelEnabled) {
            try {
                setupSSHKeys();
                establishSSHTunnel();
                logInfo("SSH tunnel setup complete");
            } catch (const std::exception& e) {
                logError(std::string("SSH setup failed: ") + e.what());
            }
        }
    } catch (const std::exception& e) {
        logError(std::string("enrollment failed: ") + e.what());
    }
}

void Agent::logInfo(const std::string& m)  {
    if (logBuf.size() >= cfg.maxLogBuffer) logBuf.erase(logBuf.begin());
    logBuf.push_back({{"ts", (long long)std::time(nullptr)}, {"level","info"}, {"msg",m}});
    appendLogFile("info", m);
}
void Agent::logError(const std::string& m) {
    if (logBuf.size() >= cfg.maxLogBuffer) logBuf.erase(logBuf.begin());
    logBuf.push_back({{"ts", (long long)std::time(nullptr)}, {"level","error"}, {"msg",m}});
    appendLogFile("error", m);
}

void Agent::flushLogsInto(json& statusPayload) {
    if (logBuf.empty()) return;
    statusPayload["logs"] = logBuf;
    logBuf.clear();
}

void Agent::appendLogFile(const std::string& level, const std::string& m) {
    try {
        fs::create_directories("/var/log/streamdeploy-agent");
        std::ofstream f("/var/log/streamdeploy-agent/agent.log", std::ios::app);
        long long ts = (long long)std::time(nullptr);
        f << ts << " [" << level << "] " << m << "\n";
    } catch (...) {
        // best-effort logging to file
    }
}

/*==================  Payloads  ==================*/

json Agent::buildDeviceFacts() {
    // Keep it small & cross-platform
    json facts;
    facts["device_id"]   = cfg.deviceId;
    facts["device_class"]= cfg.deviceClass;

    // Kernel/OS
    facts["uname"]   = run("uname -a");
    facts["os_release"] = run("cat /etc/os-release | tr -d '\\n'");

    // CPU/GPU quick facts (best-effort; ignore failures)
    facts["cpuinfo"] = run("grep -m1 'model name' /proc/cpuinfo || true");
    facts["meminfo"] = run("grep -m1 'MemTotal' /proc/meminfo || true");
    facts["gpu"]     = run("nvidia-smi --query-gpu=name,compute_cap --format=csv,noheader 2>/dev/null || true");

    return facts;
}

json Agent::buildStatusUpdatePayload() {
    auto st = loadState();

    // Determine update type
    bool enrolled = st.value("enrolled", false);
    std::string updateType = (!enrolled && !cfg.bootstrapToken.empty()) ? "enrollment" : "update_check";

    // Build current_state payload matching your exact format
    json current;
    
    // Agent settings
    current["agent_setting"] = {
        {"heartbeat_frequency", std::to_string(cfg.heartbeatIntervalSeconds) + "s"},
        {"update_frequency", "30s"},
        {"agent_ver", "1"}
    };
    
    // Environment variables
    current["env"] = collectEnvironmentVariables();
    
    // Detailed container information
    json containers = json::array();
    try {
        // Get detailed container info including environment and probing
        std::string dockerCmd = "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' --no-trunc";
        std::string dockerOutput = run(dockerCmd);
        
        if (!dockerOutput.empty()) {
            std::istringstream stream(dockerOutput);
            std::string line;
            bool firstLine = true;
            
            while (std::getline(stream, line)) {
                if (firstLine) {
                    firstLine = false;
                    continue; // Skip header
                }
                
                if (line.empty()) continue;
                
                // Parse container info
                std::istringstream lineStream(line);
                std::string name, image, status;
                
                if (std::getline(lineStream, name, '\t') &&
                    std::getline(lineStream, image, '\t') &&
                    std::getline(lineStream, status)) {
                    
                    json container;
                    container["name"] = name;
                    container["image"] = image;
                    container["env"] = json::object(); // Container-specific env vars would go here
                    
                    // Add probing URL if this is the main app container
                    if (name == cfg.containerName) {
                        container["probing"] = "http://localhost:" + std::to_string(cfg.appPort) + cfg.healthPath;
                    } else {
                        container["probing"] = "";
                    }
                    
                    // Determine status based on docker status
                    if (status.find("Up") != std::string::npos) {
                        container["status"] = "ready";
                    } else {
                        container["status"] = "stopped";
                    }
                    
                    containers.push_back(container);
                }
            }
        }
        
        // If no containers found, add a placeholder for the main app container
        if (containers.empty()) {
            json container;
            container["name"] = cfg.containerName;
            container["image"] = st.value("current_digest", st.value("current_image", "unknown"));
            container["env"] = json::object();
            container["probing"] = "http://localhost:" + std::to_string(cfg.appPort) + cfg.healthPath;
            container["status"] = "stopped";
            containers.push_back(container);
        }
        
    } catch (...) {
        // Fallback container info
        json container;
        container["name"] = cfg.containerName;
        container["image"] = st.value("current_digest", st.value("current_image", "unknown"));
        container["env"] = json::object();
        container["probing"] = "http://localhost:" + std::to_string(cfg.appPort) + cfg.healthPath;
        container["status"] = "unknown";
        containers.push_back(container);
    }
    
    current["containers"] = containers;
    
    // Scripts
    current["scripts"] = collectScripts();

    json payload;
    payload["update_type"] = updateType;
    payload["status"] = "normal"; // DeviceStatus expected by backend ("normal" or "degraded")
    payload["current_state"] = current;

    // ship buffered logs with status update (embed inside current_state to match backend schema)
    flushLogsInto(current);
    
    // Add SSH tunnel status to current_state
    updateSSHState(current);
    
    // assign accumulated current_state
    payload["current_state"] = current;

    return payload;
}

/*==================  Actions / Updates  ==================*/

void Agent::deployContainerAB(const std::string& image, const std::string& version,
                              const json& env, const std::string& args) {
    logInfo("Deploying image=" + image + " version=" + version);

    // 1) Pull
    if (system(("docker pull " + image).c_str()) != 0)
        throw std::runtime_error("docker pull failed");

    // 2) Prepare env flags
    std::string envFlags;
    if (env.is_object()) {
        for (auto it = env.begin(); it != env.end(); ++it) {
            envFlags += " -e " + it.key() + "=\"" + it.value().get<std::string>() + "\"";
        }
    }

    // 3) Kill any stale next
    system(("docker rm -f " + cfg.containerName + "-next >/dev/null 2>&1").c_str());

    // 4) Run next on staging port
    std::string runCmd = "docker run -d --restart=always --name "
      + cfg.containerName + "-next " + cfg.extraDockerArgs + envFlags + " "
      + "-p " + std::to_string(cfg.nextPort) + ":" + std::to_string(cfg.appPort) + " "
      + image + " " + args;

    if (system(runCmd.c_str()) != 0)
        throw std::runtime_error("docker run next failed");

    // 5) Health wait
    std::string healthURL = "http://127.0.0.1:" + std::to_string(cfg.nextPort) + cfg.healthPath;
    bool ok = false;
    for (int i=0; i<cfg.healthWaitSeconds; ++i) {
        if (urlHealthy(healthURL, 1500)) { ok = true; break; }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if (!ok) {
        system(("docker rm -f " + cfg.containerName + "-next >/dev/null 2>&1").c_str());
        throw std::runtime_error("healthcheck failed; rollback kept previous live");
    }

    // 6) Promote
    system(("docker rm -f " + cfg.containerName + " >/dev/null 2>&1").c_str());
    if (system(("docker rename " + cfg.containerName + "-next " + cfg.containerName).c_str()) != 0)
        throw std::runtime_error("promotion (rename) failed");

    // 7) Persist state
    auto st = loadState();
    st["current_version"] = version;
    st["current_image"]   = image;
    st["current_digest"]  = image;
    saveState(st);

    logInfo("Promoted version=" + version);
}

void Agent::actOnDesired(const json& desired) {
    if (!desired.is_object()) return;

    // New contract: desired_state { app_digest, env, config }
    if (desired.contains("app_digest")) {
        const std::string app_digest = desired.value("app_digest", "");
        const json env               = desired.value("env", json::object());
        if (app_digest.empty()) return;

        auto st = loadState();
        const std::string current = st.value("current_digest", st.value("current_image",""));

        if (current == app_digest) {
            logInfo("desired app_digest matches current; no-op");
            return;
        }

        try {
            // Use digest as both image and version (version can be derived upstream)
            deployContainerAB(app_digest, app_digest, env, "");
            // Success confirmation (best-effort)
            json okPayload = {
                {"update_type", "rollout_complete"},
                {"status", "normal"},
                {"current_state", {
                    {"current_digest", app_digest},
                    {"container", cfg.containerName},
                    {"device_class", cfg.deviceClass}
                }}
            };
            try { http->postJson(cfg.statusPath, okPayload, {{"X-Device-Id", cfg.deviceId}}); } catch (...) {}
        } catch (const std::exception& e) {
            logError(std::string("deploy failed: ") + e.what());
            json failPayload = {
                {"update_type", "rollout_complete"},
                {"status", "degraded"},
                {"current_state", {
                    {"last_error", e.what()},
                    {"container", cfg.containerName},
                    {"device_class", cfg.deviceClass}
                }}
            };
            try { http->postJson(cfg.statusPath, failPayload, {{"X-Device-Id", cfg.deviceId}}); } catch (...) {}
        }
        return;
    }

    // Legacy contract support (action-style)
    const std::string action = desired.value("action","noop");
    if (action == "noop") return;

    if (action == "deploy_container") {
        const std::string image   = desired.at("image").get<std::string>();
        const std::string version = desired.value("version","unknown");
        const std::string args    = desired.value("args","");
        const json env            = desired.value("env", json::object());
        try {
            deployContainerAB(image, version, env, args);
            // Send a quick status confirmation (best-effort)
            json okPayload = {
                {"device_id", cfg.deviceId},
                {"event", "update_ok"},
                {"version", version},
                {"image", image}
            };
            http->postJson(cfg.statusPath, okPayload, {
                {"X-Device-Id", cfg.deviceId}
            });
        } catch (const std::exception& e) {
            logError(std::string("update failed: ") + e.what());
            json failPayload = {
                {"device_id", cfg.deviceId},
                {"event", "update_failed"},
                {"error", e.what()}
            };
            try { http->postJson(cfg.statusPath, failPayload, {{"X-Device-Id", cfg.deviceId}}); } catch (...) {}
        }
        return;
    }

    if (action == "rollback_container") {
        // With A/B, if promotion failed we're already rolled back.
        // For a forced rollback, you could re-run a pinned prior image digest here.
        logInfo("forced rollback requested (no-op without stored prior digest)");
        return;
    }

    // Future actions: reboot, run-script, update-binary, etc.
}

/*==================  Metrics Collection  ==================*/

json Agent::collectSystemMetrics() {
    json metrics;
    
    try {
        // CPU percentage - get from /proc/stat
        std::string cpuLine = run("head -1 /proc/stat");
        if (!cpuLine.empty()) {
            // Parse CPU stats and calculate percentage (simplified approach)
            std::string cpuUsage = run("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | sed 's/%us,//' || echo '0.0'");
            if (!cpuUsage.empty()) {
                try {
                    metrics["cpu_pct"] = std::stod(cpuUsage);
                } catch (...) {
                    metrics["cpu_pct"] = 0.0;
                }
            } else {
                metrics["cpu_pct"] = 0.0;
            }
        } else {
            metrics["cpu_pct"] = 0.0;
        }
    } catch (...) {
        metrics["cpu_pct"] = 0.0;
    }
    
    try {
        // Memory percentage - get from /proc/meminfo
        std::string memTotal = run("grep '^MemTotal:' /proc/meminfo | awk '{print $2}' || echo '0'");
        std::string memAvail = run("grep '^MemAvailable:' /proc/meminfo | awk '{print $2}' || echo '0'");
        
        if (!memTotal.empty() && !memAvail.empty()) {
            try {
                double total = std::stod(memTotal);
                double avail = std::stod(memAvail);
                if (total > 0) {
                    double used_pct = ((total - avail) / total) * 100.0;
                    metrics["mem_pct"] = used_pct;
                } else {
                    metrics["mem_pct"] = 0.0;
                }
            } catch (...) {
                metrics["mem_pct"] = 0.0;
            }
        } else {
            metrics["mem_pct"] = 0.0;
        }
    } catch (...) {
        metrics["mem_pct"] = 0.0;
    }
    
    return metrics;
}

json Agent::collectContainerMetrics() {
    json containers = json::array();
    
    try {
        // Get running containers with detailed info
        std::string dockerCmd = "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' --no-trunc";
        std::string dockerOutput = run(dockerCmd);
        
        if (!dockerOutput.empty()) {
            std::istringstream stream(dockerOutput);
            std::string line;
            bool firstLine = true;
            
            while (std::getline(stream, line)) {
                if (firstLine) {
                    firstLine = false;
                    continue; // Skip header
                }
                
                if (line.empty()) continue;
                
                // Parse container info
                std::istringstream lineStream(line);
                std::string name, image, status;
                
                if (std::getline(lineStream, name, '\t') &&
                    std::getline(lineStream, image, '\t') &&
                    std::getline(lineStream, status)) {
                    
                    json container;
                    container["name"] = name;
                    container["image"] = image;
                    
                    // Determine status based on docker status
                    if (status.find("Up") != std::string::npos) {
                        container["status"] = "ready";
                    } else {
                        container["status"] = "stopped";
                    }
                    
                    containers.push_back(container);
                }
            }
        }
        
        // If no containers found, add a placeholder for the main app container
        if (containers.empty()) {
            json container;
            container["name"] = cfg.containerName;
            container["image"] = "unknown";
            container["status"] = "stopped";
            containers.push_back(container);
        }
        
    } catch (...) {
        // Fallback container info
        json container;
        container["name"] = cfg.containerName;
        container["image"] = "unknown";
        container["status"] = "unknown";
        containers.push_back(container);
    }
    
    return containers;
}

json Agent::collectCustomMetrics() {
    json custom;
    
    try {
        // Load custom metrics from config file if it exists
        std::string customMetricsFile = "/etc/streamdeploy/custom_metrics.json";
        if (fs::exists(customMetricsFile)) {
            std::ifstream in(customMetricsFile);
            if (in) {
                json customConfig;
                in >> customConfig;
                
                // Execute custom metric commands
                for (auto& [key, value] : customConfig.items()) {
                    if (value.is_string()) {
                        std::string result = run(value.get<std::string>());
                        if (!result.empty()) {
                            // Remove trailing newline
                            if (result.back() == '\n') result.pop_back();
                            custom[key] = result;
                        }
                    } else {
                        custom[key] = value;
                    }
                }
            }
        }
        
        // Add default test metric if no custom metrics
        if (custom.empty()) {
            custom["test"] = "ok";
        }
        
    } catch (...) {
        custom["test"] = "ok";
    }
    
    return custom;
}

json Agent::collectEnvironmentVariables() {
    json env;
    
    try {
        // Load environment variables from config file if it exists
        std::string envFile = "/etc/streamdeploy/environment.json";
        if (fs::exists(envFile)) {
            std::ifstream in(envFile);
            if (in) {
                in >> env;
            }
        }
        
        // Add some default environment variables if none configured
        if (env.empty()) {
            env["DEVICE_ID"] = cfg.deviceId;
            env["DEVICE_CLASS"] = cfg.deviceClass;
        }
        
    } catch (...) {
        env["DEVICE_ID"] = cfg.deviceId;
        env["DEVICE_CLASS"] = cfg.deviceClass;
    }
    
    return env;
}

json Agent::collectScripts() {
    json scripts = json::array();
    
    try {
        // Load scripts from config file if it exists
        std::string scriptsFile = "/etc/streamdeploy/scripts.json";
        if (fs::exists(scriptsFile)) {
            std::ifstream in(scriptsFile);
            if (in) {
                in >> scripts;
            }
        }
        
        // Add default script if none configured
        if (scripts.empty()) {
            json script;
            script["name"] = "health_check";
            script["cmd"] = "echo 'healthy'";
            scripts.push_back(script);
        }
        
    } catch (...) {
        json script;
        script["name"] = "health_check";
        script["cmd"] = "echo 'healthy'";
        scripts.push_back(script);
    }
    
    return scripts;
}

/*==================  Heartbeat Storage  ==================*/

void Agent::saveHeartbeatData(const json& heartbeat) {
    try {
        std::string heartbeatFile = "/var/lib/streamdeploy/heartbeat.json";
        fs::create_directories(fs::path(heartbeatFile).parent_path());
        
        // Load existing heartbeats
        json heartbeats = json::array();
        if (fs::exists(heartbeatFile)) {
            std::ifstream in(heartbeatFile);
            if (in) {
                try {
                    in >> heartbeats;
                    if (!heartbeats.is_array()) {
                        heartbeats = json::array();
                    }
                } catch (...) {
                    heartbeats = json::array();
                }
            }
        }
        
        // Add timestamp to heartbeat
        json timestampedHeartbeat = heartbeat;
        timestampedHeartbeat["timestamp"] = std::time(nullptr);
        
        // Add new heartbeat
        heartbeats.push_back(timestampedHeartbeat);
        
        // Keep only last 100 heartbeats
        if (heartbeats.size() > 100) {
            heartbeats.erase(heartbeats.begin(), heartbeats.end() - 100);
        }
        
        // Save atomically
        std::string tmpFile = heartbeatFile + ".tmp";
        {
            std::ofstream out(tmpFile);
            out << heartbeats.dump(2);
        }
        fs::rename(tmpFile, heartbeatFile);
        
    } catch (...) {
        // Best effort - don't fail if storage fails
    }
}

json Agent::loadLastHeartbeat() {
    try {
        std::string heartbeatFile = "/var/lib/streamdeploy/heartbeat.json";
        if (fs::exists(heartbeatFile)) {
            std::ifstream in(heartbeatFile);
            if (in) {
                json heartbeats;
                in >> heartbeats;
                if (heartbeats.is_array() && !heartbeats.empty()) {
                    return heartbeats.back();
                }
            }
        }
    } catch (...) {
        // Return empty if loading fails
    }
    
    return json::object();
}

/*==================  Heartbeat  ==================*/

void Agent::sendHeartbeat() {
    // Build new heartbeat format matching your specification
    json systemMetrics = collectSystemMetrics();
    json containers = collectContainerMetrics();
    json custom = collectCustomMetrics();
    
    json hb{
        {"status", "normal"},
        {"agent_setting", {
            {"heartbeat_frequency", std::to_string(cfg.heartbeatIntervalSeconds) + "s"},
            {"update_frequency", "30s"},
            {"agent_ver", "1"}
        }},
        {"metrics", {
            {"cpu_pct", systemMetrics.value("cpu_pct", 0.0)},
            {"mem_pct", systemMetrics.value("mem_pct", 0.0)},
            {"containers", containers},
            {"custom", custom}
        }}
    };
    
    // Save heartbeat data locally
    saveHeartbeatData(hb);
    
    // Send to platform (best-effort; ignore errors)
    try {
        http->postJson(cfg.heartbeatPath, hb, {{"X-Device-Id", cfg.deviceId}});
    } catch (...) {}
}

/*==================  tick()  ==================*/

void Agent::tick() {
    // Attempt auto-enrollment (no-op if already enrolled or disabled)
    performEnrollmentIfNeeded();

    // Load state for headers (If-None-Match and enrollment)
    auto st = loadState();
    std::vector<std::pair<std::string,std::string>> headers = {{"X-Device-Id", cfg.deviceId}};
    if (!st.value("enrolled", false) && !cfg.bootstrapToken.empty()) {
        headers.emplace_back("X-Bootstrap-Token", cfg.bootstrapToken);
    }
    const std::string lastEtag = st.value("last_etag", "");
    if (!lastEtag.empty()) headers.emplace_back("If-None-Match", lastEtag);

    // 1) Build status payload and pull desired state
    json status = buildStatusUpdatePayload();
    try {
        HttpResponse r = http->postJsonWithMeta(cfg.statusPath, status, headers);
        if (r.status == 304) {
            // Not modified; skip acting on desired
        } else if (r.status >= 200 && r.status < 300) {
            if (!r.body.empty()) {
                json resp = json::parse(r.body, nullptr, true);
                if (resp.contains("desired_state"))
                    actOnDesired(resp["desired_state"]);
            }
            auto it = r.headers.find("etag");
            if (it != r.headers.end()) st["last_etag"] = it->second;
            st["enrolled"] = true;
            saveState(st);
        }
    } catch (const std::exception& e) {
        logError(std::string("status-update failed: ") + e.what());
    }

    // 2) SSH tunnel health monitoring (if enabled)
    if (cfg.sshTunnelEnabled) {
        monitorSSHTunnelHealth();
    }

    // 3) Heartbeat (best-effort)
    sendHeartbeat();
}

/*==================  SSH Management  ==================*/

void Agent::setupSSHKeys() {
    if (!cfg.sshTunnelEnabled) return;

    // Generate SSH key pair if it doesn't exist
    if (!fs::exists(cfg.sshKeyPath)) {
        logInfo("Generating SSH key pair for device: " + cfg.deviceId);
        
        // Generate ed25519 key pair
        std::string genCmd = "ssh-keygen -t ed25519 -C '" + cfg.deviceId + "' -f " + 
                           cfg.sshKeyPath + " -N ''";
        if (system(genCmd.c_str()) != 0) {
            throw std::runtime_error("Failed to generate SSH key pair");
        }
        
        // Set proper permissions
        run("chmod 600 " + cfg.sshKeyPath);
        run("chmod 644 " + cfg.sshPubKeyPath);
        
        logInfo("SSH key pair generated successfully");
    }

    // Submit public key to platform for tunnel port allocation
    if (fs::exists(cfg.sshPubKeyPath)) {
        try {
            std::string pubKey = run("cat " + cfg.sshPubKeyPath);
            // Remove trailing newline
            if (!pubKey.empty() && pubKey.back() == '\n') {
                pubKey.pop_back();
            }
            
            json sshRegisterReq = {
                {"device_id", cfg.deviceId},
                {"ssh_public_key", pubKey},
                {"device_class", cfg.deviceClass}
            };
            
            // Register SSH key with platform (best-effort)
            try {
                json response = json::parse(http->postJson("/v1-device/ssh/register", sshRegisterReq, 
                                                         {{"X-Device-Id", cfg.deviceId}}));
                if (response.contains("tunnel_port")) {
                    cfg.sshTunnelPort = response["tunnel_port"].get<int>();
                    logInfo("Assigned SSH tunnel port: " + std::to_string(cfg.sshTunnelPort));
                    
                    // Save updated config
                    saveConfigJson();
                }
            } catch (const std::exception& e) {
                logError("Failed to register SSH key with platform: " + std::string(e.what()));
            }
        } catch (const std::exception& e) {
            logError("Failed to read SSH public key: " + std::string(e.what()));
        }
    }
}

void Agent::establishSSHTunnel() {
    if (!cfg.sshTunnelEnabled || cfg.sshTunnelPort == 0) return;
    
    // Check if tunnel is already active
    if (isSSHTunnelHealthy()) {
        logInfo("SSH tunnel already active");
        return;
    }
    
    logInfo("Establishing SSH tunnel to " + cfg.sshBastionHost + ":" + std::to_string(cfg.sshTunnelPort));
    
    // Kill any existing tunnel processes
    run("pkill -f 'ssh.*" + cfg.sshBastionHost + ".*" + std::to_string(cfg.sshTunnelPort) + "'");
    
    // Build SSH tunnel command (similar to existing bastion setup)
    std::string sshCmd = "ssh -f -N -T "
                        "-o ExitOnForwardFailure=yes "
                        "-o ServerAliveInterval=30 -o ServerAliveCountMax=3 "
                        "-o StrictHostKeyChecking=no "
                        "-i " + cfg.sshKeyPath + " -o IdentitiesOnly=yes "
                        "-R 0.0.0.0:" + std::to_string(cfg.sshTunnelPort) + ":localhost:22 "
                        + cfg.sshBastionUser + "@" + cfg.sshBastionHost;
    
    if (system(sshCmd.c_str()) == 0) {
        sshTunnelActive = true;
        lastSSHCheck = std::chrono::steady_clock::now();
        logInfo("SSH tunnel established successfully");
        
        // Update state
        auto st = loadState();
        st["ssh_tunnel_active"] = true;
        st["ssh_tunnel_port"] = cfg.sshTunnelPort;
        st["ssh_tunnel_established"] = std::time(nullptr);
        saveState(st);
    } else {
        throw std::runtime_error("Failed to establish SSH tunnel");
    }
}

void Agent::monitorSSHTunnelHealth() {
    if (!cfg.sshTunnelEnabled) return;
    
    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastCheck = std::chrono::duration_cast<std::chrono::seconds>(now - lastSSHCheck);
    
    // Check tunnel health every 60 seconds
    if (timeSinceLastCheck.count() < 60) return;
    
    lastSSHCheck = now;
    
    bool tunnelHealthy = isSSHTunnelHealthy();
    
    if (sshTunnelActive && !tunnelHealthy) {
        logError("SSH tunnel connection lost, attempting to re-establish");
        sshTunnelActive = false;
        try {
            establishSSHTunnel();
        } catch (const std::exception& e) {
            logError("Failed to re-establish SSH tunnel: " + std::string(e.what()));
        }
    } else if (!sshTunnelActive && cfg.sshTunnelPort > 0) {
        // Try to establish tunnel if we have a port assigned
        try {
            establishSSHTunnel();
        } catch (const std::exception& e) {
            logError("Failed to establish SSH tunnel: " + std::string(e.what()));
        }
    }
}

bool Agent::isSSHTunnelHealthy() {
    if (!cfg.sshTunnelEnabled || cfg.sshTunnelPort == 0) return false;
    
    // Check if SSH process is running
    std::string checkCmd = "pgrep -f 'ssh.*" + cfg.sshBastionHost + ".*" + 
                          std::to_string(cfg.sshTunnelPort) + "' > /dev/null 2>&1";
    return system(checkCmd.c_str()) == 0;
}

void Agent::executeSSHCommand(const std::string& command) {
    // TODO: Implement SSH command execution for Phase 2
    // This will be used for SSH-based deployments
    logInfo("SSH command execution requested: " + command);
}

nlohmann::json Agent::getSSHStatus() {
    json status;
    status["enabled"] = cfg.sshTunnelEnabled;
    status["tunnel_active"] = sshTunnelActive;
    status["tunnel_port"] = cfg.sshTunnelPort;
    status["bastion_host"] = cfg.sshBastionHost;
    status["last_check"] = std::chrono::duration_cast<std::chrono::seconds>(
        lastSSHCheck.time_since_epoch()).count();
    
    if (cfg.sshTunnelEnabled && fs::exists(cfg.sshPubKeyPath)) {
        std::string pubKey = run("cat " + cfg.sshPubKeyPath);
        if (!pubKey.empty() && pubKey.back() == '\n') {
            pubKey.pop_back();
        }
        // Get fingerprint for identification
        std::string fingerprint = run("ssh-keygen -lf " + cfg.sshPubKeyPath + " | awk '{print $2}'");
        if (!fingerprint.empty() && fingerprint.back() == '\n') {
            fingerprint.pop_back();
        }
        status["public_key_fingerprint"] = fingerprint;
    }
    
    return status;
}

void Agent::updateSSHState(nlohmann::json& currentState) {
    if (!cfg.sshTunnelEnabled) return;
    
    json sshStatus = getSSHStatus();
    currentState["ssh_tunnel"] = sshStatus;
}

/*==================  Secret File Management  ==================*/

std::string AgentConfig::loadSecretFromFile(const std::string& filePath, const std::string& fallbackValue, const std::string& secretName) {
    if (filePath.empty()) {
        return fallbackValue;
    }
    
    try {
        std::string secretValue = readSecureFile(filePath);
        if (!secretValue.empty()) {
            // Log successful secret loading (without revealing the secret)
            std::ofstream logFile("/var/log/streamdeploy-agent/agent.log", std::ios::app);
            if (logFile) {
                long long ts = (long long)std::time(nullptr);
                logFile << ts << " [info] Loaded " << secretName << " from secure file: " << filePath << std::endl;
            }
            return secretValue;
        }
    } catch (const std::exception& e) {
        // Log error but continue with fallback
        std::ofstream logFile("/var/log/streamdeploy-agent/agent.log", std::ios::app);
        if (logFile) {
            long long ts = (long long)std::time(nullptr);
            logFile << ts << " [warn] Failed to load " << secretName << " from " << filePath << ": " << e.what() << ", using fallback" << std::endl;
        }
    }
    
    // Use fallback value and log the source
    if (!fallbackValue.empty()) {
        std::ofstream logFile("/var/log/streamdeploy-agent/agent.log", std::ios::app);
        if (logFile) {
            long long ts = (long long)std::time(nullptr);
            logFile << ts << " [info] Using " << secretName << " from config file (fallback)" << std::endl;
        }
    }
    
    return fallbackValue;
}

std::string AgentConfig::readSecureFile(const std::string& filePath) {
    if (filePath.empty()) {
        throw std::runtime_error("Empty file path provided");
    }
    
    // Check if file exists
    if (!fs::exists(filePath)) {
        throw std::runtime_error("Secret file does not exist: " + filePath);
    }
    
    // Check file permissions for security
    auto perms = fs::status(filePath).permissions();
    if ((perms & fs::perms::group_read) != fs::perms::none ||
        (perms & fs::perms::group_write) != fs::perms::none ||
        (perms & fs::perms::others_read) != fs::perms::none ||
        (perms & fs::perms::others_write) != fs::perms::none) {
        throw std::runtime_error("Secret file has insecure permissions (should be 600): " + filePath);
    }
    
    // Read file contents
    std::ifstream file(filePath);
    if (!file) {
        throw std::runtime_error("Cannot open secret file: " + filePath);
    }
    
    std::string content;
    std::string line;
    while (std::getline(file, line)) {
        if (!content.empty()) {
            content += "\n";
        }
        content += line;
    }
    
    // Trim whitespace
    content.erase(0, content.find_first_not_of(" \t\n\r"));
    content.erase(content.find_last_not_of(" \t\n\r") + 1);
    
    if (content.empty()) {
        throw std::runtime_error("Secret file is empty: " + filePath);
    }
    
    return content;
}
