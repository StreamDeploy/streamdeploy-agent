#include "agent.h"
#include "http_client.h"
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <thread>
#include <array>

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

        // Submit CSR
        const std::string csrPem = run("cat " + csr);
        json csrReq = {{"token", cfg.bootstrapToken}, {"nonce", nonce}, {"csr", csrPem}};
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

    // Build current_state payload expected by backend
    json current;
    current["current_digest"] = st.value("current_digest", st.value("current_image",""));
    current["container"]      = cfg.containerName;
    current["device_class"]   = cfg.deviceClass;
    current["etag"]           = st.value("last_etag", "");

    json payload;
    payload["update_type"]   = updateType;
    payload["status"]        = "normal"; // DeviceStatus expected by backend ("normal" or "degraded")
    payload["current_state"] = current;

    // ship buffered logs with status update (embed inside current_state to match backend schema)
    flushLogsInto(current);
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

/*==================  Heartbeat  ==================*/

void Agent::sendHeartbeat() {
    // Build Heartbeat model
    json hb{
        {"status", "normal"},
        {"agent_setting", {
            {"heartbeat_frequency", std::to_string(cfg.heartbeatIntervalSeconds) + "s"},
            {"agent_version", "0.1.0"},
            {"device_class", cfg.deviceClass}
        }},
        {"metrics", {
            {"uptime_s", run("cut -d. -f1 /proc/uptime")},
            {"temps_c",  run("cat /sys/devices/virtual/thermal/thermal_zone0/temp 2>/dev/null || true")}
        }}
    };

    // best-effort; ignore errors
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

    // 3) Heartbeat (best-effort)
    sendHeartbeat();
}
