#include "agent.h"
#include <iostream>
#include <thread>
#include <chrono>

int main(int argc, char** argv) {
    std::string cfg = "/etc/streamdeploy/agent.json";
    if (argc > 1) cfg = argv[1];

    try {
        Agent agent(cfg);
        agent.logInfo("StreamDeploy pull agent starting");
        for (;;) {
            agent.tick();  // status-update (pull desired state) + apply + heartbeat + flush logs
            std::this_thread::sleep_for(std::chrono::seconds(agent.heartbeatIntervalSeconds()));
        }
    } catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << std::endl;
        return 1;
    }
}
