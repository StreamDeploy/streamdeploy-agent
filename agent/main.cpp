#include "agent.h"
#include <iostream>
#include <csignal>
#include <atomic>

std::atomic<bool> shutdown_requested(false);

void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    shutdown_requested = true;
}

int main(int argc, char** argv) {
    std::string config_path = "/etc/streamdeploy/agent.json";
    
    // Parse command line arguments
    if (argc > 1) {
        config_path = argv[1];
    }
    
    // Set up signal handlers for graceful shutdown
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    try {
        std::cout << "StreamDeploy Agent starting..." << std::endl;
        std::cout << "Using config: " << config_path << std::endl;
        
        // Create and start the agent
        Agent agent(config_path);
        agent.start();
        
        // Main loop - wait for shutdown signal
        while (!shutdown_requested && agent.isRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        std::cout << "Shutting down agent..." << std::endl;
        agent.stop();
        
        std::cout << "StreamDeploy Agent stopped successfully" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << std::endl;
        return 1;
    }
}
