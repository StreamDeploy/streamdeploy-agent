#pragma once

#include <string>
#include <functional>
#include <nlohmann/json.hpp>

// Forward declaration
struct mosquitto;

class MqttClient {
public:
    using MessageCallback = std::function<void(const std::string& topic, const std::string& message)>;

    MqttClient(const std::string& endpoint,
               const std::string& ca_cert_path,
               const std::string& client_cert_path,
               const std::string& client_key_path,
               const std::string& device_id);
    ~MqttClient();

    // Connection management
    bool connect();
    void disconnect();
    bool isConnected() const;

    // Publishing
    bool publishHeartbeat(const nlohmann::json& heartbeat_data);
    bool publishStatusUpdate(const nlohmann::json& status_data);
    bool publish(const std::string& topic, const std::string& message, int qos = 1);

    // Subscription
    bool subscribe(const std::string& topic, int qos = 1);
    bool unsubscribe(const std::string& topic);
    void setMessageCallback(MessageCallback callback);

    // Topics
    std::string getHeartbeatTopic() const;
    std::string getStatusUpdateTopic() const;
    std::string getCommandTopic() const;
    std::string getConfigUpdateTopic() const;

private:
    std::string endpoint_;
    std::string ca_cert_path_;
    std::string client_cert_path_;
    std::string client_key_path_;
    std::string device_id_;
    
    // MQTT client handle
    struct mosquitto* mqtt_handle_;
    
    MessageCallback message_callback_;
    bool connected_;

    // Private methods (to be implemented later)
    void initializeMqtt();
    void cleanupMqtt();
    void setupTLS();
    void handleMessage(const std::string& topic, const std::string& message);
    
    // Topic builders
    std::string buildTopic(const std::string& suffix) const;
};
