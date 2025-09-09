#include "mqtt_client.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <mosquitto.h>

MqttClient::MqttClient(const std::string& endpoint,
                       const std::string& ca_cert_path,
                       const std::string& client_cert_path,
                       const std::string& client_key_path,
                       const std::string& device_id)
    : endpoint_(endpoint)
    , ca_cert_path_(ca_cert_path)
    , client_cert_path_(client_cert_path)
    , client_key_path_(client_key_path)
    , device_id_(device_id)
    , mqtt_handle_(nullptr)
    , connected_(false) {
    
    initializeMqtt();
}

MqttClient::~MqttClient() {
    disconnect();
    cleanupMqtt();
}

bool MqttClient::connect() {
    if (!mqtt_handle_) {
        std::cerr << "[MqttClient] MQTT handle not initialized" << std::endl;
        return false;
    }
    
    // Set up TLS
    setupTLS();
    
    // Connect to broker
    int result = mosquitto_connect(mqtt_handle_, endpoint_.c_str(), 8883, 60);
    if (result != MOSQ_ERR_SUCCESS) {
        std::cerr << "[MqttClient] Failed to connect to MQTT broker: " << mosquitto_strerror(result) << std::endl;
        return false;
    }
    
    // Start the network loop
    result = mosquitto_loop_start(mqtt_handle_);
    if (result != MOSQ_ERR_SUCCESS) {
        std::cerr << "[MqttClient] Failed to start MQTT loop: " << mosquitto_strerror(result) << std::endl;
        mosquitto_disconnect(mqtt_handle_);
        return false;
    }
    
    connected_ = true;
    std::cout << "[MqttClient] Connected to MQTT broker: " << endpoint_ << std::endl;
    return true;
}

void MqttClient::disconnect() {
    if (mqtt_handle_ && connected_) {
        mosquitto_disconnect(mqtt_handle_);
        mosquitto_loop_stop(mqtt_handle_, true);
        connected_ = false;
        std::cout << "[MqttClient] Disconnected from MQTT broker" << std::endl;
    }
}

bool MqttClient::isConnected() const {
    return connected_ && mqtt_handle_;
}

bool MqttClient::publishHeartbeat(const nlohmann::json& heartbeat_data) {
    std::string topic = getHeartbeatTopic();
    std::string message = heartbeat_data.dump();
    return publish(topic, message, 1);
}

bool MqttClient::publishStatusUpdate(const nlohmann::json& status_data) {
    std::string topic = getStatusUpdateTopic();
    std::string message = status_data.dump();
    return publish(topic, message, 1);
}

bool MqttClient::publish(const std::string& topic, const std::string& message, int qos) {
    if (!isConnected()) {
        std::cerr << "[MqttClient] Not connected to broker" << std::endl;
        return false;
    }
    
    int result = mosquitto_publish(mqtt_handle_, nullptr, topic.c_str(), 
                                  message.length(), message.c_str(), qos, false);
    
    if (result != MOSQ_ERR_SUCCESS) {
        std::cerr << "[MqttClient] Failed to publish to topic " << topic 
                  << ": " << mosquitto_strerror(result) << std::endl;
        return false;
    }
    
    std::cout << "[MqttClient] Published message to topic: " << topic << std::endl;
    return true;
}

bool MqttClient::subscribe(const std::string& topic, int qos) {
    if (!isConnected()) {
        std::cerr << "[MqttClient] Not connected to broker" << std::endl;
        return false;
    }
    
    int result = mosquitto_subscribe(mqtt_handle_, nullptr, topic.c_str(), qos);
    
    if (result != MOSQ_ERR_SUCCESS) {
        std::cerr << "[MqttClient] Failed to subscribe to topic " << topic 
                  << ": " << mosquitto_strerror(result) << std::endl;
        return false;
    }
    
    std::cout << "[MqttClient] Subscribed to topic: " << topic << std::endl;
    return true;
}

bool MqttClient::unsubscribe(const std::string& topic) {
    if (!isConnected()) {
        std::cerr << "[MqttClient] Not connected to broker" << std::endl;
        return false;
    }
    
    int result = mosquitto_unsubscribe(mqtt_handle_, nullptr, topic.c_str());
    
    if (result != MOSQ_ERR_SUCCESS) {
        std::cerr << "[MqttClient] Failed to unsubscribe from topic " << topic 
                  << ": " << mosquitto_strerror(result) << std::endl;
        return false;
    }
    
    std::cout << "[MqttClient] Unsubscribed from topic: " << topic << std::endl;
    return true;
}

void MqttClient::setMessageCallback(MessageCallback callback) {
    message_callback_ = callback;
}

std::string MqttClient::getHeartbeatTopic() const {
    return buildTopic("/heartbeat");
}

std::string MqttClient::getStatusUpdateTopic() const {
    return buildTopic("/status");
}

std::string MqttClient::getCommandTopic() const {
    return buildTopic("/commands");
}

std::string MqttClient::getConfigUpdateTopic() const {
    return buildTopic("/config");
}

void MqttClient::initializeMqtt() {
    // Initialize mosquitto library
    mosquitto_lib_init();
    
    // Create mosquitto instance
    mqtt_handle_ = mosquitto_new(device_id_.c_str(), true, this);
    if (!mqtt_handle_) {
        std::cerr << "[MqttClient] Failed to create MQTT client instance" << std::endl;
        return;
    }
    
    // Set up callbacks
    mosquitto_connect_callback_set(mqtt_handle_, [](struct mosquitto* mosq, void* userdata, int result) {
        MqttClient* client = static_cast<MqttClient*>(userdata);
        if (result == 0) {
            std::cout << "[MqttClient] Connected to broker" << std::endl;
        } else {
            std::cerr << "[MqttClient] Connection failed: " << mosquitto_strerror(result) << std::endl;
        }
    });
    
    mosquitto_disconnect_callback_set(mqtt_handle_, [](struct mosquitto* mosq, void* userdata, int result) {
        MqttClient* client = static_cast<MqttClient*>(userdata);
        client->connected_ = false;
        std::cout << "[MqttClient] Disconnected from broker" << std::endl;
    });
    
    mosquitto_message_callback_set(mqtt_handle_, [](struct mosquitto* mosq, void* userdata, 
                                                   const struct mosquitto_message* message) {
        MqttClient* client = static_cast<MqttClient*>(userdata);
        if (client && client->message_callback_) {
            std::string topic(message->topic);
            std::string payload(static_cast<char*>(message->payload), message->payloadlen);
            client->handleMessage(topic, payload);
        }
    });
}

void MqttClient::cleanupMqtt() {
    if (mqtt_handle_) {
        mosquitto_destroy(mqtt_handle_);
        mqtt_handle_ = nullptr;
    }
    mosquitto_lib_cleanup();
}

void MqttClient::setupTLS() {
    if (!mqtt_handle_) {
        return;
    }
    
    // Set CA certificate
    int result = mosquitto_tls_set(mqtt_handle_, ca_cert_path_.c_str(), nullptr, 
                                  client_cert_path_.c_str(), client_key_path_.c_str(), nullptr);
    if (result != MOSQ_ERR_SUCCESS) {
        std::cerr << "[MqttClient] Failed to set TLS certificates: " << mosquitto_strerror(result) << std::endl;
        return;
    }
    
    // Set TLS options
    result = mosquitto_tls_opts_set(mqtt_handle_, 1, "tlsv1.2", nullptr);
    if (result != MOSQ_ERR_SUCCESS) {
        std::cerr << "[MqttClient] Failed to set TLS options: " << mosquitto_strerror(result) << std::endl;
        return;
    }
    
    // Set insecure mode (for self-signed certificates)
    result = mosquitto_tls_insecure_set(mqtt_handle_, true);
    if (result != MOSQ_ERR_SUCCESS) {
        std::cerr << "[MqttClient] Failed to set TLS insecure mode: " << mosquitto_strerror(result) << std::endl;
        return;
    }
    
    std::cout << "[MqttClient] TLS configured with certificates" << std::endl;
}

void MqttClient::handleMessage(const std::string& topic, const std::string& message) {
    if (message_callback_) {
        message_callback_(topic, message);
    }
}

std::string MqttClient::buildTopic(const std::string& suffix) const {
    return "devices/" + device_id_ + suffix;
}
