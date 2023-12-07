#pragma once
#include "interface/client.hpp"
#include "ipc_packet/srv/packet.hpp"
#include "std_msgs/msg/string.hpp"

namespace ipc
{
class Client : public IClient, public rclcpp::Node
{
public:
    using rclcpp::Node::Node;
    void connect(const std::string& server_address,
                 const std::string& receive_address,
                 const rclcpp::Node::SharedPtr& node,
                 const OnReceiveHandler& on_receive_handler,
                 const std::function<void()>& on_connect_handler) override;
    void subscribe(const std::string& topic) override;
    void unsubscribe(const std::string& topic) override;
    void forward_payload(const std::string& topic, const std::string& payload) override;
    void shutdown() override;

protected:
    void send_packet(ipc_packet::srv::Packet_Request::SharedPtr request);
    void notify_existance();

protected:
    std::recursive_mutex m_mutex;
    rclcpp::Client<ipc_packet::srv::Packet>::SharedPtr m_request_sender;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr m_receiver;
    rclcpp::Node::SharedPtr m_node;
    OnReceiveHandler m_on_receive_handler;
    std::function<void()> m_on_connect_handler;
};
}  // namespace ipc