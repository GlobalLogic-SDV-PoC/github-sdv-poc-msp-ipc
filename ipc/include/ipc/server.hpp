#pragma once

#include "interface/server.hpp"

namespace ipc
{
class Server : public IServer, public rclcpp::Node
{
public:
    using rclcpp::Node::Node;
    void start(const std::string& address, const OnReceiveHandler& on_receive_handler) override;
    void shutdown() override;

protected:
    rclcpp::Service<ipc_packet::srv::Packet>::SharedPtr m_listener;
};
}  // namespace ipc