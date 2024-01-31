#pragma once

#include "interface/server.hpp"

namespace ipc
{
class Server : public IServer
{
public:
    void start(const rclcpp::Node::SharedPtr& node,
               const std::string& address,
               const OnReceiveHandler& on_receive_handlerr) override;
    void shutdown() override;

protected:
    rclcpp::Service<ipc_packet::srv::Packet>::SharedPtr m_listener;
    rclcpp::Node::SharedPtr m_node;
};
}  // namespace ipc