#include "ipc/server.hpp"

#include <cassert>

namespace ipc
{
IServer::~IServer() = default;

void Server::start(const rclcpp::Node::SharedPtr& node,
               const std::string& address,
               const OnReceiveHandler& on_receive_handlerr)
{
    assert(on_receive_handlerr);
    m_node = node;
    RCLCPP_INFO(m_node->get_logger(), "Creating server with address %s", address.c_str());

    m_listener = m_node->create_service<ipc_packet::srv::Packet>(address, on_receive_handlerr);
}
void Server::shutdown()
{
    assert(m_listener);
    RCLCPP_INFO(m_node->get_logger(), "Killing server with address %s", m_listener->get_service_name());
    m_listener.reset();
}
}  // namespace ipc