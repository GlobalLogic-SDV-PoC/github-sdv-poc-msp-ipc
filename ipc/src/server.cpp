#include "ipc/server.hpp"

#include <cassert>

namespace ipc
{
IServer::~IServer() = default;

void Server::start(const std::string& address, const OnReceiveHandler& on_receive_handler)
{
    assert(on_receive_handler);
    RCLCPP_INFO(get_logger(), "Creating server with address %s", address.c_str());

    m_listener = create_service<ipc_packet::srv::Packet>(address, on_receive_handler);
}
void Server::shutdown()
{
    assert(m_listener);
    RCLCPP_INFO(get_logger(), "Killing server with address %s", m_listener->get_service_name());
    m_listener.reset();
}
}  // namespace ipc