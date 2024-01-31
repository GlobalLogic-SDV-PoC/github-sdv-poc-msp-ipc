#pragma once

#include <functional>

#include "ipc_packet/srv/packet.hpp"
#include "rclcpp/rclcpp.hpp"

namespace ipc
{
class IServer
{
public:
    using RequestSharedPtr = ipc_packet::srv::Packet_Request::SharedPtr;
    using ResponseSharedPtr = ipc_packet::srv::Packet_Response::SharedPtr;
    using OnReceiveHandler = std::function<void(RequestSharedPtr, ResponseSharedPtr)>;

public:
    virtual void start(const rclcpp::Node::SharedPtr& node,
                       const std::string& address,
                       const OnReceiveHandler& on_receive_handlerr)
        = 0;
    virtual void shutdown() = 0;
    virtual ~IServer() = 0;
};
}  // namespace ipc