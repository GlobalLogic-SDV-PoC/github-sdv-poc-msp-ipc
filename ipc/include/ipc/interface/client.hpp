#pragma once

#include <functional>

#include "rclcpp/rclcpp.hpp"

namespace ipc
{
class IClient
{
public:
    using OnReceiveHandler = std::function<void(const std::string& /*payload*/)>;

public:
    virtual void connect(const std::string& server_address,
                         const std::string& receive_address,
                         const rclcpp::Node::SharedPtr& node,
                         const OnReceiveHandler& on_receive_handler,
                         const std::function<void()>& on_connect_handler)
        = 0;
    virtual void subscribe(const std::string& topic) = 0;
    virtual void unsubscribe(const std::string& topic) = 0;
    virtual void forward_payload(const std::string& topic, const std::string& payload) = 0;
    virtual void shutdown() = 0;
    virtual ~IClient() = 0;
};
}  // namespace ipc