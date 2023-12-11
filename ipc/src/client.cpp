#include "ipc/client.hpp"

#include <cassert>
#include <functional>

namespace ipc
{
IClient::~IClient() = default;
void Client::connect(const std::string& server_address,
                     const std::string& receive_address,
                     const rclcpp::Node::SharedPtr& node,
                     const OnReceiveHandler& on_receive_handler,
                     const std::function<void()>& on_connect_handler)
{
    std::scoped_lock lock(m_mutex);
    assert(on_receive_handler);
    assert(on_connect_handler);
    m_on_receive_handler = on_receive_handler;
    m_on_connect_handler = on_connect_handler;
    m_receiver = node->create_subscription<std_msgs::msg::String>(receive_address, 5, [this](const std_msgs::msg::String& msg)
                                                                  { m_on_receive_handler(msg.data); });
    m_request_sender = create_client<ipc_packet::srv::Packet>(server_address);
    notify_existance();
}

void Client::notify_existance()
{
    std::scoped_lock lock(m_mutex);
    auto req = std::make_shared<ipc_packet::srv::Packet_Request>();
    req->type = ipc_packet::srv::Packet_Request::HELLO_TYPE;
    req->topic = m_receiver->get_topic_name();
    send_packet(std::move(req));
}
void Client::send_packet(ipc_packet::srv::Packet_Request::SharedPtr request)
{
    std::scoped_lock lock(m_mutex);
    if (!m_request_sender->service_is_ready())
    {
        while (!m_request_sender->wait_for_service(std::chrono::seconds(2)))
        {
            if (!rclcpp::ok())
            {
                RCLCPP_INFO(get_logger(), "shutting down request: %d %s %s", request->type, request->topic.c_str(), request->payload.c_str());
                return;
            }
            RCLCPP_INFO(get_logger(), "Can't connect to %s not sending a request: %d %s %s", m_receiver->get_topic_name(), request->type, request->topic.c_str(), request->payload.c_str());
        }
        notify_existance();
        m_on_connect_handler();
    }

    auto fut = m_request_sender->async_send_request(request);
    if (rclcpp::spin_until_future_complete(shared_from_this(), fut, std::chrono::seconds(2)) != rclcpp::FutureReturnCode::SUCCESS)
    {
        m_request_sender->remove_pending_request(fut);
        RCLCPP_INFO(get_logger(), "Send message timeout");
    }
    else
    {
        if (fut.wait_for(std::chrono::seconds(1)) != std::future_status::ready)
        {
            RCLCPP_INFO(get_logger(), "Send message timeout");
            return;
        }
        const auto resp = fut.get();
        RCLCPP_INFO(get_logger(), "Received response %d", resp->status_code);
    }
}
void Client::subscribe(const std::string& topic)
{
    auto req = std::make_shared<ipc_packet::srv::Packet_Request>();
    req->type = ipc_packet::srv::Packet_Request::SUBSCRIBE_TYPE;
    req->topic = topic;
    send_packet(std::move(req));
}
void Client::unsubscribe(const std::string& topic)
{
    auto req = std::make_shared<ipc_packet::srv::Packet_Request>();
    req->type = ipc_packet::srv::Packet_Request::UNSUBSCRIBE_TYPE;
    req->topic = topic;
    send_packet(std::move(req));
}
void Client::forward_payload(const std::string& topic, const std::string& payload)
{
    auto req = std::make_shared<ipc_packet::srv::Packet_Request>();
    req->type = ipc_packet::srv::Packet_Request::FORWARD_TYPE;
    req->topic = topic;
    req->payload = payload;
    send_packet(std::move(req));
}
void Client::shutdown()
{
    std::scoped_lock lock(m_mutex);
    m_receiver.reset();
    m_request_sender.reset();
}
}  // namespace ipc