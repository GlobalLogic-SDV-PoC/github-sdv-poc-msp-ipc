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
    assert(on_receive_handler);
    assert(on_connect_handler);
    m_on_receive_handler = on_receive_handler;
    m_on_connect_handler = on_connect_handler;
    m_node = node;
    m_receiver = node->create_subscription<std_msgs::msg::String>(receive_address, 15, [this](const std_msgs::msg::String& msg)
                                                                  { m_on_receive_handler(msg.data); });
    m_request_sender = create_client<ipc_packet::srv::Packet>(server_address);
    notify_existance();
}

void Client::notify_existance()
{
    auto req = std::make_shared<ipc_packet::srv::Packet_Request>();
    req->type = ipc_packet::srv::Packet_Request::HELLO_TYPE;
    req->topic = m_receiver->get_topic_name();
    send_packet(std::move(req));
}
void Client::notify_shutdown(const std::string& client_name)
{
    auto req = std::make_shared<ipc_packet::srv::Packet_Request>();
    req->type = ipc_packet::srv::Packet_Request::GOODBYE_TYPE;
    req->topic = client_name;
    send_packet(std::move(req));
}

void Client::send_packet(ipc_packet::srv::Packet_Request::SharedPtr request)
{
    if (!m_request_sender->service_is_ready())
    {
        while (!m_request_sender->wait_for_service(std::chrono::seconds(15)))
        {
            if (!rclcpp::ok())
            {
                RCLCPP_INFO(m_node->get_logger(), "shutting down request: %d %s %s", request->type, request->topic.c_str(), request->payload.c_str());
                return;
            }
            RCLCPP_INFO(m_node->get_logger(), "Can't connect to %s not sending a request: %d %s %s", m_receiver->get_topic_name(), request->type, request->topic.c_str(), request->payload.c_str());
        }
        notify_existance();
        m_on_connect_handler();
    }

    auto fut = m_request_sender->async_send_request(request);
    if (rclcpp::spin_until_future_complete(shared_from_this(), fut, std::chrono::seconds(15)) != rclcpp::FutureReturnCode::SUCCESS)
    {
        m_request_sender->remove_pending_request(fut);
        RCLCPP_INFO(m_node->get_logger(), "Send message timeout. Ros spin_future is incomplete");
    }
    else
    {
        const auto resp = fut.get();
        RCLCPP_INFO(m_node->get_logger(), "Received response %d", resp->status_code);
    }
}
void Client::subscribe(const std::string& topic)
{
    auto req = std::make_shared<ipc_packet::srv::Packet_Request>();
    req->type = ipc_packet::srv::Packet_Request::SUBSCRIBE_TYPE;
    req->topic = topic;
    req->payload = m_receiver->get_topic_name();
    send_packet(std::move(req));
}
void Client::unsubscribe(const std::string& topic)
{
    auto req = std::make_shared<ipc_packet::srv::Packet_Request>();
    req->type = ipc_packet::srv::Packet_Request::UNSUBSCRIBE_TYPE;
    req->topic = topic;
    req->payload = m_receiver->get_topic_name();
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
    m_receiver.reset();
    m_request_sender.reset();
}
}  // namespace ipc