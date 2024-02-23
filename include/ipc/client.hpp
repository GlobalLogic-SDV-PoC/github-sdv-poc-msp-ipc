#pragma once
#include <chrono>
#include <deque>
#include <istream>

#include "common.hpp"
#include "packet.hpp"

namespace ipc
{
class Client : public std::enable_shared_from_this<Client>
{
private:
    using strand = net::io_context::strand;
    using resolved_endpoints = tcp::resolver::results_type;
    using clock = std::chrono::steady_clock;
    using message_queue = std::deque<std::shared_ptr<std::string>>;

public:
    using connection_handler = std::function<void()>;
    using packet_handler = std::function<void(std::shared_ptr<Packet>)>;

    struct Config
    {
        std::string host;
        std::string service;
        uint32_t header_buffer_size;
        uint32_t body_buffer_size;

        connection_handler on_connected_handler;
        connection_handler on_disconnected_handler;
        packet_handler on_receive_handler;
    };

public:
    Client(net::io_context& context, Config config);

    void start();
    bool post(const std::shared_ptr<Packet>& packet);
    void stop();

private:
    void asyncResolve();
    void onResolve(std::error_code error, const resolved_endpoints& endpoints);

    void asyncConnect();
    void onConnect(std::error_code error, const tcp::endpoint& endpoint);

    void asyncReadHeader();
    void onHeaderRead(std::error_code error, size_t bytes_transferred);
    std::shared_ptr<Packet> parsePacket(size_t bytes_transferred);
    void initiateBodyRead(const std::shared_ptr<Packet>& packet);

    void asyncReadBody(size_t body_size, const std::shared_ptr<Packet>& packet);
    void onBodyRead(const std::shared_ptr<Packet>& packet, std::error_code error, size_t bytes_transferred);

    void asyncWriteIfAny();
    void onWrite(std::error_code error, size_t bytes_transferred);

    void handleError(std::error_code error);
    void setUpRetryTimer();
    void recordFailedAttempt();

    // listener
    void asyncNotifyConnected();
    void asyncNotifyDisconnected();
    void asyncNotifyReceive(const std::shared_ptr<Packet>& packet);

private:
    net::io_context& m_context;
    Config m_config;
    tcp::resolver m_resolver;
    strand m_read_strand;
    strand m_write_strand;
    tcp::socket m_socket;
    net::steady_timer m_retry_timer;
    std::deque<clock::time_point> m_last_failed;
    std::vector<char> m_read_buffer;

    std::mutex m_message_queue_mutex;
    std::atomic_bool m_is_connected;
    message_queue m_message_queue;
    resolved_endpoints m_resolved_endpoints;
};
}  // namespace ipc