#pragma once
#include "common.hpp"
#include "packet.hpp"

namespace ipc
{
class Server : public std::enable_shared_from_this<Server>
{
private:
    class Session;

public:
    using receive_handler = std::function<void(size_t, const std::shared_ptr<Packet>&, std::weak_ptr<Server>)>;
    struct Config
    {
        tcp::endpoint endpoint;
        int32_t max_listen_connections;
        bool reuse_address;              // false by default
        bool enable_connection_aborted;  // false by default

        uint32_t header_buffer_size;
        uint32_t body_buffer_size;
        receive_handler on_receive_handler;
    };

public:
    Server(net::io_context& context, Config config);

    void start();
    bool post(size_t session_uuid, const std::shared_ptr<Packet>& packet);
    void stop();

private:
    void asyncAccept();
    void onAccept(std::error_code error, tcp::socket connection);
    void killActiveSessions();

private:
    net::io_context& m_context;
    Config m_config;
    tcp::acceptor m_acceptor;

    // session
    size_t m_uuid_counter;
    std::unordered_map<size_t, std::weak_ptr<Session>> m_sessions;
};
}  // namespace ipc