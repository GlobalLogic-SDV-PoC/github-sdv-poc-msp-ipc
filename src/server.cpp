#include "ipc/server.hpp"

#include <cassert>
#include <deque>
#include <iostream>
#include <type_traits>

#include "ipc/util.hpp"

namespace ipc
{
class Server::Session : public std::enable_shared_from_this<Server::Session>
{
private:
    using packet_read_handler = std::function<void(size_t, const std::shared_ptr<Packet>&)>;
    using strand = net::io_context::strand;
    using message_queue = std::deque<std::shared_ptr<std::string>>;

public:
    struct Config
    {
        uint32_t header_buffer_size;
        uint32_t body_buffer_size;
        packet_read_handler read_handler;
    };

public:
    Session(size_t uuid,
            net::io_context& context,
            tcp::socket&& socket,
            Config config)
        : m_uuid(uuid)
        , m_context(context)
        , m_socket(std::move(socket))
        , m_read_strand(context)
        , m_write_strand(context)
        , m_config(std::move(config))
    {
        assert(m_config.read_handler);
        m_read_buffer.reserve(m_config.header_buffer_size);
    }
    void start()
    {
        asyncReadHeader();
    }
    void stop()
    {
        // breaks constant read loop
        m_socket.cancel();
    }
    bool post(const std::shared_ptr<Packet>& packet)
    {
        if (!packet)
        {
            std::cout << "[ipc server] packet is nullptr\n";
            return false;
        }
        // validating and prepping packet
        if (!packet->is_ok())
        {
            std::cout << "[ipc server] invalid packet format\n";
            return false;
        }
        if (packet->payload.size() > m_config.body_buffer_size)
        {
            std::cout << "[ipc server] invalid packet payload length\n";
            return false;
        }
        if (!packet->payload.empty())
        {
            packet->header["payload_size"] = packet->payload.size();
        }
        {
            const auto lock = std::unique_lock(m_message_queue_mutex);
            auto serialized = std::make_shared<std::string>(packet->serialize());
            if (serialized->size() > m_config.body_buffer_size + m_config.header_buffer_size)
            {
                std::cout << "[ipc server] invalid packet header length\n";
                return false;
            }
            m_message_queue.push_back(std::move(serialized));
        }
        asyncWriteIfAny();
        return true;
    }
    size_t getUUID() const
    {
        return m_uuid;
    }

private:
    void asyncReadHeader()
    {
        net::async_read_until(m_socket, net::dynamic_vector_buffer(m_read_buffer, m_config.header_buffer_size), Packet::DELIM, net::bind_executor(m_read_strand, bind_front(&Session::onHeaderRead, shared_from_this())));
    }

    void onHeaderRead(std::error_code error, size_t bytes_transferred)
    {
        // if error occurred, session is dropped
        if (error)
        {
            return;
        }
        auto packet = parsePacket(bytes_transferred);
        initiateBodyRead(packet);
    }
    std::shared_ptr<Packet> parsePacket(size_t bytes_transferred)
    {
        auto packet = std::make_shared<Packet>();
        // bytes_transferred is header_length
        packet->header = json::json::parse(std::begin(m_read_buffer), std::begin(m_read_buffer) + bytes_transferred - std::size(Packet::DELIM));

        std::cout << "[ipc server] before:" << m_read_buffer.size() << " ";
        // header parsed, we can erase header data
        m_read_buffer.erase(std::begin(m_read_buffer), std::begin(m_read_buffer) + bytes_transferred);
        std::cout << "[ipc server] after:" << m_read_buffer.size() << "\n";
        return packet;
    }
    void initiateBodyRead(const std::shared_ptr<Packet>& packet)
    {
        size_t body_size = packet->header.value("payload_size", 0);
        // if body is empty it is already read
        if (body_size == 0)
        {
            onBodyRead(packet, {}, {});
            return;
        }
        // if body is to big we drop connection
        if (body_size > m_config.body_buffer_size)
        {
            handleError(std::make_error_code(std::errc::no_buffer_space));
            return;
        }
        // preallocate dynamic buffer
        packet->payload.reserve(body_size);

        // part of the message is already in header buffer
        if (std::size(m_read_buffer) != 0)
        {
            const size_t payload_size = std::min(body_size, std::size(m_read_buffer));
            // fill the payload
            std::copy(std::begin(m_read_buffer), std::begin(m_read_buffer) + payload_size, std::back_inserter(packet->payload));
            // clear buffer
            m_read_buffer.erase(std::begin(m_read_buffer), std::begin(m_read_buffer) + payload_size);
            body_size -= payload_size;
        }
        asyncReadBody(body_size, packet);
    }

    void asyncReadBody(size_t body_size, const std::shared_ptr<Packet>& packet)
    {
        // synced with read strand
        net::async_read(m_socket, net::dynamic_string_buffer(packet->payload, packet->payload.capacity()), net::transfer_exactly(body_size), net::bind_executor(m_read_strand, bind_front(&Session::onBodyRead, shared_from_this(), packet)));
    }
    void onBodyRead(const std::shared_ptr<Packet>& packet, std::error_code error, size_t bytes_transferred)
    {
        if (error)
        {
            handleError(error);
            return;
        }
        asyncNotifyReceive(packet);
        // start new read cycle
        asyncReadHeader();
    }
    void asyncNotifyReceive(const std::shared_ptr<Packet>& packet)
    {
        net::post(m_context, [self = shared_from_this(), packet]()
                  {
            std::cout << "[ipc server] received packet:" << packet->header.dump() << "\n";
            self->m_config.read_handler(self->getUUID(), packet); });
    }
    void asyncWriteIfAny()
    {
        std::shared_ptr<std::string> to_send;
        {
            const auto lock = std::unique_lock(m_message_queue_mutex);
            if (m_message_queue.empty())
            {
                return;
            }
            std::cout << "[ipc server] sending: " << *m_message_queue.front() << "\n";
            to_send = std::move(m_message_queue.front());
            m_message_queue.pop_front();
        }
        net::async_write(m_socket, net::const_buffer(to_send->data(), to_send->size()), net::bind_executor(m_write_strand, [self = shared_from_this(), to_send](std::error_code error, size_t bytes_transferred)
                                                                                                           { self->onWrite(error, bytes_transferred); }));
    }
    void onWrite(std::error_code error, size_t bytes_transferred)
    {
        if (error)
        {
            handleError(error);
            return;
        }
        std::cout << "[ipc server] sent packet\n";
        asyncWriteIfAny();
    }

    void handleError(std::error_code error)
    {
        if (error == std::errc::operation_canceled)
        {
            return;
        }
        std::cout << "[ipc server] error: " << strerror(error.value()) << "\n";
        m_socket.close();
    }

private:
    size_t m_uuid;
    net::io_context& m_context;
    tcp::socket m_socket;
    strand m_read_strand;
    strand m_write_strand;
    std::vector<char> m_read_buffer;

    message_queue m_message_queue;
    std::mutex m_message_queue_mutex;

    Config m_config;
};

Server::Server(net::io_context& context, Config config)
    : m_context(context)
    , m_config(std::move(config))
    , m_acceptor(net::make_strand(context))
    , m_uuid_counter(0U)
{
    assert(m_config.on_receive_handler);
}

template <typename T, typename = std::enable_if_t<std::is_trivial_v<T>>>
static T trivial_min(T a, T b)
{
    return a > b ? a : b;
}

void Server::start()
{
    // this may throw if there are any issus with binding to endpoint
    // TODO: think this through
    m_acceptor.open(m_config.endpoint.protocol());
    m_acceptor.set_option(net::socket_base::reuse_address(m_config.reuse_address));
    m_acceptor.set_option(net::socket_base::enable_connection_aborted(m_config.enable_connection_aborted));
    m_acceptor.bind(m_config.endpoint);
    m_acceptor.listen(trivial_min(net::socket_base::max_listen_connections, m_config.max_listen_connections));
    asyncAccept();
}

bool Server::post(size_t session_uuid, const std::shared_ptr<Packet>& packet)
{
    const auto it = m_sessions.find(session_uuid);
    if (it == std::end(m_sessions))
    {
        std::cout << "[ipc server] cant find session with uuid: " << session_uuid << "\n";
        return false;
    }
    if (it->second.expired())
    {
        std::cout << "[ipc server] session with uuid: " << session_uuid << " expired\n";
        m_sessions.erase(it);
        return false;
    }
    return it->second.lock()->post(packet);
}

void Server::stop()
{
    m_acceptor.cancel();
    m_acceptor.close();
    killActiveSessions();
}

void Server::killActiveSessions()
{
    for (auto [uuid, weak_session] : m_sessions)
    {
        if (weak_session.expired())
        {
            continue;
        }
        weak_session.lock()->stop();
    }
}

void Server::asyncAccept()
{
    m_acceptor.async_accept(m_context, bind_front(&Server::onAccept, shared_from_this()));
}

void Server::onAccept(std::error_code error, tcp::socket connection)
{
    if (error)
    {
        std::cout << "[ipc server] error: " << strerror(error.value()) << " accepting anyway\n";
        asyncAccept();
        return;
    }
    const size_t session_uuid = m_uuid_counter++;
    auto session = std::make_shared<Session>(session_uuid,
                                             m_context,
                                             std::move(connection),
                                             Session::Config{m_config.header_buffer_size,
                                                             m_config.body_buffer_size,
                                                             bind_back(m_config.on_receive_handler, weak_from_this())});
    session->start();
    m_sessions.emplace(session_uuid, session);

    asyncAccept();
}
}  // namespace ipc