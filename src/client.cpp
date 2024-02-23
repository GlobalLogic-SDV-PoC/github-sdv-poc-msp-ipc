#include "ipc/client.hpp"

#include <fstream>
// TODO: REMOVE
#include <iostream>

#include "ipc/util.hpp"

using namespace std::chrono_literals;

namespace ipc
{
Client::Client(net::io_context& context, Config config)
    : m_context(context)
    , m_config(std::move(config))
    , m_resolver(net::make_strand(m_context))
    , m_read_strand(m_context)
    , m_write_strand(m_context)
    , m_socket(m_context)
    , m_retry_timer(net::make_strand(m_context))
    , m_is_connected(false)
{
    m_read_buffer.reserve(m_config.header_buffer_size);
}

void Client::stop()
{
    m_socket.close();
    m_resolver.cancel();
    m_retry_timer.cancel();
    m_is_connected = false;
    asyncNotifyDisconnected();
}

void Client::start()
{
    stop();
    asyncResolve();
}

bool Client::post(const std::shared_ptr<Packet>& packet)
{
    if (!packet)
    {
        std::cout << "[ipc client] packet is nullptr\n";
        return false;
    }
    // validating and prepping packet
    if (!packet->is_ok())
    {
        std::cout << "[ipc client] invalid packet format\n";
        return false;
    }
    if (packet->payload.size() > m_config.body_buffer_size)
    {
        std::cout << "[ipc client] invalid packet payload length\n";
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
            std::cout << "[ipc client] invalid packet header length\n";
            return false;
        }
        m_message_queue.push_back(std::move(serialized));
    }
    // we can only post messages after successful connection is established
    if (m_is_connected)
    {
        asyncWriteIfAny();
    }
    return true;
}

void Client::asyncWriteIfAny()
{
    // in case we call push  while this function is active
    // because strand is used on read, all read operations are sequential
    std::shared_ptr<std::string> to_send;
    {
        const auto lock = std::unique_lock(m_message_queue_mutex);
        if (m_message_queue.empty())
        {
            return;
        }
        std::cout << "[ipc client] sending: " << *m_message_queue.front() << " size: " << std::size(*m_message_queue.front()) << "\n";
        to_send = std::move(m_message_queue.front());
        m_message_queue.pop_front();
    }
    net::async_write(m_socket, net::const_buffer(to_send->data(), to_send->size()), net::bind_executor(m_write_strand, [self = shared_from_this(), to_send](std::error_code error, size_t bytes_transferred)
                                                                                                       { self->onWrite(error, bytes_transferred); }));
}

void Client::onWrite(std::error_code error, size_t bytes_transferred)
{
    if (error)
    {
        handleError(error);
        return;
    }
    std::cout << "[ipc client] sent packet\n";
    asyncWriteIfAny();
}

void Client::asyncResolve()
{
    std::cout << "[ipc client] resolving\n";
    m_resolver.async_resolve(m_config.host, m_config.service, bind_front(&Client::onResolve, shared_from_this()));
}

void Client::onResolve(std::error_code error, const resolved_endpoints& endpoints)
{
    if (error)
    {
        handleError(error);
        return;
    }
    std::cout << "[ipc client] resolved\n";
    m_resolved_endpoints = endpoints;
    asyncConnect();
}

void Client::asyncConnect()
{
    std::cout << "[ipc client] connecting\n";
    net::async_connect(m_socket, m_resolved_endpoints, bind_front(&Client::onConnect, shared_from_this()));
}

void Client::onConnect(std::error_code error, const tcp::endpoint& endpoint)
{
    if (error)
    {
        handleError(error);
        return;
    }
    std::cout << "[ipc client] connected: " << endpoint << "ready to send"
              << "\n";
    m_is_connected = true;
    asyncReadHeader();
    asyncWriteIfAny();
    asyncNotifyConnected();
}

void Client::asyncReadHeader()
{
    net::async_read_until(m_socket, net::dynamic_vector_buffer(m_read_buffer, m_config.header_buffer_size), Packet::DELIM, net::bind_executor(m_read_strand, bind_front(&Client::onHeaderRead, shared_from_this())));
}

void Client::onHeaderRead(std::error_code error, size_t bytes_transferred)
{
    if (error)
    {
        handleError(error);
        return;
    }
    auto packet = parsePacket(bytes_transferred);
    initiateBodyRead(packet);
}

std::shared_ptr<Packet> Client::parsePacket(size_t bytes_transferred)
{
    auto packet = std::make_shared<Packet>();
    // bytes_transferred is header_length
    packet->header = json::json::parse(std::begin(m_read_buffer), std::begin(m_read_buffer) + bytes_transferred - std::size(Packet::DELIM));

    std::cout << "[ipc client] before:" << m_read_buffer.size() << " ";
    // header parsed, we can erase header data
    m_read_buffer.erase(std::begin(m_read_buffer), std::begin(m_read_buffer) + bytes_transferred);
    std::cout << "[ipc client] after:" << m_read_buffer.size() << "\n";
    return packet;
}

void Client::initiateBodyRead(const std::shared_ptr<Packet>& packet)
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

void Client::asyncReadBody(size_t body_size, const std::shared_ptr<Packet>& packet)
{
    // synced with read strand
    net::async_read(m_socket, net::dynamic_string_buffer(packet->payload, packet->payload.capacity()), net::transfer_exactly(body_size), net::bind_executor(m_read_strand, bind_front(&Client::onBodyRead, shared_from_this(), packet)));
}

void Client::onBodyRead(const std::shared_ptr<Packet>& packet, std::error_code error, size_t bytes_transferred)
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

void Client::handleError(std::error_code error)
{
    if (error == std::errc::operation_canceled)
    {
        return;
    }
    std::cout << "[ipc client] error: " << strerror(error.value()) << "\n";

    stop();
    recordFailedAttempt();
    setUpRetryTimer();
}

void Client::recordFailedAttempt()
{
    const auto current_failure_time = clock::now();
    m_last_failed.erase(std::remove_if(std::begin(m_last_failed), std::end(m_last_failed), [current_failure_time](const auto last_failed_time)
                                       {
                            // get failure count in last 1.5 minutes
                            static constexpr auto VALID_FAILURE_PERIOD = 90s;
                            return current_failure_time - last_failed_time >= VALID_FAILURE_PERIOD; }),
                        std::end(m_last_failed));
    m_last_failed.push_back(current_failure_time);
}

void Client::setUpRetryTimer()
{
    // calculate the retry interval using exponential backoff
    static constexpr auto INITIAL_RETRY_INTERVAL = 1s;
    auto retry_interval = INITIAL_RETRY_INTERVAL * (1 << std::size(m_last_failed)) + 1s;

    static constexpr auto MAX_RETRY_INTERVAL = 60s;
    retry_interval = std::min(retry_interval, MAX_RETRY_INTERVAL);

    std::cout << "[ipc client] timeout: " << retry_interval.count() << "\n";

    m_retry_timer.expires_after(retry_interval);
    m_retry_timer.async_wait([self = shared_from_this()](std::error_code error)
                             {
        if (!error)
        {
            self->asyncConnect();
        } });
}

void Client::asyncNotifyConnected()
{
    net::post(m_context, [self = shared_from_this()]()
              {
        if (!self->m_config.on_connected_handler)
        {
            return;
        }
        self->m_config.on_connected_handler(); });
}

void Client::asyncNotifyDisconnected()
{
    net::post(m_context, [self = shared_from_this()]()
              {
        if (!self->m_config.on_disconnected_handler)
        {
            return;
        }
        self->m_config.on_disconnected_handler(); });
}

void Client::asyncNotifyReceive(const std::shared_ptr<Packet>& packet)
{
    net::post(m_context, [self = shared_from_this(), packet]()
              {
        if (!self->m_config.on_receive_handler)
        {
            return;
        }
        self->m_config.on_receive_handler(packet); });
}
}  // namespace ipc