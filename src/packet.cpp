#include "ipc/packet.hpp"

namespace ipc
{
bool Packet::is_ok() const
{
    return header.contains("action")
           && header["action"].is_string();
}

std::string Packet::serialize() const
{
    std::string result = header.dump();
    result.reserve(result.size() + payload.size() + DELIM.size());
    result += DELIM;
    result += payload;
    return result;
}
}  // namespace ipc