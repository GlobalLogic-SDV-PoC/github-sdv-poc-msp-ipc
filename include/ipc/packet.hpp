#pragma once
#include "common.hpp"

namespace ipc
{
struct Packet
{
    json::json header;
    std::string payload;
    static constexpr std::string_view DELIM = "\r\n";

public:
    bool is_ok() const;
    std::string serialize() const;
};
}  // namespace ipc