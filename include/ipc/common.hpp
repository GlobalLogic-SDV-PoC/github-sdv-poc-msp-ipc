#pragma once
#include "asio.hpp"
#include "nlohmann/json.hpp"

namespace ipc
{
namespace net = asio;
using tcp = net::ip::tcp;
namespace json = nlohmann;
}  // namespace ipc