cmake_minimum_required(VERSION 3.5.2)
project(
    ipc
    VERSION 1.0.0
    LANGUAGES CXX)
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

# options
set(ASIO_ROOT
    "${CMAKE_CURRENT_SOURCE_DIR}/dep/external/asio"
    CACHE STRING "Path to asio")
option(IPC_EXTERNAL_JSON
    "Specify whether to use an external nlohmann_json library" OFF)

# dependencies
find_package(Asio REQUIRED)

if(NOT IPC_EXTERNAL_JSON)
    add_subdirectory(dep/external/json)
endif()

# library
add_library(ipc src/client.cpp src/server.cpp src/packet.cpp)
target_include_directories(ipc PUBLIC include)
target_link_libraries(ipc PUBLIC net::asio nlohmann_json::nlohmann_json)
target_compile_features(ipc PUBLIC cxx_std_17)
