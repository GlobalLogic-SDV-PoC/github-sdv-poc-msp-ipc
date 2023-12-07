cmake_minimum_required(VERSION 3.8)
project(ipc)

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)
find_package(ipc_packet REQUIRED)

add_library(${PROJECT_NAME} STATIC)
target_sources(${PROJECT_NAME} PRIVATE src/server.cpp src/client.cpp)
target_include_directories(
    ${PROJECT_NAME}
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<INSTALL_INTERFACE:include>)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_14)
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
endif()
ament_target_dependencies(${PROJECT_NAME} rclcpp std_msgs ipc_packet)

install(
    TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}_export
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION include/)

ament_export_targets(${PROJECT_NAME}_export HAS_LIBRARY_TARGET)
ament_export_dependencies(rclcpp std_msgs ipc_packet)

ament_package()
