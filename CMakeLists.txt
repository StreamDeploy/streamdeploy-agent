cmake_minimum_required(VERSION 3.16)
project(streamdeploy_agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Header-only nlohmann/json is vendored under third_party/
include_directories(third_party)

find_package(CURL REQUIRED)

add_executable(streamdeploy-agent
  src/main.cpp
  src/agent.cpp
  src/http_client.cpp
  src/hal_jetson.cpp
)

target_include_directories(streamdeploy-agent PRIVATE ${CURL_INCLUDE_DIRS})
target_include_directories(streamdeploy-agent PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
target_link_libraries(streamdeploy-agent PRIVATE CURL::libcurl)

install(TARGETS streamdeploy-agent DESTINATION /usr/local/bin)
