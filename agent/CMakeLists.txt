cmake_minimum_required(VERSION 3.16)
project(streamdeploy-agent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static linking configuration (set by build script for musl/static builds)
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
# set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Find libcurl
pkg_check_modules(CURL REQUIRED libcurl)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find mosquitto
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)

# Try to find nlohmann-json via pkg-config first
pkg_check_modules(NLOHMANN_JSON nlohmann_json)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CURL_INCLUDE_DIRS})
include_directories(${MOSQUITTO_INCLUDE_DIRS})

# Check if we have system nlohmann-json
if(NLOHMANN_JSON_FOUND)
    include_directories(${NLOHMANN_JSON_INCLUDE_DIRS})
    message(STATUS "Using system nlohmann-json")
else()
    # Use bundled version
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../third_party)
    message(STATUS "Using bundled nlohmann-json")
endif()

# Source files
set(SOURCES
    main.cpp
    agent.cpp
    config_manager.cpp
    metrics_collector.cpp
    container_manager.cpp
    certificate_manager.cpp
    mqtt_client.cpp
    https_client.cpp
    package_manager.cpp
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME}
    ${CURL_LIBRARIES}
    ${MOSQUITTO_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Compiler flags
target_compile_options(${PROJECT_NAME} PRIVATE ${CURL_CFLAGS_OTHER} ${MOSQUITTO_CFLAGS_OTHER})

# Set output name
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "streamdeploy-agent")

# Install target
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
