cmake_minimum_required(VERSION 3.10)
project(StreamDeployInstaller)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static linking configuration (enabled by build script when needed)
# These are set by the build script for musl/static builds
if(STATIC_BUILD)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(CMAKE_EXE_LINK_DYNAMIC_C_FLAGS "")
    set(CMAKE_EXE_LINK_DYNAMIC_CXX_FLAGS "")
    set(CMAKE_SHARED_LIBRARY_C_FLAGS "")
    set(CMAKE_SHARED_LIBRARY_CXX_FLAGS "")
    set(BUILD_SHARED_LIBS OFF)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif()

# Find required packages
find_package(PkgConfig REQUIRED)

# Find libcurl
if(STATIC_BUILD)
    pkg_check_modules(CURL REQUIRED libcurl --static)
else()
    pkg_check_modules(CURL REQUIRED libcurl)
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find jsoncpp
if(STATIC_BUILD)
    pkg_check_modules(JSONCPP REQUIRED jsoncpp --static)
else()
    pkg_check_modules(JSONCPP REQUIRED jsoncpp)
endif()

# Add executable
add_executable(streamdeploy-installer installer.cpp)

# Include directories
target_include_directories(streamdeploy-installer PRIVATE 
    ${CURL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${JSONCPP_INCLUDE_DIRS}
)

# Link libraries dynamically
target_link_libraries(streamdeploy-installer 
    ${CURL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
)

# Compiler flags
target_compile_options(streamdeploy-installer PRIVATE 
    ${CURL_CFLAGS_OTHER}
    ${JSONCPP_CFLAGS_OTHER}
)

# Set output name
set_target_properties(streamdeploy-installer PROPERTIES OUTPUT_NAME "streamdeploy-installer")
