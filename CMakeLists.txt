# Builds the server side of SimpleVPN (the Android app is built by Gradle in client/):
#   git submodule update --init
#   cmake -B build && cmake --build build -j
# Results:
#   build/server/reactor/mulserver      reactor server engine
#   build/server/libvpnproxy.so         VPN plugin
#   build/tools/simplevpn-client        Linux test client (Linux only)
#   build/tests/packet_test             unit tests
cmake_minimum_required(VERSION 3.10)
project(SimpleVPN CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/server/reactor/CMakeLists.txt)
    message(FATAL_ERROR "server/reactor is empty, run: git submodule update --init")
endif()

set(SIMPLEVPN_SANITIZE "" CACHE STRING "Build with -fsanitize=<value> (address, thread, undefined)")
if(SIMPLEVPN_SANITIZE)
    add_compile_options(-fsanitize=${SIMPLEVPN_SANITIZE} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${SIMPLEVPN_SANITIZE})
endif()

add_subdirectory(server)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(tools)
endif()
add_subdirectory(tests)
