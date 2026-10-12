# Builds the server side of SimpleVPN (the Android app is built by Gradle in client/):
#   git submodule update --init
#   cmake -B build && cmake --build build -j
# Results:
#   build/server/reactor/mulserver      reactor server engine
#   build/server/libvpnproxy.so         VPN plugin
#   build/tools/simplevpn-client        Linux test client (Linux only)
#   build/tests/packet_test             unit tests
#
# Run the server from server/ (the config uses paths relative to it, see README.md):
#   cd server && ../build/server/reactor/mulserver conf/server.ini ../build/server/libvpnproxy.so
# The engine loads the plugin given on the command line with dlopen().
cmake_minimum_required(VERSION 3.10)
project(SimpleVPN CXX)

# The whole C++ code base (server, plugin, client core) is C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Default to an optimized build that still has debug symbols (useful for gdb / sanitizers),
# unless the user chose a build type or uses a multi-config generator (Xcode, Visual Studio)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

# server/reactor is a git submodule: fail early with a helpful message if it was not checked out
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/server/reactor/CMakeLists.txt)
    message(FATAL_ERROR "server/reactor is empty, run: git submodule update --init")
endif()

# Optional sanitizer build, e.g. cmake -B build-asan -DSIMPLEVPN_SANITIZE=address
# (applies to every target: engine, plugin, client and tests)
set(SIMPLEVPN_SANITIZE "" CACHE STRING "Build with -fsanitize=<value> (address, thread, undefined)")
if(SIMPLEVPN_SANITIZE)
    add_compile_options(-fsanitize=${SIMPLEVPN_SANITIZE} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${SIMPLEVPN_SANITIZE})
endif()

# The reactor engine + the VPN plugin
add_subdirectory(server)
# The Linux test client needs /dev/net/tun, so it is only built on Linux
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(tools)
endif()
# Unit tests (packet_test)
add_subdirectory(tests)
