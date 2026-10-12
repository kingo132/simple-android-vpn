# Linux test client (simplevpn-client): the Android app's tunnel core
# (client/app/src/main/cpp/tunnel_client.cpp) compiled for Linux together with
# a small main() that opens a Linux TUN device. Used by tests/e2e_test.sh and
# for debugging the server without a phone. Only added on Linux (see the
# top-level CMakeLists.txt) because it needs /dev/net/tun.

# tunnel_client.cpp uses std::mutex / std::atomic (and the app runs it on its own
# thread): link the platform's thread library, with -pthread where supported
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Compile the very same tunnel_client.cpp as the app, so the e2e test checks the real code
set(CLIENT_CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../client/app/src/main/cpp)
add_executable(simplevpn-client linux_client/main.cpp ${CLIENT_CORE_DIR}/tunnel_client.cpp)
# tunnel_client.h from the app sources, tunnel_protocol.h from /common
target_include_directories(simplevpn-client PRIVATE ${CLIENT_CORE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(simplevpn-client PRIVATE Threads::Threads)
# Same warnings as the app build (GCC / Clang only)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(simplevpn-client PRIVATE -Wall -Wextra)
endif()
