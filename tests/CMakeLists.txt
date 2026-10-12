# packet_test: unit tests for the packet code, the inspector and the tunnel framing.
# It compiles the plugin sources it tests directly (no plugin, no engine
# needed); the srv_* functions those sources call are stubbed in packet_test.cpp.
# Run: build/tests/packet_test (exit code 0 = pass).
add_executable(packet_test packet_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../server/src/packet.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../server/src/inspector.cpp)
# server/src for packet.h / inspector.h, the engine dir for server_api.h, /common for tunnel_protocol.h
target_include_directories(packet_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../server/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../server/reactor/MultithreadServer
    ${CMAKE_CURRENT_SOURCE_DIR}/../common)
