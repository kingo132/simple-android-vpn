add_executable(packet_test packet_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../server/src/packet.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../server/src/inspector.cpp)
target_include_directories(packet_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../server/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../server/reactor/MultithreadServer
    ${CMAKE_CURRENT_SOURCE_DIR}/../common)
