# The reactor engine (git submodule) provides the `mulserver` executable and
# reactor_add_plugin(); the VPN logic is a plugin loaded by mulserver.
add_subdirectory(reactor)

set(VPN_SERVER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vpn_plugin.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vpn_session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/flows.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/packet.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/inspector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pcap_writer.cpp
)

reactor_add_plugin(vpnproxy ${VPN_SERVER_SOURCES})
target_include_directories(vpnproxy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/../common)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vpnproxy PRIVATE -Wall -Wextra)
endif()
