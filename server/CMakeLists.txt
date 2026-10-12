# The reactor engine (git submodule) provides the `mulserver` executable and
# reactor_add_plugin(); the VPN logic is a plugin loaded by mulserver.
add_subdirectory(reactor)

# Sources of the VPN plugin:
#   vpn_plugin.cpp   engine callbacks (handle_*), entry point of the plugin
#   vpn_session.cpp  one tunnel per phone: handshake, packet dispatch, back pressure
#   flows.cpp        user-space TCP endpoint, UDP and ICMP NAT flows
#   packet.cpp       IPv4/IPv6/TCP/UDP/ICMP parsing, building, fragmentation
#   inspector.cpp    protocol detection (HTTP, TLS SNI, DNS), blocking, rewriting
#   pcap_writer.cpp  pcap files and the live capture stream
set(VPN_SERVER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vpn_plugin.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vpn_session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/flows.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/packet.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/inspector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pcap_writer.cpp
)

# reactor_add_plugin() (defined by the engine) builds a loadable module
# (libvpnproxy.so) that sees server_api.h and resolves the srv_* functions
# from the mulserver executable at load time.
reactor_add_plugin(vpnproxy ${VPN_SERVER_SOURCES})
# Plugin headers live in src/, the tunnel protocol shared with the client in /common
target_include_directories(vpnproxy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/../common)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vpnproxy PRIVATE -Wall -Wextra)
endif()
