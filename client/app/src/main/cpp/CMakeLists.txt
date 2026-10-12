# Native part of the Android app: the tunnel client core (shared with the
# Linux test client in tools/linux_client) plus the JNI glue.
cmake_minimum_required(VERSION 3.22.1)

project("simplevpn")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# repository root /common holds the tunnel protocol shared with the server
set(SIMPLEVPN_COMMON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../common)

add_library(${CMAKE_PROJECT_NAME} SHARED
        native-lib.cpp
        tunnel_client.cpp)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${SIMPLEVPN_COMMON_DIR})

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wall -Wextra)

# Android 15+ devices may use 16 KB memory pages: align the ELF segments to
# 16 KB (NDK r27 and older default to 4 KB, which such devices refuse / warn about)
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,-z,max-page-size=16384")

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log)
