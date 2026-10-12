# Native part of the Android app: the tunnel client core (shared with the
# Linux test client in tools/linux_client) plus the JNI glue.
#
# Gradle (externalNativeBuild in client/app/build.gradle.kts) runs this once
# per ABI (arm64-v8a, x86_64, ...) with the NDK toolchain and packs the resulting
# libsimplevpn.so into the APK. Kotlin loads it with
# System.loadLibrary("simplevpn") in MyVpnService's companion object.
cmake_minimum_required(VERSION 3.22.1)

# The project name doubles as the library name (libsimplevpn.so), see add_library below
project("simplevpn")

# C++11 is enough and keeps the core portable (the server side uses C++11 too)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# repository root /common holds the tunnel protocol shared with the server
# (this file is client/app/src/main/cpp/CMakeLists.txt, five levels below the root)
set(SIMPLEVPN_COMMON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../common)

# A SHARED library: JNI code is always loaded at run time by the Java VM
add_library(${CMAKE_PROJECT_NAME} SHARED
        native-lib.cpp
        tunnel_client.cpp)

# tunnel_client.h lives here, tunnel_protocol.h in /common
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${SIMPLEVPN_COMMON_DIR})

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wall -Wextra)

# Android 15+ devices may use 16 KB memory pages: align the ELF segments to
# 16 KB (NDK r27 and older default to 4 KB, which such devices refuse / warn about)
# The linker flag max-page-size=16384 makes every loadable segment start on a
# 16 KB boundary; such a library also works on 4 KB page devices.
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,-z,max-page-size=16384")

# android: NDK platform library (not strictly needed by this code, harmless);
# log: liblog, provides __android_log_print() used in native-lib.cpp
target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log)
