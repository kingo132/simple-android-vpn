#include <jni.h>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>

extern "C" JNIEXPORT jstring JNICALL
Java_com_kingo132_simplevpn_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_kingo132_simplevpn_MyVpnService_startVpnNative(JNIEnv *env, jobject instance, jint fd) {
    char buffer[32767]; // Buffer size for reading data from VPN interface
    int vpn_fd = fd;

    while (true) {
        ssize_t length = read(vpn_fd, buffer + 4, sizeof(buffer) - 4);
        if (length <= 0) {
            break; // VPN interface closed or error occurred
        }

        *reinterpret_cast<int*>(buffer) = htonl(length + 4);
        ssize_t sent_bytes = write(vpn_fd, buffer, length + 4);
        if (sent_bytes < 0) {
            perror("send to VPN server failed");
        }
    }
}