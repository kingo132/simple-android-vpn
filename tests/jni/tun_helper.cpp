/**
 * @file tun_helper.cpp
 * @brief Opens a Linux TUN device for the JNI test (Android gets it from
 *        VpnService.Builder.establish()).
 *
 * tests/jni_test.sh builds this into libtunhelper.so next to the real
 * libsimplevpn.so. The Java test double
 * tests/jni/com/kingo132/simplevpn/MyVpnService.java declares
 * "static native int openTun(String name)", calls it to get a TUN fd and
 * passes that fd to the real nativeStart(), exactly like the Android service
 * passes the fd of its VPN interface. This file is test-only and is not part
 * of the app.
 */
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <jni.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

/**
 * @brief MyVpnService.openTun() of the Java test double: create a TUN device.
 *
 * IFF_TUN | IFF_NO_PI gives one raw IP packet per read()/write(), the same
 * format as Android's VPN interface. Needs root (CAP_NET_ADMIN).
 *
 * @param env  JNIEnv of the calling thread.
 * @param cls  The Java class (static method), unused.
 * @param name Interface name, e.g. "tun0".
 * @return The TUN file descriptor, or -1 on error.
 */
extern "C" JNIEXPORT jint JNICALL Java_com_kingo132_simplevpn_MyVpnService_openTun(JNIEnv* env, jclass, jstring name) {
    const char* n = env->GetStringUTFChars(name, nullptr);
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // layer 3, no packet info prefix
        std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", n);
        if (ioctl(fd, TUNSETIFF, &ifr) < 0) { // create / attach the interface
            close(fd);
            fd = -1;
        }
    }
    env->ReleaseStringUTFChars(name, n);
    return fd;
}
