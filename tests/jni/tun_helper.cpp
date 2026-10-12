// Opens a Linux TUN device for the JNI test (Android gets it from VpnService.Builder.establish())
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <jni.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

extern "C" JNIEXPORT jint JNICALL Java_com_kingo132_simplevpn_MyVpnService_openTun(JNIEnv* env, jclass, jstring name) {
    const char* n = env->GetStringUTFChars(name, nullptr);
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", n);
        if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
            close(fd);
            fd = -1;
        }
    }
    env->ReleaseStringUTFChars(name, n);
    return fd;
}
