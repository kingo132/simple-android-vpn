// JNI glue between MyVpnService (Kotlin) and the portable TunnelClient.
#include <jni.h>

#include <memory>
#include <string>
#include <thread>
#include <unistd.h>

#ifdef __ANDROID__
#include <android/log.h>
#else
#include <cstdio>
#endif

#include "tunnel_client.h"

namespace {

JavaVM* g_vm = nullptr;
const char* const kTag = "SimpleVPN";

void android_log(int level, const std::string& message) {
#ifdef __ANDROID__
    int priority = level == simplevpn::kLogError  ? ANDROID_LOG_ERROR
                   : level == simplevpn::kLogWarn ? ANDROID_LOG_WARN
                   : level == simplevpn::kLogInfo ? ANDROID_LOG_INFO
                                                  : ANDROID_LOG_DEBUG;
    __android_log_print(priority, kTag, "%s", message.c_str());
#else
    std::fprintf(stderr, "%s [%d] %s\n", kTag, level, message.c_str());
#endif
}

// NewStringUTF needs modified UTF-8; messages may contain arbitrary bytes
std::string sanitize(const std::string& in) {
    std::string out;
    for (char c : in) {
        unsigned char u = static_cast<unsigned char>(c);
        out += (u >= 32 && u < 127) ? c : '?';
    }
    return out;
}

std::string to_std(JNIEnv* env, jstring s) {
    if (s == nullptr) {
        return "";
    }
    const char* chars = env->GetStringUTFChars(s, nullptr);
    std::string result = chars ? chars : "";
    if (chars) {
        env->ReleaseStringUTFChars(s, chars);
    }
    return result;
}

struct NativeTunnel {
    std::unique_ptr<simplevpn::TunnelClient> client;
    std::thread thread;
    jobject service = nullptr;         // global reference to MyVpnService
    jmethodID protect_method = nullptr; // boolean VpnService.protect(int)
    jmethodID state_method = nullptr;   // void MyVpnService.onNativeState(int, String)
    JNIEnv* thread_env = nullptr;       // JNIEnv of the tunnel thread, only used there
};

bool clear_exception(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return true;
    }
    return false;
}

} // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_kingo132_simplevpn_MyVpnService_nativeStart(JNIEnv* env, jobject thiz, jint tun_fd, jstring server,
                                                     jint port, jstring token, jint mtu, jstring ipv4,
                                                     jstring ipv6) {
    NativeTunnel* tunnel = new NativeTunnel();
    tunnel->service = env->NewGlobalRef(thiz);
    jclass cls = env->GetObjectClass(thiz);
    tunnel->protect_method = env->GetMethodID(cls, "protect", "(I)Z");
    tunnel->state_method = env->GetMethodID(cls, "onNativeState", "(ILjava/lang/String;)V");
    env->DeleteLocalRef(cls);
    if (tunnel->protect_method == nullptr || tunnel->state_method == nullptr) {
        clear_exception(env);
        env->DeleteGlobalRef(tunnel->service);
        delete tunnel;
        close(tun_fd); // we own the detached fd
        return 0;
    }

    simplevpn::TunnelClientConfig config;
    config.server_host = to_std(env, server);
    config.server_port = static_cast<uint16_t>(port);
    config.token = to_std(env, token);
    config.tun_fd = tun_fd;
    config.mtu = mtu;
    config.client_name = "android";
    config.tun_ipv4 = to_std(env, ipv4);
    config.tun_ipv6 = to_std(env, ipv6);
    config.log = android_log;
    config.protect_socket = [tunnel](int fd) -> bool {
        JNIEnv* e = tunnel->thread_env;
        if (e == nullptr) {
            return false;
        }
        jboolean ok = e->CallBooleanMethod(tunnel->service, tunnel->protect_method, fd);
        return !clear_exception(e) && ok == JNI_TRUE;
    };
    config.on_state = [tunnel](simplevpn::TunnelState state, const std::string& message) {
        JNIEnv* e = tunnel->thread_env;
        if (e == nullptr) {
            return;
        }
        jstring text = e->NewStringUTF(sanitize(message).c_str());
        e->CallVoidMethod(tunnel->service, tunnel->state_method, static_cast<jint>(state), text);
        clear_exception(e);
        e->DeleteLocalRef(text);
    };

    tunnel->client.reset(new simplevpn::TunnelClient(config));
    tunnel->thread = std::thread([tunnel]() {
        JNIEnv* e = nullptr;
        JavaVMAttachArgs args;
        args.version = JNI_VERSION_1_6;
        args.name = const_cast<char*>("SimpleVPN-tunnel");
        args.group = nullptr;
#ifdef __ANDROID__
        jint attached = g_vm->AttachCurrentThread(&e, &args);
#else
        jint attached = g_vm->AttachCurrentThread(reinterpret_cast<void**>(&e), &args);
#endif
        if (attached == JNI_OK) {
            tunnel->thread_env = e;
        } else {
            android_log(simplevpn::kLogError, "AttachCurrentThread failed");
        }
        tunnel->client->run(); // returns after stop(), closes the TUN fd
        tunnel->thread_env = nullptr;
        if (attached == JNI_OK) {
            g_vm->DetachCurrentThread();
        }
    });
    return reinterpret_cast<jlong>(tunnel);
}

extern "C" JNIEXPORT void JNICALL
Java_com_kingo132_simplevpn_MyVpnService_nativeStop(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    NativeTunnel* tunnel = reinterpret_cast<NativeTunnel*>(handle);
    if (tunnel == nullptr) {
        return;
    }
    tunnel->client->stop();
    if (tunnel->thread.joinable()) {
        tunnel->thread.join();
    }
    env->DeleteGlobalRef(tunnel->service);
    delete tunnel;
}

// [state, tx packets, tx bytes, rx packets, rx bytes, dropped, reconnects, connected since (ms)]
extern "C" JNIEXPORT jlongArray JNICALL
Java_com_kingo132_simplevpn_MyVpnService_nativeGetStats(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    NativeTunnel* tunnel = reinterpret_cast<NativeTunnel*>(handle);
    jlong values[8] = {0};
    if (tunnel != nullptr) {
        const simplevpn::TunnelStats& s = tunnel->client->stats();
        values[0] = s.state.load();
        values[1] = static_cast<jlong>(s.tx_packets.load());
        values[2] = static_cast<jlong>(s.tx_bytes.load());
        values[3] = static_cast<jlong>(s.rx_packets.load());
        values[4] = static_cast<jlong>(s.rx_bytes.load());
        values[5] = static_cast<jlong>(s.dropped.load());
        values[6] = static_cast<jlong>(s.reconnects.load());
        values[7] = static_cast<jlong>(s.connected_since_ms.load());
    }
    jlongArray result = env->NewLongArray(8);
    if (result != nullptr) {
        env->SetLongArrayRegion(result, 0, 8, values);
    }
    return result;
}
