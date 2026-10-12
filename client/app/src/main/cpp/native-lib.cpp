/**
 * @file native-lib.cpp
 * @brief JNI glue between MyVpnService (Kotlin) and the portable TunnelClient.
 *
 * Overview
 * --------
 * The Kotlin service creates the TUN interface with VpnService.Builder and
 * passes its file descriptor to nativeStart(). This file then:
 *   - builds a TunnelClientConfig from the Java arguments,
 *   - wires the two platform callbacks back into Java: protect_socket ->
 *     VpnService.protect(int) and on_state -> MyVpnService.onNativeState(),
 *   - starts a dedicated native thread ("SimpleVPN-tunnel") that runs
 *     TunnelClient::run(), attached to the Java VM so it can call those
 *     Java methods,
 *   - returns an opaque handle (a NativeTunnel pointer cast to jlong) that
 *     Kotlin passes back to nativeStop / nativeReconnect / nativeGetStats.
 *
 * JNI rules that shape this code:
 *   - A JNIEnv* is valid only on the thread it belongs to. The tunnel thread
 *     therefore attaches itself to the VM and uses its own JNIEnv.
 *   - A local reference (like `thiz`) dies when the native method returns,
 *     so the service object is kept as a global reference until nativeStop.
 *   - jmethodID values are valid on every thread and can be cached.
 *   - A thread attached with AttachCurrentThread must detach before it exits.
 *   - Pending Java exceptions must be cleared before the next JNI call.
 *
 * The same file also runs on a desktop JVM for tests/jni_test.sh (without
 * __ANDROID__ it logs to stderr instead of logcat).
 *
 * Reading guide: nativeStart (top to bottom), then nativeStop. The Kotlin
 * side is MyVpnService.kt; the tunnel logic is tunnel_client.cpp.
 */
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

JavaVM* g_vm = nullptr;                // the process' Java VM, saved in JNI_OnLoad (valid on every thread)
const char* const kTag = "SimpleVPN";  // logcat tag, same as MyVpnService.TAG

/**
 * @brief Log callback of the tunnel client: write to logcat (or stderr off Android).
 * @param level   simplevpn::LogLevel.
 * @param message Text.
 */
void android_log(int level, const std::string& message) {
#ifdef __ANDROID__
    // Map our levels to logcat priorities
    int priority = level == simplevpn::kLogError  ? ANDROID_LOG_ERROR
                   : level == simplevpn::kLogWarn ? ANDROID_LOG_WARN
                   : level == simplevpn::kLogInfo ? ANDROID_LOG_INFO
                                                  : ANDROID_LOG_DEBUG;
    __android_log_print(priority, kTag, "%s", message.c_str());
#else
    std::fprintf(stderr, "%s [%d] %s\n", kTag, level, message.c_str());
#endif
}

/**
 * @brief Make a string safe for NewStringUTF().
 *
 * NewStringUTF needs modified UTF-8; messages may contain arbitrary bytes
 * (e.g. an ERROR text from the server), and invalid input can crash the VM
 * with CheckJNI enabled. Keeping only printable ASCII is always valid.
 *
 * @param in Any bytes.
 * @return The same text with every non printable / non ASCII byte replaced by '?'.
 */
std::string sanitize(const std::string& in) {
    std::string out;
    for (char c : in) {
        unsigned char u = static_cast<unsigned char>(c);
        out += (u >= 32 && u < 127) ? c : '?';
    }
    return out;
}

/**
 * @brief Copy a Java string into a std::string.
 * @param env JNIEnv of the calling thread.
 * @param s   Java string, may be null.
 * @return The (modified UTF-8) bytes of @p s, "" for null.
 */
std::string to_std(JNIEnv* env, jstring s) {
    if (s == nullptr) {
        return "";
    }
    const char* chars = env->GetStringUTFChars(s, nullptr);
    std::string result = chars ? chars : "";
    if (chars) {
        env->ReleaseStringUTFChars(s, chars); // every Get must be paired with a Release
    }
    return result;
}

/**
 * @brief Everything one running tunnel needs; its address is the jlong handle
 *        held by Kotlin. Created in nativeStart, deleted in nativeStop.
 */
struct NativeTunnel {
    std::unique_ptr<simplevpn::TunnelClient> client; // the portable tunnel core
    std::thread thread;                              // runs client->run()
    jobject service = nullptr;         // global reference to MyVpnService
    jmethodID protect_method = nullptr; // boolean VpnService.protect(int)
    jmethodID state_method = nullptr;   // void MyVpnService.onNativeState(int, String)
    JNIEnv* thread_env = nullptr;       // JNIEnv of the tunnel thread, only used there
};

/**
 * @brief Clear a pending Java exception (after printing it to the log).
 *
 * A Java method called from native code may throw; the exception stays
 * pending and most JNI calls are illegal until it is cleared.
 *
 * @param env JNIEnv of the calling thread.
 * @return true if an exception was pending.
 */
bool clear_exception(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return true;
    }
    return false;
}

} // namespace

/**
 * @brief Called by the VM when System.loadLibrary("simplevpn") loads this library.
 * @param vm The Java VM; stored so the native tunnel thread can attach to it later.
 * @return The JNI version this library needs.
 */
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}

/**
 * @brief MyVpnService.nativeStart(): start the tunnel on its own native thread.
 *
 * Called on MyVpnService's worker thread right after the TUN interface was
 * established. Returns quickly; connecting happens on the tunnel thread.
 *
 * @param env    JNIEnv of the calling (Java) thread.
 * @param thiz   The MyVpnService instance (local reference).
 * @param tun_fd TUN file descriptor detached from its ParcelFileDescriptor:
 *               from now on this native code owns it and closes it.
 * @param server Server IP address (already resolved by Kotlin).
 * @param port   Server TCP port.
 * @param token  Shared secret (vpn_token of the server).
 * @param mtu    MTU of the TUN interface.
 * @param ipv4   TUN IPv4 address (informational, sent in HELLO).
 * @param ipv6   TUN IPv6 address or "" (informational).
 * @return Opaque handle (NativeTunnel pointer) for the other native methods,
 *         or 0 if the Java callbacks could not be found.
 */
extern "C" JNIEXPORT jlong JNICALL
Java_com_kingo132_simplevpn_MyVpnService_nativeStart(JNIEnv* env, jobject thiz, jint tun_fd, jstring server,
                                                     jint port, jstring token, jint mtu, jstring ipv4,
                                                     jstring ipv6) {
    NativeTunnel* tunnel = new NativeTunnel();
    tunnel->service = env->NewGlobalRef(thiz); // must outlive this call: used by the tunnel thread
    jclass cls = env->GetObjectClass(thiz);
    // Look the methods up by name and JNI signature: "(I)Z" = boolean f(int)
    tunnel->protect_method = env->GetMethodID(cls, "protect", "(I)Z");
    tunnel->state_method = env->GetMethodID(cls, "onNativeState", "(ILjava/lang/String;)V");
    env->DeleteLocalRef(cls);
    if (tunnel->protect_method == nullptr || tunnel->state_method == nullptr) {
        clear_exception(env); // GetMethodID throws NoSuchMethodError
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
    // Called on the tunnel thread for every new server socket, before connect():
    // VpnService.protect(fd) exempts the socket from the VPN routing, otherwise
    // the tunnel's own packets would loop back into the TUN device.
    config.protect_socket = [tunnel](int fd) -> bool {
        JNIEnv* e = tunnel->thread_env;
        if (e == nullptr) {
            return false; // thread not attached: cannot call Java, refuse the socket
        }
        jboolean ok = e->CallBooleanMethod(tunnel->service, tunnel->protect_method, fd);
        return !clear_exception(e) && ok == JNI_TRUE;
    };
    // Called on the tunnel thread on every state change: forward to Kotlin
    config.on_state = [tunnel](simplevpn::TunnelState state, const std::string& message) {
        JNIEnv* e = tunnel->thread_env;
        if (e == nullptr) {
            return;
        }
        jstring text = e->NewStringUTF(sanitize(message).c_str());
        e->CallVoidMethod(tunnel->service, tunnel->state_method, static_cast<jint>(state), text);
        clear_exception(e);
        e->DeleteLocalRef(text); // the thread never returns to Java, so free local refs by hand
    };

    tunnel->client.reset(new simplevpn::TunnelClient(config));
    tunnel->thread = std::thread([tunnel]() {
        // A native thread must be attached to the VM before it may call Java
        JNIEnv* e = nullptr;
        JavaVMAttachArgs args;
        args.version = JNI_VERSION_1_6;
        args.name = const_cast<char*>("SimpleVPN-tunnel"); // thread name shown in debuggers / traces
        args.group = nullptr;
#ifdef __ANDROID__
        // Android's jni.h declares AttachCurrentThread(JNIEnv**, ...)
        jint attached = g_vm->AttachCurrentThread(&e, &args);
#else
        // the desktop JDK's jni.h declares AttachCurrentThread(void**, ...)
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
            g_vm->DetachCurrentThread(); // mandatory before an attached thread exits
        }
    });
    return reinterpret_cast<jlong>(tunnel); // the pointer travels through Kotlin as a Long
}

/**
 * @brief MyVpnService.nativeStop(): stop the tunnel, wait for its thread, free everything.
 *
 * Blocks until the tunnel thread has finished (at most about a poll() round
 * trip), so it is called from the service's worker thread, never from the UI
 * thread. Closing the TUN fd (done by run()) tears the VPN interface down.
 *
 * @param env    JNIEnv of the calling thread.
 * @param thiz   Unused.
 * @param handle Handle returned by nativeStart (0 is ignored); invalid afterwards.
 */
extern "C" JNIEXPORT void JNICALL
Java_com_kingo132_simplevpn_MyVpnService_nativeStop(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    NativeTunnel* tunnel = reinterpret_cast<NativeTunnel*>(handle);
    if (tunnel == nullptr) {
        return;
    }
    tunnel->client->stop(); // wakes the tunnel thread through its pipe
    if (tunnel->thread.joinable()) {
        // While we wait, the tunnel thread may still call onNativeState();
        // that method must not wait for this thread, or both would deadlock.
        tunnel->thread.join();
    }
    env->DeleteGlobalRef(tunnel->service); // safe now: nobody uses it any more
    delete tunnel;
}

/**
 * @brief MyVpnService.nativeReconnect(): reconnect immediately (network changed).
 *
 * Does not block: it only signals the tunnel thread.
 *
 * @param env    Unused.
 * @param thiz   Unused.
 * @param handle Handle returned by nativeStart (0 is ignored).
 */
extern "C" JNIEXPORT void JNICALL
Java_com_kingo132_simplevpn_MyVpnService_nativeReconnect(JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    NativeTunnel* tunnel = reinterpret_cast<NativeTunnel*>(handle);
    if (tunnel != nullptr) {
        tunnel->client->reconnect();
    }
}

/**
 * @brief MyVpnService.nativeGetStats(): snapshot of the tunnel counters for the UI.
 *
 * The counters are atomics, so this is safe to call from any thread while
 * the tunnel thread updates them.
 *
 * @param env    JNIEnv of the calling thread.
 * @param thiz   Unused.
 * @param handle Handle returned by nativeStart; 0 yields all zeros.
 * @return long[8], see the layout below (null only if the allocation failed).
 */
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
        values[7] = static_cast<jlong>(s.connected_since_ms.load()); // wall clock ms, 0 = not connected
    }
    jlongArray result = env->NewLongArray(8);
    if (result != nullptr) {
        env->SetLongArrayRegion(result, 0, 8, values); // copy the C array into the Java array
    }
    return result;
}
