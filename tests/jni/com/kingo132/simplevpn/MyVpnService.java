package com.kingo132.simplevpn;

/**
 * Test double of the Android MyVpnService with the same native methods and
 * callbacks, so the real JNI glue (native-lib.cpp) can be exercised on a
 * Linux JVM with a Linux TUN device. Used by tests/jni_test.sh.
 */
public class MyVpnService {
    static {
        System.loadLibrary("simplevpn");
        System.loadLibrary("tunhelper");
    }

    public volatile int lastState = 0;
    public volatile String lastMessage = "";
    public volatile int protectCalls = 0;

    // Same signature as android.net.VpnService.protect(int)
    public boolean protect(int fd) {
        protectCalls++;
        System.out.println("[java] protect(" + fd + ")");
        return true;
    }

    private void onNativeState(int state, String message) {
        lastState = state;
        lastMessage = message;
        System.out.println("[java] state " + state + ": " + message);
    }

    native long nativeStart(int tunFd, String server, int port, String token, int mtu, String ipv4, String ipv6);
    native void nativeStop(long handle);
    native void nativeReconnect(long handle);
    native long[] nativeGetStats(long handle);

    static native int openTun(String name);

    /** Usage: MyVpnService SERVER PORT TOKEN SECONDS */
    public static void main(String[] args) throws Exception {
        String server = args[0];
        int port = Integer.parseInt(args[1]);
        String token = args[2];
        int seconds = Integer.parseInt(args[3]);

        int fd = openTun("tun0");
        if (fd < 0) {
            throw new IllegalStateException("cannot open tun0");
        }
        run("ip link set dev tun0 mtu 1500 up");
        run("ip addr add 172.19.0.2/24 dev tun0");

        MyVpnService service = new MyVpnService();
        long handle = service.nativeStart(fd, server, port, token, 1500, "172.19.0.2", "");
        if (handle == 0) {
            throw new IllegalStateException("nativeStart failed");
        }
        long deadline = System.currentTimeMillis() + 10000;
        while (service.lastState != 2 && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        if (service.lastState != 2) {
            throw new IllegalStateException("not connected: " + service.lastMessage);
        }
        run("ip route add default dev tun0");
        System.out.println("[java] READY");

        Thread.sleep(seconds * 1000L);
        // simulate a network change: the tunnel must come back right away
        service.nativeReconnect(handle);
        long reconnectStart = System.currentTimeMillis();
        Thread.sleep(200);
        while (service.lastState != 2 && System.currentTimeMillis() - reconnectStart < 5000) {
            Thread.sleep(20);
        }
        System.out.println("[java] reconnected after " + (System.currentTimeMillis() - reconnectStart) + " ms, state "
                + service.lastState);
        long[] stats = service.nativeGetStats(handle);
        service.nativeStop(handle);
        System.out.println("[java] stats state=" + stats[0] + " tx=" + stats[1] + "/" + stats[2] + " rx=" + stats[3]
                + "/" + stats[4] + " dropped=" + stats[5] + " reconnects=" + stats[6] + " protect=" + service.protectCalls
                + " final state=" + service.lastState);
        boolean ok = service.lastState == 4 && stats[3] > 0 && stats[6] == 1 && service.protectCalls == 2;
        System.out.println(ok ? "[java] JNI OK" : "[java] JNI FAILED");
    }

    private static void run(String cmd) throws Exception {
        Process p = new ProcessBuilder(cmd.split(" ")).inheritIO().start();
        p.waitFor();
    }
}
