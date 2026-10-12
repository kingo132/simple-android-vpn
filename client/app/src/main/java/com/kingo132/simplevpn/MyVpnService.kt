/**
 * @file MyVpnService.kt
 * Android side of the VPN: the VpnService that creates the TUN interface and
 * drives the native tunnel client.
 *
 * Overview: MainActivity (or the system, for always-on VPN) starts this
 * service with ACTION_CONNECT. The service builds a TUN interface with
 * VpnService.Builder (from then on the system routes the selected apps' IP
 * packets into it), detaches the interface's file descriptor and hands it to
 * native code (native-lib.cpp -> TunnelClient), which forwards every packet
 * to the SimpleVPN server over one TCP connection and writes the server's
 * packets back into the TUN.
 *
 * Threads: the Service callbacks run on the main thread, which must never
 * block (ANR). Connecting (DNS lookup) and disconnecting (joining the native
 * thread) therefore run on [worker], a single thread executor that also keeps
 * them strictly in order. The native tunnel runs on its own native thread and
 * calls back into [onNativeState] and VpnService.protect().
 *
 * Reading guide: onStartCommand -> connect -> createInterface -> nativeStart;
 * networkCallback for Wi-Fi / mobile switches; disconnect -> nativeStop.
 * See also docs/en/android-client.md.
 */
package com.kingo132.simplevpn

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.InetAddress
import java.util.concurrent.Executors

/**
 * The VPN service. It creates the TUN interface (every app's traffic is
 * routed into it) and hands its file descriptor to the native tunnel client,
 * which forwards every IP packet to the SimpleVPN server and writes the
 * server's packets back.
 */
class MyVpnService : VpnService() {

    /** Serializes connect / disconnect, which may block (DNS, thread join). */
    private val worker = Executors.newSingleThreadExecutor()

    /**
     * Handle of the running native tunnel (a C++ pointer as Long), 0 = none.
     * Volatile: written on [worker], read on the main thread (network
     * callback, [stats] called by the activity).
     */
    @Volatile
    private var nativeHandle = 0L

    /** The physical network the tunnel currently uses (our own app is not routed into the VPN). */
    @Volatile
    private var currentNetwork: Network? = null

    /**
     * Watches this app's default network. Because the app excludes itself
     * from the VPN, that is the physical network (Wi-Fi or mobile data) the
     * tunnel connection runs on. When it changes, the old TCP connection is
     * bound to a network that is gone, so the tunnel is told to reconnect
     * immediately instead of waiting for the keepalive timeout (45 s).
     */
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        /**
         * A (new) default network is available.
         * @param network The new default network.
         */
        override fun onAvailable(network: Network) {
            val previous = currentNetwork
            currentNetwork = network
            val handle = nativeHandle // read the volatile once
            // previous == null: the first callback right after registering, nothing changed
            if (previous != null && previous != network && handle != 0L) {
                // Wi-Fi <-> mobile data: the old TCP connection is dead, do not wait for the keepalive
                Log.i(TAG, "default network changed, reconnecting the tunnel")
                nativeReconnect(handle)
            }
        }
    }

    /** Service created: publish [instance] for the activity and start watching the network. */
    override fun onCreate() {
        super.onCreate()
        instance = this
        try {
            getSystemService(ConnectivityManager::class.java)?.registerDefaultNetworkCallback(networkCallback)
        } catch (e: Exception) {
            // Not fatal: without it the keepalive timeout still detects a dead connection
            Log.w(TAG, "cannot watch network changes", e)
        }
    }

    /**
     * Entry point for every startService() call (and for always-on VPN).
     *
     * @param intent ACTION_CONNECT, ACTION_DISCONNECT, or the system's
     *   android.net.VpnService intent; null when the system restarts a
     *   sticky service.
     * @param flags Start flags (unused).
     * @param startId Start id (unused).
     * @return START_STICKY while connecting, so the system restarts the
     *   service (and the VPN) if it kills the process; START_NOT_STICKY for a
     *   disconnect.
     */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            worker.execute {
                disconnect()
                stopSelf()
            }
            return START_NOT_STICKY
        }
        // ACTION_CONNECT from the app, or android.net.VpnService for always-on VPN
        worker.execute { connect() }
        return START_STICKY
    }

    /** The system took the VPN away from us; shut down cleanly. */
    override fun onRevoke() {
        // Another VPN was started or the user disconnected us in the system settings
        worker.execute {
            disconnect()
            stopSelf()
        }
        super.onRevoke()
    }

    /** Service destroyed: stop watching the network, stop the tunnel, end the worker. */
    override fun onDestroy() {
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(networkCallback)
        } catch (e: Exception) {
            Log.w(TAG, "unregisterNetworkCallback failed", e)
        }
        worker.execute { disconnect() }
        worker.shutdown() // the queued disconnect still runs, then the thread ends
        if (instance === this) {
            instance = null
        }
        super.onDestroy()
    }

    /**
     * Bring the VPN up (runs on [worker]): load the settings, resolve the
     * server, create the TUN interface and start the native tunnel.
     * Any previous tunnel is stopped first, so connect() is also "restart".
     */
    private fun connect() {
        disconnect()
        val settings = VpnSettings.load(this)
        if (settings.server.isBlank()) {
            updateState(STATE_FAILED, "no server configured")
            return
        }
        updateState(STATE_CONNECTING, "resolving ${settings.server}")

        // Resolve before the VPN is up, so the lookup does not go into the tunnel
        // (the native code then gets an IP literal and never has to do DNS itself)
        val serverIp = try {
            InetAddress.getByName(settings.server).hostAddress ?: settings.server
        } catch (e: Exception) {
            updateState(STATE_FAILED, "cannot resolve ${settings.server}: ${e.message}")
            return
        }

        val tun = try {
            createInterface(settings)
        } catch (e: Exception) {
            // e.g. an invalid DNS server address or MTU
            updateState(STATE_FAILED, "cannot create the VPN interface: ${e.message}")
            return
        }
        if (tun == null) {
            // establish() returns null when the app is not (or no longer) the prepared VPN app
            updateState(STATE_FAILED, "VPN permission was revoked, start again from the app")
            return
        }

        // The native client owns the fd from now on and closes it when stopped
        // (detachFd() makes the ParcelFileDescriptor forget it, so GC cannot close it)
        val fd = tun.detachFd()
        val v6 = if (settings.ipv6) TUN_IPV6 else ""
        nativeHandle = nativeStart(fd, serverIp, settings.port, settings.token, settings.mtu, TUN_IPV4, v6)
        if (nativeHandle == 0L) {
            updateState(STATE_FAILED, "native tunnel failed to start")
        }
        Log.i(TAG, "VPN interface up, tunnel to $serverIp:${settings.port}")
    }

    /**
     * Describe and create the TUN interface.
     *
     * @param settings The user's settings (MTU, DNS, IPv6, app list).
     * @return The interface's file descriptor, or null if the VPN permission
     *   is missing. Throws (e.g. IllegalArgumentException) for invalid settings.
     */
    private fun createInterface(settings: VpnSettings): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("SimpleVPN ${settings.server}") // name shown in the system VPN dialog / notification
            .setMtu(settings.mtu)
            .addAddress(TUN_IPV4, 24)  // our address inside the VPN; the server does not care which one
            .addRoute("0.0.0.0", 0)    // default route: all IPv4 traffic goes into the TUN
            .addDnsServer(settings.dns) // DNS queries go to this server, through the tunnel
            .setBlocking(false)        // non-blocking fd: the native code multiplexes it with poll()
            .setConfigureIntent(
                // tapping the system's VPN notification / settings entry opens our activity
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            )
        if (settings.ipv6) {
            builder.addAddress(TUN_IPV6, 64)
            builder.addRoute("::", 0) // default route for IPv6 as well
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Android 10+ treats a VPN as metered by default, which makes apps hold
            // back on big downloads; the tunnel itself adds no data costs
            builder.setMetered(false)
        }
        val allowed = settings.allowedPackages()
        // The Builder accepts either an allow list or a deny list, never both
        if (allowed.isEmpty()) {
            // Everything except ourselves: our tunnel connection must not loop into the VPN
            builder.addDisallowedApplication(packageName)
        } else {
            // Only the listed apps use the VPN (ourselves not included)
            for (pkg in allowed) {
                try {
                    builder.addAllowedApplication(pkg)
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "allowed app $pkg is not installed")
                }
            }
        }
        return builder.establish()
    }

    /** Stop the native tunnel if one runs (runs on [worker]; blocks until its thread ended). */
    private fun disconnect() {
        val handle = nativeHandle
        if (handle != 0L) {
            nativeHandle = 0L // first, so the network callback and stats() stop using the handle
            nativeStop(handle) // closes the TUN fd, which tears the VPN down
            updateState(STATE_STOPPED, "disconnected")
            Log.i(TAG, "VPN stopped")
        }
    }

    /**
     * Called by the native tunnel thread. Must not block.
     * (nativeStop() waits for that thread on [worker]; if this method waited
     * for [worker] in turn, both threads would deadlock.)
     *
     * @param state One of the STATE_* values (same numbers as simplevpn::TunnelState).
     * @param message Human readable description of the state.
     */
    @Suppress("unused") // only called from native code (JNI looks it up by name)
    private fun onNativeState(state: Int, message: String) {
        updateState(state, message)
    }

    /**
     * Remember the latest state for the activity (it polls [lastState] /
     * [lastMessage] once a second) and log it ("state 2: connected ..." is
     * what tests/device_test.sh looks for in logcat).
     */
    private fun updateState(state: Int, message: String) {
        lastState = state
        lastMessage = message
        Log.i(TAG, "state $state: $message")
    }

    /** [state, tx packets, tx bytes, rx packets, rx bytes, dropped, reconnects, connected since ms] */
    fun stats(): LongArray? {
        val handle = nativeHandle
        return if (handle != 0L) nativeGetStats(handle) else null
    }

    // Implemented in native-lib.cpp (Java_com_kingo132_simplevpn_MyVpnService_<name>)

    /** Start the tunnel thread; takes ownership of [tunFd]. @return handle, 0 on failure. */
    private external fun nativeStart(
        tunFd: Int, server: String, port: Int, token: String, mtu: Int, ipv4: String, ipv6: String
    ): Long

    /** Stop the tunnel and wait for its thread; the handle is invalid afterwards. */
    private external fun nativeStop(handle: Long)

    /** Drop the server connection and reconnect immediately (does not block). */
    private external fun nativeReconnect(handle: Long)

    /** Counters, see [stats]. */
    private external fun nativeGetStats(handle: Long): LongArray

    companion object {
        const val TAG = "SimpleVPN" // logcat tag (also used by native-lib.cpp)
        const val ACTION_CONNECT = "com.kingo132.simplevpn.CONNECT"
        const val ACTION_DISCONNECT = "com.kingo132.simplevpn.DISCONNECT"

        // Same values as simplevpn::TunnelState
        const val STATE_IDLE = 0
        const val STATE_CONNECTING = 1
        const val STATE_CONNECTED = 2
        const val STATE_RECONNECTING = 3
        const val STATE_STOPPED = 4
        const val STATE_AUTH_FAILED = 5
        const val STATE_FAILED = 100 // Kotlin side only: the tunnel could not even be started

        const val TUN_IPV4 = "172.19.0.2"   // private address of the phone inside the VPN
        const val TUN_IPV6 = "fd00:5356::2" // unique local IPv6 address ("5356" = "SV")

        /** The running service, for the activity (null when not running). */
        @Volatile
        var instance: MyVpnService? = null
            private set

        /** Last reported state (STATE_*), kept even after the service stopped. */
        @Volatile
        var lastState = STATE_IDLE
            private set

        /** Last state / error message shown in the activity. */
        @Volatile
        var lastMessage = ""
            private set

        init {
            // Loads libsimplevpn.so (built from client/app/src/main/cpp); runs JNI_OnLoad
            System.loadLibrary("simplevpn")
        }
    }
}
