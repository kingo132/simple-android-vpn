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

    @Volatile
    private var nativeHandle = 0L

    /** The physical network the tunnel currently uses (our own app is not routed into the VPN). */
    @Volatile
    private var currentNetwork: Network? = null

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val previous = currentNetwork
            currentNetwork = network
            val handle = nativeHandle
            if (previous != null && previous != network && handle != 0L) {
                // Wi-Fi <-> mobile data: the old TCP connection is dead, do not wait for the keepalive
                Log.i(TAG, "default network changed, reconnecting the tunnel")
                nativeReconnect(handle)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        try {
            getSystemService(ConnectivityManager::class.java)?.registerDefaultNetworkCallback(networkCallback)
        } catch (e: Exception) {
            Log.w(TAG, "cannot watch network changes", e)
        }
    }

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

    override fun onRevoke() {
        // Another VPN was started or the user disconnected us in the system settings
        worker.execute {
            disconnect()
            stopSelf()
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(networkCallback)
        } catch (e: Exception) {
            Log.w(TAG, "unregisterNetworkCallback failed", e)
        }
        worker.execute { disconnect() }
        worker.shutdown()
        if (instance === this) {
            instance = null
        }
        super.onDestroy()
    }

    private fun connect() {
        disconnect()
        val settings = VpnSettings.load(this)
        if (settings.server.isBlank()) {
            updateState(STATE_FAILED, "no server configured")
            return
        }
        updateState(STATE_CONNECTING, "resolving ${settings.server}")

        // Resolve before the VPN is up, so the lookup does not go into the tunnel
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
            updateState(STATE_FAILED, "VPN permission was revoked, start again from the app")
            return
        }

        // The native client owns the fd from now on and closes it when stopped
        val fd = tun.detachFd()
        val v6 = if (settings.ipv6) TUN_IPV6 else ""
        nativeHandle = nativeStart(fd, serverIp, settings.port, settings.token, settings.mtu, TUN_IPV4, v6)
        if (nativeHandle == 0L) {
            updateState(STATE_FAILED, "native tunnel failed to start")
        }
        Log.i(TAG, "VPN interface up, tunnel to $serverIp:${settings.port}")
    }

    private fun createInterface(settings: VpnSettings): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("SimpleVPN ${settings.server}")
            .setMtu(settings.mtu)
            .addAddress(TUN_IPV4, 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(settings.dns)
            .setBlocking(false)
            .setConfigureIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            )
        if (settings.ipv6) {
            builder.addAddress(TUN_IPV6, 64)
            builder.addRoute("::", 0)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        val allowed = settings.allowedPackages()
        if (allowed.isEmpty()) {
            // Everything except ourselves: our tunnel connection must not loop into the VPN
            builder.addDisallowedApplication(packageName)
        } else {
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

    private fun disconnect() {
        val handle = nativeHandle
        if (handle != 0L) {
            nativeHandle = 0L
            nativeStop(handle) // closes the TUN fd, which tears the VPN down
            updateState(STATE_STOPPED, "disconnected")
            Log.i(TAG, "VPN stopped")
        }
    }

    /** Called by the native tunnel thread. Must not block. */
    @Suppress("unused")
    private fun onNativeState(state: Int, message: String) {
        updateState(state, message)
    }

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

    private external fun nativeStart(
        tunFd: Int, server: String, port: Int, token: String, mtu: Int, ipv4: String, ipv6: String
    ): Long

    private external fun nativeStop(handle: Long)

    private external fun nativeReconnect(handle: Long)

    private external fun nativeGetStats(handle: Long): LongArray

    companion object {
        const val TAG = "SimpleVPN"
        const val ACTION_CONNECT = "com.kingo132.simplevpn.CONNECT"
        const val ACTION_DISCONNECT = "com.kingo132.simplevpn.DISCONNECT"

        // Same values as simplevpn::TunnelState
        const val STATE_IDLE = 0
        const val STATE_CONNECTING = 1
        const val STATE_CONNECTED = 2
        const val STATE_RECONNECTING = 3
        const val STATE_STOPPED = 4
        const val STATE_AUTH_FAILED = 5
        const val STATE_FAILED = 100

        const val TUN_IPV4 = "172.19.0.2"
        const val TUN_IPV6 = "fd00:5356::2"

        @Volatile
        var instance: MyVpnService? = null
            private set

        @Volatile
        var lastState = STATE_IDLE
            private set

        @Volatile
        var lastMessage = ""
            private set

        init {
            System.loadLibrary("simplevpn")
        }
    }
}
