/**
 * @file MainActivity.kt
 * The app's only screen: settings form, Start / Stop buttons and a live
 * status / statistics display.
 *
 * Overview: "Start" saves the settings ([VpnSettings]), asks the system for
 * the VPN permission once (VpnService.prepare shows the consent dialog), and
 * then starts [MyVpnService] with ACTION_CONNECT; the service does all the
 * real work. The activity never talks to native code directly: once a second
 * it reads the service's last state and its counters ([refreshStatus]).
 *
 * Debug builds additionally accept connect / disconnect commands through an
 * intent, so tests/device_test.sh can drive the app with adb without any tap
 * on the phone ([handleTestIntent]).
 *
 * Reading guide: onCreate -> onStartClicked -> vpnPermission ->
 * startVpnService; refreshStatus for the display; handleTestIntent for the
 * test automation.
 */
package com.kingo132.simplevpn

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import java.util.Locale

/** Settings + status screen; see the file comment above. */
class MainActivity : AppCompatActivity() {

    // Views of res/layout/activity_main.xml, looked up in onCreate
    private lateinit var serverEdit: EditText // server host name or IP
    private lateinit var portEdit: EditText   // server TCP port
    private lateinit var tokenEdit: EditText  // shared secret (vpn_token)
    private lateinit var dnsEdit: EditText    // DNS server the phone should use inside the VPN
    private lateinit var mtuEdit: EditText    // TUN MTU
    private lateinit var appsEdit: EditText   // optional allow list of package names
    private lateinit var ipv6Check: CheckBox  // also route IPv6 into the VPN
    private lateinit var statusText: TextView // state + last message
    private lateinit var statsText: TextView  // packet / byte counters

    /** Main thread handler for the periodic status refresh. */
    private val handler = Handler(Looper.getMainLooper())

    /** Refreshes the status once a second while the activity is visible (posted in onResume). */
    private val refresher = object : Runnable {
        override fun run() {
            refreshStatus()
            handler.postDelayed(this, 1000) // re-post itself: a simple 1 s timer on the UI thread
        }
    }

    /**
     * Launcher for the system VPN consent dialog. Must be registered before
     * the activity is started (hence a property initializer). On "OK" the
     * service is started, otherwise a toast explains why nothing happens.
     */
    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startVpnService()
            } else {
                Toast.makeText(this, R.string.permission_denied, Toast.LENGTH_SHORT).show()
            }
        }

    /**
     * Build the UI, fill the form with the saved settings and wire the buttons.
     * @param savedInstanceState Non-null when the activity is re-created (e.g.
     *   after a rotation); then a test intent was already handled once.
     */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        serverEdit = findViewById(R.id.server_edit)
        portEdit = findViewById(R.id.port_edit)
        tokenEdit = findViewById(R.id.token_edit)
        dnsEdit = findViewById(R.id.dns_edit)
        mtuEdit = findViewById(R.id.mtu_edit)
        appsEdit = findViewById(R.id.apps_edit)
        ipv6Check = findViewById(R.id.ipv6_check)
        statusText = findViewById(R.id.status_text)
        statsText = findViewById(R.id.stats_text)

        // Show what was saved last time
        val settings = VpnSettings.load(this)
        serverEdit.setText(settings.server)
        portEdit.setText(settings.port.toString())
        tokenEdit.setText(settings.token)
        dnsEdit.setText(settings.dns)
        mtuEdit.setText(settings.mtu.toString())
        appsEdit.setText(settings.allowedApps)
        ipv6Check.isChecked = settings.ipv6

        findViewById<Button>(R.id.start_vpn_button).setOnClickListener { onStartClicked() }
        findViewById<Button>(R.id.stop_vpn_button).setOnClickListener { stopVpnService() }

        if (savedInstanceState == null) {
            handleTestIntent(intent) // only on a fresh start, not again after a rotation
        }
    }

    /**
     * The activity is already running and was started again (e.g. a second
     * "adb shell am start" from the device test): handle the new intent.
     * @param intent The new intent.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleTestIntent(intent)
    }

    /**
     * Automation hook for tests/device_test.sh, honoured by debuggable builds only:
     *   adb shell am start -n com.kingo132.simplevpn/.MainActivity --es vpn_action connect \
     *       --es server 192.168.1.10 --ei port 9443 --es token secret [--es dns 8.8.8.8] [--ez ipv6 false]
     *   adb shell am start -n com.kingo132.simplevpn/.MainActivity --es vpn_action disconnect
     * Release builds ignore it, so other apps cannot redirect the VPN to their own server.
     *
     * The extras only fill in the form; then the normal Start / Stop code
     * paths run, so the test exercises exactly what a user's tap does.
     *
     * @param intent The intent that started the activity (may be null).
     */
    private fun handleTestIntent(intent: Intent?) {
        val action = intent?.getStringExtra("vpn_action") ?: return // a normal launch: nothing to do
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            return // release build: ignore (the launcher activity can be started by any app)
        }
        when (action) {
            "connect" -> {
                intent.getStringExtra("server")?.let { serverEdit.setText(it) }
                if (intent.hasExtra("port")) portEdit.setText(intent.getIntExtra("port", 9443).toString())
                intent.getStringExtra("token")?.let { tokenEdit.setText(it) }
                intent.getStringExtra("dns")?.let { dnsEdit.setText(it) }
                intent.getStringExtra("apps")?.let { appsEdit.setText(it) }
                if (intent.hasExtra("ipv6")) ipv6Check.isChecked = intent.getBooleanExtra("ipv6", true)
                onStartClicked()
            }
            "disconnect" -> stopVpnService()
        }
    }

    /** Visible again: start the 1 s status refresh. */
    override fun onResume() {
        super.onResume()
        handler.post(refresher)
    }

    /** Not visible: stop refreshing (no work for a hidden screen). */
    override fun onPause() {
        handler.removeCallbacks(refresher)
        super.onPause()
    }

    /**
     * "Start" tapped (or a test connect command): validate and save the form,
     * then get the VPN permission if needed and start the service.
     */
    private fun onStartClicked() {
        val settings = VpnSettings(
            server = serverEdit.text.toString().trim(),
            port = portEdit.text.toString().toIntOrNull() ?: 9443,
            token = tokenEdit.text.toString(),
            dns = dnsEdit.text.toString().trim().ifEmpty { "8.8.8.8" },
            mtu = (mtuEdit.text.toString().toIntOrNull() ?: 1500).coerceIn(576, 9000), // keep the MTU sane
            ipv6 = ipv6Check.isChecked,
            allowedApps = appsEdit.text.toString().trim(),
        )
        if (settings.server.isEmpty()) {
            serverEdit.error = getString(R.string.server_required)
            return
        }
        settings.save(this) // the service reads the settings from SharedPreferences

        // prepare() returns an intent for the consent dialog, or null if we already have the permission
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermission.launch(intent) // ask the user for the VPN permission once
        } else {
            startVpnService()
        }
    }

    /** Ask [MyVpnService] to (re)connect with the saved settings. */
    private fun startVpnService() {
        startService(Intent(this, MyVpnService::class.java).setAction(MyVpnService.ACTION_CONNECT))
    }

    /** Ask [MyVpnService] to disconnect (only if it runs, so Stop never creates the service). */
    private fun stopVpnService() {
        if (MyVpnService.instance != null) {
            startService(Intent(this, MyVpnService::class.java).setAction(MyVpnService.ACTION_DISCONNECT))
        }
    }

    /** Show the service's current state, message and counters (called every second). */
    private fun refreshStatus() {
        val state = when (MyVpnService.lastState) {
            MyVpnService.STATE_CONNECTING -> getString(R.string.state_connecting)
            MyVpnService.STATE_CONNECTED -> getString(R.string.state_connected)
            MyVpnService.STATE_RECONNECTING -> getString(R.string.state_reconnecting)
            MyVpnService.STATE_AUTH_FAILED -> getString(R.string.state_auth_failed)
            MyVpnService.STATE_FAILED -> getString(R.string.state_failed)
            MyVpnService.STATE_STOPPED -> getString(R.string.state_stopped)
            else -> getString(R.string.state_idle)
        }
        statusText.text = getString(R.string.status_format, state, MyVpnService.lastMessage)

        // Layout of the array: see MyVpnService.stats() / nativeGetStats in native-lib.cpp
        val stats = MyVpnService.instance?.stats()
        statsText.text = if (stats == null) {
            ""
        } else {
            // stats[7] = wall clock ms when the tunnel connected, 0 = not connected
            val uptime = if (stats[7] > 0) (System.currentTimeMillis() - stats[7]) / 1000 else 0
            String.format(
                Locale.US,
                "↑ %d packets  %s\n↓ %d packets  %s\ndropped %d   reconnects %d   uptime %ds",
                stats[1], formatBytes(stats[2]), stats[3], formatBytes(stats[4]), stats[5], stats[6], uptime
            )
        }
    }

    /**
     * Human readable byte count.
     * @param bytes Number of bytes.
     * @return e.g. "512 B", "1.5 KB", "3.25 MB", "1.07 GB" (binary units).
     */
    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1L shl 30 -> String.format(Locale.US, "%.2f GB", bytes / (1L shl 30).toDouble())
        bytes >= 1L shl 20 -> String.format(Locale.US, "%.2f MB", bytes / (1L shl 20).toDouble())
        bytes >= 1L shl 10 -> String.format(Locale.US, "%.1f KB", bytes / (1L shl 10).toDouble())
        else -> "$bytes B"
    }
}
