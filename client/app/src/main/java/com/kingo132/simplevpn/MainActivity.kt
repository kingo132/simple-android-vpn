package com.kingo132.simplevpn

import android.content.Intent
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

class MainActivity : AppCompatActivity() {

    private lateinit var serverEdit: EditText
    private lateinit var portEdit: EditText
    private lateinit var tokenEdit: EditText
    private lateinit var dnsEdit: EditText
    private lateinit var mtuEdit: EditText
    private lateinit var appsEdit: EditText
    private lateinit var ipv6Check: CheckBox
    private lateinit var statusText: TextView
    private lateinit var statsText: TextView

    private val handler = Handler(Looper.getMainLooper())
    private val refresher = object : Runnable {
        override fun run() {
            refreshStatus()
            handler.postDelayed(this, 1000)
        }
    }

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startVpnService()
            } else {
                Toast.makeText(this, R.string.permission_denied, Toast.LENGTH_SHORT).show()
            }
        }

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
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresher)
    }

    override fun onPause() {
        handler.removeCallbacks(refresher)
        super.onPause()
    }

    private fun onStartClicked() {
        val settings = VpnSettings(
            server = serverEdit.text.toString().trim(),
            port = portEdit.text.toString().toIntOrNull() ?: 9443,
            token = tokenEdit.text.toString(),
            dns = dnsEdit.text.toString().trim().ifEmpty { "8.8.8.8" },
            mtu = (mtuEdit.text.toString().toIntOrNull() ?: 1500).coerceIn(576, 9000),
            ipv6 = ipv6Check.isChecked,
            allowedApps = appsEdit.text.toString().trim(),
        )
        if (settings.server.isEmpty()) {
            serverEdit.error = getString(R.string.server_required)
            return
        }
        settings.save(this)

        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermission.launch(intent) // ask the user for the VPN permission once
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        startService(Intent(this, MyVpnService::class.java).setAction(MyVpnService.ACTION_CONNECT))
    }

    private fun stopVpnService() {
        if (MyVpnService.instance != null) {
            startService(Intent(this, MyVpnService::class.java).setAction(MyVpnService.ACTION_DISCONNECT))
        }
    }

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

        val stats = MyVpnService.instance?.stats()
        statsText.text = if (stats == null) {
            ""
        } else {
            val uptime = if (stats[7] > 0) (System.currentTimeMillis() - stats[7]) / 1000 else 0
            String.format(
                Locale.US,
                "↑ %d packets  %s\n↓ %d packets  %s\ndropped %d   reconnects %d   uptime %ds",
                stats[1], formatBytes(stats[2]), stats[3], formatBytes(stats[4]), stats[5], stats[6], uptime
            )
        }
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1L shl 30 -> String.format(Locale.US, "%.2f GB", bytes / (1L shl 30).toDouble())
        bytes >= 1L shl 20 -> String.format(Locale.US, "%.2f MB", bytes / (1L shl 20).toDouble())
        bytes >= 1L shl 10 -> String.format(Locale.US, "%.1f KB", bytes / (1L shl 10).toDouble())
        else -> "$bytes B"
    }
}
