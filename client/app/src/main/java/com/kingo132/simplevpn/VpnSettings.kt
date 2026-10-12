package com.kingo132.simplevpn

import android.content.Context

/** User settings of the VPN, stored in SharedPreferences. */
data class VpnSettings(
    val server: String = "",
    val port: Int = 9443,
    val token: String = "change-me",
    val dns: String = "8.8.8.8",
    val mtu: Int = 1500,
    val ipv6: Boolean = true,
    /** Comma separated package names. Empty = every app except this one goes through the VPN. */
    val allowedApps: String = "",
) {
    fun allowedPackages(): List<String> =
        allowedApps.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }

    fun save(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("server", server)
            .putInt("port", port)
            .putString("token", token)
            .putString("dns", dns)
            .putInt("mtu", mtu)
            .putBoolean("ipv6", ipv6)
            .putString("allowed_apps", allowedApps)
            .apply()
    }

    companion object {
        private const val PREFS = "simplevpn"

        fun load(context: Context): VpnSettings {
            val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val defaults = VpnSettings()
            return VpnSettings(
                server = p.getString("server", defaults.server) ?: defaults.server,
                port = p.getInt("port", defaults.port),
                token = p.getString("token", defaults.token) ?: defaults.token,
                dns = p.getString("dns", defaults.dns) ?: defaults.dns,
                mtu = p.getInt("mtu", defaults.mtu),
                ipv6 = p.getBoolean("ipv6", defaults.ipv6),
                allowedApps = p.getString("allowed_apps", defaults.allowedApps) ?: defaults.allowedApps,
            )
        }
    }
}
