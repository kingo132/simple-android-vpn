/**
 * @file VpnSettings.kt
 * The user's VPN settings and their persistence in SharedPreferences.
 *
 * MainActivity fills a [VpnSettings] from its form and calls [VpnSettings.save];
 * MyVpnService calls [VpnSettings.load] when it connects. Storing the
 * settings (instead of passing them in the intent) lets the system restart
 * the VPN on its own (sticky service, always-on VPN) with the same values.
 */
package com.kingo132.simplevpn

import android.content.Context

/** User settings of the VPN, stored in SharedPreferences. */
data class VpnSettings(
    /** Server host name or IP address; empty = not configured yet. */
    val server: String = "",
    /** TCP port of the server's tunnel listener (tunnel::kDefaultPort). */
    val port: Int = 9443,
    /** Shared secret, must equal vpn_token in the server config. */
    val token: String = "change-me",
    /** DNS server the phone uses while the VPN is up (queries travel through the tunnel). */
    val dns: String = "8.8.8.8",
    /** MTU of the TUN interface, i.e. the largest IP packet the phone sends. */
    val mtu: Int = 1500,
    /** Also route IPv6 into the VPN. */
    val ipv6: Boolean = true,
    /** Comma separated package names. Empty = every app except this one goes through the VPN. */
    val allowedApps: String = "",
) {
    /**
     * @return The package names of [allowedApps]; commas, spaces and newlines
     *   all work as separators, empty entries are dropped.
     */
    fun allowedPackages(): List<String> =
        allowedApps.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }

    /**
     * Persist the settings.
     * @param context Any context of the app.
     */
    fun save(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("server", server)
            .putInt("port", port)
            .putString("token", token)
            .putString("dns", dns)
            .putInt("mtu", mtu)
            .putBoolean("ipv6", ipv6)
            .putString("allowed_apps", allowedApps)
            .apply() // asynchronous write; the in-memory values are visible to load() at once
    }

    companion object {
        /** Name of the SharedPreferences file (private to this app). */
        private const val PREFS = "simplevpn"

        /**
         * Read the saved settings.
         * @param context Any context of the app.
         * @return The saved values, with the constructor defaults for anything never saved.
         */
        fun load(context: Context): VpnSettings {
            val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val defaults = VpnSettings()
            return VpnSettings(
                // getString() is nullable in the Android API, hence the ?: fallback
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
