package dev.leshiy.data

import android.content.Context

/** Misc app-level preferences (SharedPreferences, synchronous for the VpnService). */
object AppPrefs {
    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences("settings", Context.MODE_PRIVATE)

    /**
     * Block all IPv6 while connected (route ::/0 into the tunnel). Off by default: Android can't
     * carry IPv6 through the tunnel yet (the engine's CARRIES_V6 is false), so blocking it
     * black-holes every IPv6 site — which breaks IPv6-heavy services like YouTube/Google. Left
     * off, IPv6 goes direct (it can leak outside the tunnel, but sites keep working). On is a
     * strict no-leak mode for users who accept some IPv6 sites breaking.
     */
    fun blockIpv6(context: Context): Boolean = prefs(context).getBoolean("block_ipv6", false)

    fun setBlockIpv6(context: Context, value: Boolean) =
        prefs(context).edit().putBoolean("block_ipv6", value).apply()
}
