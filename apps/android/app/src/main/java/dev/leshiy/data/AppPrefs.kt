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

    /**
     * Keep the tunnel alive while the device sleeps, by waking the CPU periodically to ping
     * (ADR-0031). Off by default.
     *
     * Off, the tunnel dies once a sleep outlasts the server's tolerance and re-dials within ~2s of
     * waking — invisible unless something needed to reach you meanwhile. On, it survives sleep, so
     * apps routed through the tunnel keep receiving pushes; the cost is a couple of seconds of CPU
     * every ~9 minutes (Doze's floor for an allow-while-idle alarm), which is far cheaper than a
     * wakelock but not free.
     *
     * Does nothing against a server predating CAP_IDLE_TOLERANCE: it drops the session at 45s
     * regardless, long before the alarm can fire. Degrades to the off behaviour rather than
     * breaking.
     */
    fun sleepKeepalive(context: Context): Boolean =
        prefs(context).getBoolean("sleep_keepalive", false)

    fun setSleepKeepalive(context: Context, value: Boolean) =
        prefs(context).edit().putBoolean("sleep_keepalive", value).apply()

    /** Epoch ms of the last GitHub release check (launch checks are throttled to 24h). */
    fun lastUpdateCheck(context: Context): Long = prefs(context).getLong("last_update_check", 0L)

    fun setLastUpdateCheck(context: Context, value: Long) =
        prefs(context).edit().putLong("last_update_check", value).apply()

    /** Version whose "new version" card the user dismissed — don't re-nag on launch checks. */
    fun dismissedUpdateVersion(context: Context): String? =
        prefs(context).getString("dismissed_update_version", null)

    fun setDismissedUpdateVersion(context: Context, value: String) =
        prefs(context).edit().putString("dismissed_update_version", value).apply()
}
