package dev.leshiy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import dev.leshiy.data.AppPrefs
import dev.leshiy.data.TunnelRepository

/**
 * Wakes the CPU periodically so the tunnel's keepalive can fire while the device sleeps
 * (ADR-0031). Scheduled by [LeshiyVpnService] only when the user opts in.
 *
 * It sends nothing itself. The mux decides when to ping from the **wall clock**, not a monotonic
 * timer — a `sleep(15s)` is frozen mid-count by suspend and would need 15 seconds of *awake* time
 * after waking, which these brief wakes would take hours to accumulate. So the entire job here is
 * to hold the CPU awake long enough for that poll to run and notice a ping is overdue.
 *
 * `goAsync` is what makes the hold real: `onReceive` normally releases its wakelock the moment it
 * returns, and the device could suspend again before the poll ever ran.
 */
class KeepalivePingReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        // The alarm outlives a stopped tunnel if teardown was skipped (crash, force-stop). Don't
        // hold the CPU for a tunnel that isn't there, and don't re-arm.
        if (!TunnelRepository.running.value || !AppPrefs.sleepKeepalive(context)) {
            LeshiyVpnService.cancelKeepaliveAlarm(context)
            return
        }

        val result = goAsync()
        Thread {
            try {
                // Long enough for the mux's wall-clock keepalive poll to run and send. Short
                // enough that the cost is a couple of seconds of CPU per ~9 minutes rather than
                // the permanent wakelock this exists to avoid.
                Thread.sleep(HOLD_MS)
            } catch (e: InterruptedException) {
                Log.w(TAG, "keepalive hold interrupted: $e")
                Thread.currentThread().interrupt()
            } finally {
                // Re-arm before releasing: allow-while-idle alarms are one-shot, so a missed
                // re-arm silently ends the keepalive and the tunnel quietly reverts to dying on
                // the next long sleep.
                LeshiyVpnService.scheduleKeepaliveAlarm(context)
                result.finish()
            }
        }.start()
    }

    private companion object {
        const val TAG = "LeshiyKeepalive"

        /** How long to hold the CPU so the wall-clock keepalive poll gets a turn. */
        const val HOLD_MS = 3_000L
    }
}
