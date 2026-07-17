package dev.leshiy

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.RemoteViews
import dev.leshiy.data.Profiles
import dev.leshiy.data.TunnelRepository

/**
 * Home-screen toggle widget mirroring the Quick Settings tile. Tapping replays [tileAction] — the
 * same decision the tile uses — so behaviour stays consistent: running → stop, ready → start,
 * otherwise open the app for consent/profile setup. The [LeshiyVpnService] pushes state refreshes
 * via [requestUpdate]; there is no polling.
 */
class LeshiyWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, mgr: AppWidgetManager, ids: IntArray) {
        val running = TunnelRepository.running.value
        for (id in ids) mgr.updateAppWidget(id, render(context, running))
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_TOGGLE) {
            val verb = tileAction(
                running = TunnelRepository.running.value,
                hasConsent = VpnService.prepare(context) == null,
                hasProfile = runCatching { Profiles.manager(context).activeUri() }.getOrNull() != null,
            )
            when (verb) {
                TileVerb.STOP ->
                    context.startService(
                        Intent(context, LeshiyVpnService::class.java).setAction(LeshiyVpnService.ACTION_STOP),
                    )
                TileVerb.START ->
                    context.startForegroundService(Intent(context, LeshiyVpnService::class.java))
                TileVerb.OPEN_APP ->
                    context.startActivity(
                        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
            }
            requestUpdate(context)
        }
        super.onReceive(context, intent)
    }

    private fun render(context: Context, running: Boolean): RemoteViews {
        val views = RemoteViews(context.packageName, R.layout.widget_leshiy)
        val tint = if (running) COLOR_ON else COLOR_OFF
        views.setInt(R.id.widget_icon, "setColorFilter", tint)
        views.setTextColor(R.id.widget_state, tint)
        views.setTextViewText(
            R.id.widget_state,
            context.getString(if (running) R.string.widget_state_on else R.string.widget_state_off),
        )
        views.setOnClickPendingIntent(R.id.widget_root, togglePendingIntent(context))
        return views
    }

    private fun togglePendingIntent(context: Context): PendingIntent =
        PendingIntent.getBroadcast(
            context,
            0,
            Intent(context, LeshiyWidgetProvider::class.java).setAction(ACTION_TOGGLE),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

    companion object {
        private const val ACTION_TOGGLE = "dev.leshiy.WIDGET_TOGGLE"
        private const val COLOR_ON = 0xFF7CE07A.toInt() // Wisp
        private const val COLOR_OFF = 0xFF8FA98C.toInt() // Dim

        /** Re-render every placed widget (called by the service on connect/disconnect). */
        fun requestUpdate(context: Context) {
            val mgr = AppWidgetManager.getInstance(context) ?: return
            val ids = mgr.getAppWidgetIds(ComponentName(context, LeshiyWidgetProvider::class.java))
            if (ids.isEmpty()) return
            val provider = LeshiyWidgetProvider()
            provider.onUpdate(context, mgr, ids)
        }
    }
}
