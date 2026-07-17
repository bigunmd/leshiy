package dev.leshiy.ui

/** Human-readable byte count (cumulative counters from the bridge). */
fun formatBytes(n: ULong): String {
    val b = n.toDouble()
    return when {
        b < 1024 -> "$n B"
        b < 1024 * 1024 -> String.format("%.1f KB", b / 1024)
        b < 1024.0 * 1024 * 1024 -> String.format("%.1f MB", b / (1024 * 1024))
        else -> String.format("%.2f GB", b / (1024.0 * 1024 * 1024))
    }
}

/** Elapsed connection time as m:ss, extending to h:mm:ss past an hour. Negatives clamp to 0. */
fun formatDuration(totalSeconds: Long): String {
    val s = totalSeconds.coerceAtLeast(0)
    val h = s / 3600
    val m = (s % 3600) / 60
    val sec = s % 60
    // Locale.ROOT: a clock should render the same digits/separators regardless of device locale.
    return if (h > 0) {
        String.format(java.util.Locale.ROOT, "%d:%02d:%02d", h, m, sec)
    } else {
        String.format(java.util.Locale.ROOT, "%d:%02d", m, sec)
    }
}
