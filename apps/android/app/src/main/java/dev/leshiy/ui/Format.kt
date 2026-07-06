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
