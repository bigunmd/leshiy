package dev.leshiy.data

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Parse `host:port` from a `leshiy://<pubkey>@<host>:<port>?<query>` URI (the authority between `@`
 * and `?`). Handles bracketed IPv6. Returns null on a wrong scheme, missing authority/port, or an
 * out-of-range port. Pure — kept testable.
 */
fun hostPort(uri: String): Pair<String, Int>? {
    val afterScheme = uri.removePrefix("leshiy://")
    if (afterScheme == uri) return null // wrong scheme
    val authority = afterScheme.substringAfter('@', "").substringBefore('?').substringBefore('/')
    if (authority.isEmpty()) return null

    val host: String
    val portStr: String
    if (authority.startsWith("[")) { // [ipv6]:port
        host = authority.substringAfter('[').substringBefore(']')
        portStr = authority.substringAfterLast("]:", "")
    } else {
        host = authority.substringBeforeLast(':', "")
        portStr = authority.substringAfterLast(':', "")
    }
    val port = portStr.toIntOrNull() ?: return null
    if (host.isEmpty() || port !in 1..65535) return null
    return host to port
}

/** Id of the lowest-latency reachable server, or null if none are reachable. Pure. */
fun fastestReachable(latencies: Map<String, Long?>): String? =
    latencies.entries.filter { it.value != null }.minByOrNull { it.value!! }?.key

/**
 * TCP-connect latency to [host]:[port] in ms, or null on failure/timeout. A bare connect to the
 * REALITY port is indistinguishable from a browser that gave up (the server serves the masqueraded
 * site to unauthenticated peers), so it leaves no distinguishing fingerprint.
 */
suspend fun tcpLatency(host: String, port: Int, timeoutMs: Int): Long? = withContext(Dispatchers.IO) {
    val socket = Socket()
    try {
        val start = SystemClock.elapsedRealtime()
        socket.connect(InetSocketAddress(host, port), timeoutMs)
        SystemClock.elapsedRealtime() - start
    } catch (_: Exception) {
        null
    } finally {
        runCatching { socket.close() }
    }
}
