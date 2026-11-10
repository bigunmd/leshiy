package dev.leshiy

/** Per-watch callback state: a recovered network is not the initial registration callback. */
internal class NetworkRecovery<T> {
    private var seenNetwork = false
    private var current: T? = null

    fun available(network: T): Boolean {
        val reconnect = seenNetwork && current != network
        seenNetwork = true
        current = network
        return reconnect
    }

    fun lost(network: T) {
        if (current == network) current = null
    }
}
