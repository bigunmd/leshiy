package dev.leshiy.data

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import uniffi.leshiy_mobile.ConnState

/** How a [UiMessage] should be presented and what recovery it offers. */
enum class UiMessageKind {
    /** Informational failure — message plus a dismiss. */
    PLAIN,

    /** A dropped/failed tunnel — offers Retry + Switch server. */
    CONNECTION_FAILURE,
}

data class UiMessage(val text: String, val kind: UiMessageKind = UiMessageKind.PLAIN)

/**
 * App-wide one-shot UI notifications (snackbars). Process-scoped singleton, mirroring
 * [TunnelRepository]: any ViewModel/manager emits, the global host in `AppNav` collects. A buffered
 * [MutableSharedFlow] with no replay so a message shows once and isn't re-shown to a new collector.
 */
object UiEvents {
    private val _messages = MutableSharedFlow<UiMessage>(extraBufferCapacity = 8)
    val messages: SharedFlow<UiMessage> = _messages.asSharedFlow()

    fun emit(message: UiMessage) {
        _messages.tryEmit(message)
    }
}

/**
 * True only on the transition edge into [ConnState.FAILED] — so the failure snackbar fires once per
 * failure, not on every status tick while the tunnel stays failed. [prev] is null before the first
 * status arrives.
 */
fun isFailureEdge(prev: ConnState?, next: ConnState): Boolean =
    next == ConnState.FAILED && prev != ConnState.FAILED
