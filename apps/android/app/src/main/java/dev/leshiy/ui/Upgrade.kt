package dev.leshiy.ui

/** Visual state of one node in the upgrade timeline. */
enum class StepState { PENDING, ACTIVE, DONE, FAILED }

/** The steps `ServerManager.upgrade` emits, in order. Index = position in the timeline. */
val UPGRADE_STEPS = listOf("Connect", "PullImage", "RunContainer", "Persist")

/**
 * Everything the upgrade screen renders.
 *
 * [activeIndex] is tracked rather than derived from [doneCount] because it is where a thrown
 * error gets pinned — see [applyError].
 */
data class UpgradeState(
    val running: Boolean = false,
    /** Step Started but not yet Done; -1 when none. */
    val activeIndex: Int = -1,
    /** Steps fully Done. */
    val doneCount: Int = 0,
    val failedIndex: Int = -1,
    val log: List<String> = emptyList(),
    /** Latest non-blank event detail — the image ref, during the pull. */
    val detail: String = "",
    val error: String? = null,
    val done: Boolean = false,
    /** Short versions for the `from → to` subtitle. */
    val from: String = "",
    val to: String = "",
    /** Server label, for the screen title. */
    val label: String = "",
    /** Finalised per-step durations in ms, keyed by step index. */
    val stepMs: Map<Int, Long> = emptyMap(),
    /**
     * When the active step started, for its live timer.
     *
     * Only meaningful while [activeIndex] names the step it belongs to — a `Done` for some
     * other index must not read this as its own start time. `0L` is a valid start time (a
     * step can legitimately start at `nowMs = 0`), so [activeIndex] identity, not a
     * greater-than-zero check, is what gates its use in [applyEvent].
     */
    val activeSince: Long = 0L,
)

/** Fold one bridge progress event into the state. Unknown steps are logged and ignored. */
fun UpgradeState.applyEvent(step: String, status: String, detail: String, nowMs: Long): UpgradeState {
    var next = copy(log = log + "$step/$status  $detail".trimEnd())
    if (detail.isNotBlank()) next = next.copy(detail = detail)
    val i = UPGRADE_STEPS.indexOf(step)
    if (i < 0) return next
    return when (status) {
        "Started" -> next.copy(activeIndex = i, activeSince = nowMs)
        "Done" -> next.copy(
            doneCount = maxOf(next.doneCount, i + 1),
            activeIndex = -1,
            // Gate on step identity, not a timestamp sentinel: `activeSince` is only this
            // step's start time when `activeIndex == i` — a stray Done for a step that never
            // Started, or one arriving after a different step's stale activeSince, must not
            // borrow someone else's start time, and a step that legitimately starts at
            // nowMs = 0 must not have its duration silently dropped.
            stepMs = if (next.activeIndex == i) next.stepMs + (i to (nowMs - next.activeSince)) else next.stepMs,
        )
        "Failed" -> next.copy(failedIndex = i, activeIndex = -1)
        else -> next
    }
}

/**
 * Pin a thrown FFI error to whichever step was in flight.
 *
 * `engine::upgrade` returns `Err` without emitting a Failed event, so this is the only way the
 * timeline can show *where* an upgrade broke.
 */
fun UpgradeState.applyError(message: String): UpgradeState = copy(
    running = false,
    error = message,
    failedIndex = if (activeIndex >= 0) activeIndex else failedIndex,
    activeIndex = -1,
)

/** Per-step visual state. A step already counted done stays done. */
fun stepStates(count: Int, doneCount: Int, activeIndex: Int, failedIndex: Int): List<StepState> =
    (0 until count).map { i ->
        when {
            i < doneCount -> StepState.DONE
            i == failedIndex -> StepState.FAILED
            i == activeIndex -> StepState.ACTIVE
            else -> StepState.PENDING
        }
    }

/**
 * The human-facing version in an image ref: its tag, when it has one.
 *
 * Deliberately conservative, because the Advanced field accepts any ref. A registry port
 * (`localhost:5000/leshiy`) is not a tag and a digest's hex is not a version, so both refs are
 * returned whole rather than mined for something that merely looks like one.
 */
fun shortVersion(imageRef: String): String {
    val name = imageRef.substringAfterLast('/')
    if (name.contains('@') || !name.contains(':')) return imageRef
    return name.substringAfterLast(':')
}

/** True when [target] is a different image than [current]. Never claims "newer" — ordering is
 *  meaningless across tags and digests. */
fun updateAvailable(current: String, target: String): Boolean = current != target

/** `m:ss` elapsed, for the step timers. */
fun formatElapsed(ms: Long): String {
    val total = (ms / 1000).coerceAtLeast(0)
    return "${total / 60}:${(total % 60).toString().padStart(2, '0')}"
}
