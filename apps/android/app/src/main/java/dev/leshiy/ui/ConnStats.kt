package dev.leshiy.ui

import uniffi.leshiy_mobile.ConnState

/** One sampled point of live connection stats. Rates are bytes/second over the sample interval. */
data class Sample(val rtt: Int, val upRate: Long, val downRate: Long)

/** Samples kept in the rolling window and the tick interval — 60 × 1s = one minute of history. */
const val MAX_SAMPLES = 60
const val SAMPLE_MS = 1000L

/**
 * Per-second byte rate from two cumulative counter readings [dtMillis] apart. Returns 0 on a counter
 * reset (curr < prev, e.g. a reconnect zeroed the counters) or a non-positive interval, so a reset
 * never shows as a negative or absurd spike.
 */
fun throughputRate(prev: ULong, curr: ULong, dtMillis: Long): Long {
    if (dtMillis <= 0 || curr < prev) return 0
    return ((curr - prev).toLong() * 1000) / dtMillis
}

/**
 * Whether the rolling window should collect a sample this tick. [enabled] is the user's opt-in
 * (graphs are off by default), so when it's false we do no sampling at all rather than collecting
 * a window nothing renders.
 */
fun shouldSample(enabled: Boolean, running: Boolean, state: ConnState): Boolean =
    enabled && running && state == ConnState.CONNECTED

/** Append [sample] to the rolling window, keeping at most [max] most-recent samples. */
fun appendSample(history: List<Sample>, sample: Sample, max: Int): List<Sample> =
    (history + sample).takeLast(max)
