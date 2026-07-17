package dev.leshiy

import dev.leshiy.ui.Sample
import dev.leshiy.ui.appendSample
import dev.leshiy.ui.throughputRate
import org.junit.Assert.assertEquals
import org.junit.Test

class ConnStatsTest {

    @Test
    fun throughput_is_delta_bytes_per_second() {
        // 2000 bytes over 1000 ms = 2000 B/s.
        assertEquals(2000L, throughputRate(prev = 1000u, curr = 3000u, dtMillis = 1000))
        // 500 bytes over 500 ms = 1000 B/s.
        assertEquals(1000L, throughputRate(prev = 0u, curr = 500u, dtMillis = 500))
    }

    @Test
    fun counter_reset_or_no_traffic_is_zero() {
        assertEquals(0L, throughputRate(prev = 5000u, curr = 100u, dtMillis = 1000)) // reset
        assertEquals(0L, throughputRate(prev = 100u, curr = 100u, dtMillis = 1000)) // idle
    }

    @Test
    fun non_positive_dt_is_zero() {
        assertEquals(0L, throughputRate(prev = 0u, curr = 1000u, dtMillis = 0))
    }

    @Test
    fun append_keeps_only_the_last_max_samples() {
        var h = emptyList<Sample>()
        repeat(65) { i -> h = appendSample(h, Sample(rtt = i, upRate = 0, downRate = 0), max = 60) }
        assertEquals(60, h.size)
        assertEquals(5, h.first().rtt) // 0..4 dropped
        assertEquals(64, h.last().rtt)
    }
}
