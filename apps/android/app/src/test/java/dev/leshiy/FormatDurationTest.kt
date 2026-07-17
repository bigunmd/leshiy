package dev.leshiy

import dev.leshiy.ui.formatDuration
import org.junit.Assert.assertEquals
import org.junit.Test

class FormatDurationTest {

    @Test
    fun formats_minutes_and_seconds() {
        assertEquals("0:00", formatDuration(0))
        assertEquals("0:05", formatDuration(5))
        assertEquals("1:00", formatDuration(60))
        assertEquals("5:23", formatDuration(323))
    }

    @Test
    fun adds_hours_past_an_hour() {
        assertEquals("1:00:00", formatDuration(3600))
        assertEquals("2:05:09", formatDuration(2 * 3600 + 5 * 60 + 9))
    }

    @Test
    fun negative_clamps_to_zero() {
        assertEquals("0:00", formatDuration(-10))
    }
}
