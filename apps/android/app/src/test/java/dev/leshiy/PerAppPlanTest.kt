package dev.leshiy

import dev.leshiy.data.PerAppMode
import dev.leshiy.data.perAppPlan
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PerAppPlanTest {
    private val self = "dev.leshiy"

    @Test
    fun off_disallows_only_self() {
        val p = perAppPlan(PerAppMode.OFF, setOf("com.a", "com.b"), self)
        assertTrue(p.allowed.isEmpty())
        assertEquals(listOf(self), p.disallowed)
    }

    @Test
    fun include_allows_listed_minus_self() {
        val p = perAppPlan(PerAppMode.INCLUDE, setOf("com.a", self), self)
        assertEquals(listOf("com.a"), p.allowed)
        assertTrue(p.disallowed.isEmpty())
    }

    @Test
    fun include_empty_falls_back_to_off() {
        val p = perAppPlan(PerAppMode.INCLUDE, setOf(self), self)
        assertTrue(p.allowed.isEmpty())
        assertEquals(listOf(self), p.disallowed)
    }

    @Test
    fun exclude_disallows_listed_plus_self() {
        val p = perAppPlan(PerAppMode.EXCLUDE, setOf("com.a"), self)
        assertTrue(p.allowed.isEmpty())
        assertTrue(p.disallowed.containsAll(listOf("com.a", self)))
    }
}
