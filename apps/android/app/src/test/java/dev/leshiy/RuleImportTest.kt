package dev.leshiy

import dev.leshiy.data.parseRuleEntries
import org.junit.Assert.assertEquals
import org.junit.Test

class RuleImportTest {

    @Test
    fun sorts_lines_into_normalized_cidrs_and_domains() {
        val (cidrs, domains) = parseRuleEntries(
            sequenceOf("10.0.0.0/8", "1.2.3.4", "Example.COM", "*.cdn.example.net", "2001:db8::/32"),
        )
        assertEquals(setOf("10.0.0.0/8", "1.2.3.4/32", "2001:db8::/32"), cidrs)
        assertEquals(setOf("example.com", "*.cdn.example.net"), domains)
    }

    @Test
    fun drops_invalid_lines_and_duplicates() {
        val (cidrs, domains) = parseRuleEntries(
            sequenceOf("10.0.0.0/8", "10.0.0.0/8", "not a rule", "999.1.1.1", "example.com", "EXAMPLE.com"),
        )
        assertEquals(setOf("10.0.0.0/8"), cidrs)
        assertEquals(setOf("example.com"), domains)
    }

    @Test
    fun a_large_list_parses_in_one_pass() {
        val lines = (0 until 50_000).asSequence().map { "10.${it / 65536}.${(it / 256) % 256}.${it % 256}" }
        assertEquals(50_000, parseRuleEntries(lines).first.size)
    }
}
