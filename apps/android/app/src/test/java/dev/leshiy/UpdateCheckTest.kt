package dev.leshiy

import dev.leshiy.update.compareVersions
import dev.leshiy.update.offerUpdate
import dev.leshiy.update.parseAndroidTag
import dev.leshiy.update.parseSha256Sums
import dev.leshiy.update.pickLatestAndroidRelease
import dev.leshiy.update.selectApkAsset
import dev.leshiy.update.shouldAutoCheck
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateCheckTest {
    // --- tag parsing ---

    @Test
    fun `android tag parses to version`() {
        assertEquals("1.7.0", parseAndroidTag("android-v1.7.0"))
    }

    @Test
    fun `server and malformed tags are rejected`() {
        assertNull(parseAndroidTag("v1.7.0"))
        assertNull(parseAndroidTag("android-v1.7"))
        assertNull(parseAndroidTag("android-v1.7.0-rc1"))
        assertNull(parseAndroidTag("desktop-v1.7.0"))
    }

    // --- version compare ---

    @Test
    fun `numeric compare not lexicographic`() {
        assertTrue(compareVersions("1.10.0", "1.9.0") > 0)
        assertTrue(compareVersions("1.6.4", "1.7.0") < 0)
        assertEquals(0, compareVersions("1.7.0", "1.7.0"))
    }

    // --- asset selection ---

    @Test
    fun `prefers new naming, skips unsigned, falls back to legacy`() {
        assertEquals(
            "leshiy_v1.7.0.apk",
            selectApkAsset(listOf("SHA256SUMS", "leshiy_v1.7.0.apk"), "1.7.0"),
        )
        assertNull(selectApkAsset(listOf("SHA256SUMS", "leshiy_v1.7.0-unsigned.apk"), "1.7.0"))
        assertEquals(
            "app-release.apk",
            selectApkAsset(listOf("SHA256SUMS", "app-release.apk"), "1.7.0"),
        )
        assertNull(selectApkAsset(listOf("SHA256SUMS", "app-release-unsigned.apk"), "1.7.0"))
    }

    // --- release list parsing ---

    private fun release(
        tag: String,
        draft: Boolean = false,
        prerelease: Boolean = false,
        assets: List<String> = listOf("leshiy_${tag.removePrefix("android-")}.apk", "SHA256SUMS"),
    ): String {
        val assetsJson = assets.joinToString(",") {
            """{"name":"$it","browser_download_url":"https://example.com/$tag/$it"}"""
        }
        return """{"tag_name":"$tag","draft":$draft,"prerelease":$prerelease,"assets":[$assetsJson]}"""
    }

    @Test
    fun `picks newest android release, ignoring server releases drafts and prereleases`() {
        val json = "[" + listOf(
            release("v1.8.0"), // server train — the shared "latest" scenario
            release("android-v1.8.0", draft = true),
            release("android-v1.7.1", prerelease = true),
            release("android-v1.6.4"),
            release("android-v1.7.0"),
        ).joinToString(",") + "]"
        val c = pickLatestAndroidRelease(json)!!
        assertEquals("1.7.0", c.version)
        assertEquals("leshiy_v1.7.0.apk", c.apkName)
        assertEquals("https://example.com/android-v1.7.0/leshiy_v1.7.0.apk", c.apkUrl)
        assertEquals("https://example.com/android-v1.7.0/SHA256SUMS", c.sumsUrl)
    }

    @Test
    fun `no android release or no usable asset yields null`() {
        assertNull(pickLatestAndroidRelease("[]"))
        assertNull(pickLatestAndroidRelease("[" + release("v1.8.0") + "]"))
        assertNull(
            pickLatestAndroidRelease("[" + release("android-v1.7.0", assets = listOf("SHA256SUMS")) + "]"),
        )
    }

    @Test
    fun `legacy asset naming still resolves`() {
        val json = "[" + release("android-v1.6.4", assets = listOf("app-release.apk", "SHA256SUMS")) + "]"
        assertEquals("app-release.apk", pickLatestAndroidRelease(json)!!.apkName)
    }

    // --- SHA256SUMS parsing ---

    @Test
    fun `sha256sums lines parse, junk ignored`() {
        val digest = "a".repeat(64)
        val sums = parseSha256Sums("$digest  leshiy_v1.7.0.apk\nnot a sums line\n${"B".repeat(64)} *other.apk\n")
        assertEquals(digest, sums["leshiy_v1.7.0.apk"])
        assertEquals("b".repeat(64), sums["other.apk"])
        assertEquals(2, sums.size)
    }

    // --- throttle + offer ---

    @Test
    fun `auto check gated to 24h`() {
        val day = 24L * 60 * 60 * 1000
        assertTrue(shouldAutoCheck(nowMs = day + 1, lastCheckMs = 1))
        assertFalse(shouldAutoCheck(nowMs = day, lastCheckMs = 1))
        assertTrue(shouldAutoCheck(nowMs = 0, lastCheckMs = 0)) // fresh install: never checked
    }

    @Test
    fun `offer only newer non-dismissed versions`() {
        assertTrue(offerUpdate(current = "1.6.4", candidate = "1.7.0", dismissed = null))
        assertFalse(offerUpdate(current = "1.7.0", candidate = "1.7.0", dismissed = null))
        assertFalse(offerUpdate(current = "1.7.0", candidate = "1.6.4", dismissed = null))
        assertFalse(offerUpdate(current = "1.6.4", candidate = "1.7.0", dismissed = "1.7.0"))
        assertTrue(offerUpdate(current = "1.6.4", candidate = "1.7.1", dismissed = "1.7.0"))
    }
}
