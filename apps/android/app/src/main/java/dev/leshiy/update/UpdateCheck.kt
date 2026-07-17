package dev.leshiy.update

import org.json.JSONArray

/** A downloadable Android release discovered on GitHub. */
data class ReleaseCandidate(
    /** Dotted version from the tag, e.g. "1.7.0". */
    val version: String,
    /** Asset filename — also the key into SHA256SUMS. */
    val apkName: String,
    val apkUrl: String,
    /** SHA256SUMS asset URL; null means the release can't be verified (and won't install). */
    val sumsUrl: String?,
)

/** "android-v1.2.3" → "1.2.3"; null for server-train (`v*`), suffixed, or malformed tags. */
fun parseAndroidTag(tag: String): String? =
    Regex("""^android-v(\d+\.\d+\.\d+)$""").find(tag)?.groupValues?.get(1)

/** Numeric compare of dotted versions ("1.10.0" > "1.9.0"); negative when [a] < [b]. */
fun compareVersions(a: String, b: String): Int {
    val pa = a.split(".").map { it.toIntOrNull() ?: 0 }
    val pb = b.split(".").map { it.toIntOrNull() ?: 0 }
    for (i in 0 until maxOf(pa.size, pb.size)) {
        val d = pa.getOrElse(i) { 0 }.compareTo(pb.getOrElse(i) { 0 })
        if (d != 0) return d
    }
    return 0
}

/**
 * The APK asset to download: the CI name (`leshiy_vX.Y.Z.apk`) when present, else any signed
 * `.apk` (covers pre-rename releases' `app-release.apk`). `-unsigned` builds are never offered —
 * they can't install over a signed app anyway.
 */
fun selectApkAsset(names: List<String>, version: String): String? {
    val preferred = "leshiy_v$version.apk"
    if (preferred in names) return preferred
    return names.firstOrNull { it.endsWith(".apk") && !it.contains("-unsigned") }
}

/**
 * Newest published `android-v*` release in a GitHub `/releases` JSON array, or null.
 * Deliberately not `/releases/latest`: the shared "latest" pointer is pinned to the `v*`
 * server/CLI train (see verify-release-pointer.yml).
 */
fun pickLatestAndroidRelease(json: String): ReleaseCandidate? {
    val arr = JSONArray(json)
    var best: ReleaseCandidate? = null
    for (i in 0 until arr.length()) {
        val rel = arr.getJSONObject(i)
        if (rel.optBoolean("draft") || rel.optBoolean("prerelease")) continue
        val version = parseAndroidTag(rel.optString("tag_name")) ?: continue
        if (best != null && compareVersions(version, best.version) <= 0) continue
        val assets = rel.optJSONArray("assets") ?: continue
        val urlByName = HashMap<String, String>()
        for (j in 0 until assets.length()) {
            val a = assets.getJSONObject(j)
            urlByName[a.optString("name")] = a.optString("browser_download_url")
        }
        val apkName = selectApkAsset(urlByName.keys.toList(), version) ?: continue
        best = ReleaseCandidate(
            version = version,
            apkName = apkName,
            apkUrl = urlByName.getValue(apkName),
            sumsUrl = urlByName["SHA256SUMS"],
        )
    }
    return best
}

/** `sha256sum` output → filename → lowercase hex digest; non-matching lines ignored. */
fun parseSha256Sums(text: String): Map<String, String> =
    text.lines().mapNotNull { line ->
        Regex("""^([0-9a-fA-F]{64})\s+\*?(\S+)$""").find(line.trim())
            ?.let { it.groupValues[2] to it.groupValues[1].lowercase() }
    }.toMap()

const val CHECK_INTERVAL_MS: Long = 24L * 60 * 60 * 1000

/** Launch checks are best-effort and rare: first run, then at most every 24h. */
fun shouldAutoCheck(nowMs: Long, lastCheckMs: Long): Boolean =
    lastCheckMs == 0L || nowMs - lastCheckMs >= CHECK_INTERVAL_MS

/** Show the launch-check card only for strictly newer, not-yet-dismissed versions. */
fun offerUpdate(current: String, candidate: String, dismissed: String?): Boolean =
    compareVersions(candidate, current) > 0 && candidate != dismissed
