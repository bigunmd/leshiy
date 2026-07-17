package dev.leshiy.update

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import dev.leshiy.BuildConfig
import dev.leshiy.data.AppPrefs
import dev.leshiy.data.UiEvents
import dev.leshiy.data.UiMessage
import dev.leshiy.ui.i18n.LangState
import dev.leshiy.ui.i18n.stringsFor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** What the update UI (Connect card + Settings row) renders. Single source of truth. */
sealed interface UpdateUi {
    data object Idle : UpdateUi
    data object Checking : UpdateUi
    data object UpToDate : UpdateUi
    data class Available(val candidate: ReleaseCandidate) : UpdateUi
    data class Downloading(val candidate: ReleaseCandidate, val progress: Float?) : UpdateUi
    data class Verifying(val candidate: ReleaseCandidate) : UpdateUi
    data class ReadyToInstall(val candidate: ReleaseCandidate, val file: File) : UpdateUi
    data object Failed : UpdateUi
}

/**
 * Checks GitHub Releases for a newer `android-v*` build, downloads + SHA-256-verifies the APK,
 * and hands it to the platform installer. Best-effort by design: when the tunnel is up the
 * requests ride through it; when GitHub is unreachable, launch checks fail silently.
 */
object UpdateManager {
    private const val RELEASES_URL =
        "https://api.github.com/repos/bigunmd/leshiy/releases?per_page=30"
    private const val TIMEOUT_MS = 8_000

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val _state = MutableStateFlow<UpdateUi>(UpdateUi.Idle)
    val state: StateFlow<UpdateUi> = _state

    /** Silent launch check: release builds only, at most once per 24h, never surfaces errors. */
    fun autoCheck(context: Context) {
        if (BuildConfig.DEBUG) return
        val app = context.applicationContext
        if (!shouldAutoCheck(System.currentTimeMillis(), AppPrefs.lastUpdateCheck(app))) return
        scope.launch { runCheck(app, manual = false) }
    }

    fun manualCheck(context: Context) {
        val app = context.applicationContext
        scope.launch { runCheck(app, manual = true) }
    }

    /** Hide the card for this version until a strictly newer one appears (or a manual check). */
    fun dismiss(context: Context) {
        val candidate = when (val s = _state.value) {
            is UpdateUi.Available -> s.candidate
            is UpdateUi.ReadyToInstall -> s.candidate
            else -> return
        }
        AppPrefs.setDismissedUpdateVersion(context.applicationContext, candidate.version)
        _state.value = UpdateUi.Idle
    }

    fun download(context: Context) {
        val candidate = (state.value as? UpdateUi.Available)?.candidate ?: return
        val app = context.applicationContext
        scope.launch {
            _state.value = UpdateUi.Downloading(candidate, null)
            try {
                val dir = File(app.cacheDir, "updates").apply {
                    deleteRecursively() // drop stale APKs from earlier update rounds
                    mkdirs()
                }
                val sumsUrl = candidate.sumsUrl ?: error("release has no SHA256SUMS")
                val sums = parseSha256Sums(fetchText(sumsUrl))
                val expected = sums[candidate.apkName] ?: error("no checksum for ${candidate.apkName}")
                val apk = File(dir, candidate.apkName)
                fetchFile(candidate.apkUrl, apk) { done, total ->
                    _state.value = UpdateUi.Downloading(candidate, total?.let { done.toFloat() / it })
                }
                _state.value = UpdateUi.Verifying(candidate)
                if (sha256Hex(apk) != expected) {
                    apk.delete()
                    error("checksum mismatch")
                }
                _state.value = UpdateUi.ReadyToInstall(candidate, apk)
            } catch (_: Exception) {
                _state.value = UpdateUi.Failed
                UiEvents.emit(UiMessage(stringsFor(LangState.lang.value).updateFailedSnack))
            }
        }
    }

    /** The platform re-verifies the signature; a wrong signing key can't install over us. */
    fun install(context: Context, file: File) {
        val uri = FileProvider.getUriForFile(context, "dev.leshiy.fileprovider", file)
        context.startActivity(
            Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            },
        )
    }

    private fun runCheck(app: Context, manual: Boolean) {
        when (_state.value) {
            is UpdateUi.Downloading, is UpdateUi.Verifying -> return // don't clobber a download
            else -> {}
        }
        if (manual) _state.value = UpdateUi.Checking
        try {
            val body = fetchText(RELEASES_URL)
            AppPrefs.setLastUpdateCheck(app, System.currentTimeMillis())
            val candidate = pickLatestAndroidRelease(body)
            val current = BuildConfig.VERSION_NAME
            _state.value = when {
                candidate == null || compareVersions(candidate.version, current) <= 0 ->
                    if (manual) UpdateUi.UpToDate else UpdateUi.Idle
                // Manual checks resurface even a dismissed version; launch checks don't.
                manual || offerUpdate(current, candidate.version, AppPrefs.dismissedUpdateVersion(app)) ->
                    UpdateUi.Available(candidate)
                else -> UpdateUi.Idle
            }
        } catch (_: Exception) {
            _state.value = if (manual) UpdateUi.Failed else UpdateUi.Idle
            // Only manual checks surface a message; silent background checks stay quiet.
            if (manual) UiEvents.emit(UiMessage(stringsFor(LangState.lang.value).updateFailedSnack))
        }
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            setRequestProperty("Accept", "application/vnd.github+json")
        }

    private fun fetchText(url: String): String {
        val conn = open(url)
        try {
            check(conn.responseCode == 200) { "HTTP ${conn.responseCode}" }
            return conn.inputStream.bufferedReader().readText()
        } finally {
            conn.disconnect()
        }
    }

    private fun fetchFile(url: String, dest: File, onProgress: (Long, Long?) -> Unit) {
        val conn = open(url)
        try {
            check(conn.responseCode == 200) { "HTTP ${conn.responseCode}" }
            val total = conn.contentLengthLong.takeIf { it > 0 }
            conn.inputStream.use { input ->
                dest.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    var done = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        done += n
                        onProgress(done, total)
                    }
                }
            }
        } finally {
            conn.disconnect()
        }
    }

    private fun sha256Hex(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
