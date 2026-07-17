package dev.leshiy.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.BuildConfig
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.i18n.Strings
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Wisp
import dev.leshiy.update.UpdateManager
import dev.leshiy.update.UpdateUi

/**
 * Dismissible "new version available" banner for the Connect screen. Renders nothing when
 * there is no actionable update (or in debug builds, whose signature could never install).
 */
@Composable
fun UpdateCard(modifier: Modifier = Modifier) {
    if (BuildConfig.DEBUG) return
    val s = LocalStrings.current
    val context = LocalContext.current
    val ui by UpdateManager.state.collectAsStateWithLifecycle()
    val u = ui
    val version = when (u) {
        is UpdateUi.Available -> u.candidate.version
        is UpdateUi.Downloading -> u.candidate.version
        is UpdateUi.Verifying -> u.candidate.version
        is UpdateUi.ReadyToInstall -> u.candidate.version
        else -> return
    }
    PanelCard(modifier = modifier) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                s.updNewVersionFmt.format("v$version"),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onBackground,
            )
            when (u) {
                is UpdateUi.Downloading -> {
                    Text(s.updDownloading, style = MaterialTheme.typography.labelSmall, color = Dim)
                    u.progress?.let { LinearProgressIndicator(progress = { it }, color = Wisp) }
                }
                is UpdateUi.Verifying ->
                    Text(s.updVerifying, style = MaterialTheme.typography.labelSmall, color = Dim)
                else -> Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = {
                        if (u is UpdateUi.ReadyToInstall) UpdateManager.install(context, u.file)
                        else UpdateManager.download(context)
                    }) {
                        Text(if (u is UpdateUi.ReadyToInstall) s.updInstall else s.updDownload, color = Wisp)
                    }
                    Spacer(Modifier.size(6.dp))
                    TextButton(onClick = { UpdateManager.dismiss(context) }) {
                        Text(s.updLater, color = Dim)
                    }
                }
            }
        }
    }
}

/** "App update" section for the Settings screen: current version + manual check / actions. */
@Composable
fun UpdateSettingsSection() {
    if (BuildConfig.DEBUG) return
    val s = LocalStrings.current
    val context = LocalContext.current
    val ui by UpdateManager.state.collectAsStateWithLifecycle()
    val u = ui
    Spacer(Modifier.size(6.dp))
    SectionLabel(s.updSection)
    PanelCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    s.updCheck,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Text(statusLine(s, u), style = MaterialTheme.typography.labelSmall, color = Dim)
            }
            Spacer(Modifier.size(12.dp))
            when (u) {
                is UpdateUi.Available ->
                    TextButton(onClick = { UpdateManager.download(context) }) { Text(s.updDownload, color = Wisp) }
                is UpdateUi.ReadyToInstall ->
                    TextButton(onClick = { UpdateManager.install(context, u.file) }) { Text(s.updInstall, color = Wisp) }
                is UpdateUi.Checking, is UpdateUi.Downloading, is UpdateUi.Verifying -> {}
                else ->
                    TextButton(onClick = { UpdateManager.manualCheck(context) }) { Text(s.updCheck, color = Wisp) }
            }
        }
    }
}

private fun statusLine(s: Strings, u: UpdateUi): String = when (u) {
    UpdateUi.Idle -> s.updCurrentFmt.format("v" + BuildConfig.VERSION_NAME)
    UpdateUi.Checking -> s.updChecking
    UpdateUi.UpToDate -> s.updUpToDate
    is UpdateUi.Available -> s.updNewVersionFmt.format("v" + u.candidate.version)
    is UpdateUi.Downloading ->
        s.updDownloading + (u.progress?.let { " ${(it * 100).toInt()}%" } ?: "")
    is UpdateUi.Verifying -> s.updVerifying
    is UpdateUi.ReadyToInstall -> s.updNewVersionFmt.format("v" + u.candidate.version)
    UpdateUi.Failed -> s.updFailed
}
