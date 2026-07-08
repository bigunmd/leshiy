package dev.leshiy.ui.screens

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.ProvisionViewModel
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.BorderCol
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.PlexMono
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp

@Composable
fun ProvisioningScreen(
    vm: ProvisionViewModel,
    onDone: (String, String) -> Unit,
    onBack: () -> Unit,
) {
    val s = LocalStrings.current
    val state by vm.state.collectAsStateWithLifecycle()
    val total = ProvisionViewModel.TOTAL_STEPS
    val target = when {
        state.resultUri != null -> 1f
        state.stepIndex < 0 -> 0.02f
        else -> ((state.stepIndex + 1).coerceIn(0, total)) / total.toFloat()
    }
    val progress by animateFloatAsState(target, label = "progress")
    var logsOpen by remember { mutableStateOf(false) }

    ScreenFrame(
        if (state.resultUri != null) s.serverReady else s.provisioningTitle,
        onBack = { onBack() },
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Spacer(Modifier.size(4.dp))

            // Status headline.
            val (headline, tint) = when {
                state.error != null -> s.provisionFailed to Warn
                state.resultUri != null -> s.serverReady to Wisp
                else -> state.label to Wisp
            }
            Text(headline, style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.onBackground)

            // Progress bar.
            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth().height(8.dp),
                color = if (state.error != null) Warn else Wisp,
                trackColor = BorderCol,
            )

            // Step counter / latest detail.
            if (state.error != null) {
                Text(state.error!!, style = MaterialTheme.typography.labelSmall, color = Warn)
            } else if (state.resultUri == null) {
                val stepNum = (state.stepIndex + 1).coerceIn(0, total)
                Text(
                    s.stepOf.format(stepNum, total),
                    style = MaterialTheme.typography.labelSmall,
                    color = Dim,
                )
                state.log.lastOrNull()?.let {
                    Text(it, fontFamily = PlexMono, style = MaterialTheme.typography.labelSmall, color = Moss, maxLines = 2)
                }
            }

            // Collapsible logs (closed by default).
            if (state.log.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth().clickable { logsOpen = !logsOpen }.padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(if (logsOpen) LeshiyIcons.ChevronDown else LeshiyIcons.ChevronRight, null, tint = Moss, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    SectionLabel("${s.logs} · ${state.log.size}")
                }
                if (logsOpen) {
                    PanelCard {
                        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            state.log.forEach { line ->
                                Text(line, fontFamily = PlexMono, style = MaterialTheme.typography.labelSmall, color = Dim)
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.size(4.dp))

            // Terminal actions.
            when {
                state.resultUri != null -> PrimaryButton(
                    s.goToServers,
                    onClick = { onDone(state.resultUri!!, state.label) },
                    modifier = Modifier.fillMaxWidth(),
                )
                state.error != null -> PrimaryButton(
                    s.back,
                    onClick = onBack,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}
