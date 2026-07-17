package dev.leshiy.ui.screens

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.StepState
import dev.leshiy.ui.UPGRADE_STEPS
import dev.leshiy.ui.UpgradeState
import dev.leshiy.ui.UpgradeViewModel
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.formatElapsed
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.stepStates
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.BorderCol
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.PlexMono
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp
import kotlinx.coroutines.delay

/**
 * Live upgrade timeline.
 *
 * A stepper rather than a progress bar on purpose: `docker pull` is one blocking remote command
 * that streams no percentage, so a bar would park mid-track and imply precision we don't have.
 */
@Composable
fun UpgradeScreen(
    vm: UpgradeViewModel,
    onDone: () -> Unit,
    onBack: () -> Unit,
) {
    val s = LocalStrings.current
    val state by vm.state.collectAsStateWithLifecycle()
    var logsOpen by remember { mutableStateOf(false) }

    // Clock for the active step's timer. Ticks only while the op runs.
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(state.running) {
        while (state.running) {
            now = System.currentTimeMillis()
            delay(500)
        }
    }

    val names = listOf(s.stepConnect, s.stepPullImage, s.stepRecreate, s.stepSave)
    require(names.size == UPGRADE_STEPS.size) {
        "UPGRADE_STEPS has ${UPGRADE_STEPS.size} steps but `names` only labels ${names.size} — add a label"
    }
    val states = stepStates(UPGRADE_STEPS.size, state.doneCount, state.activeIndex, state.failedIndex)

    val (headline, tint) = when {
        state.error != null -> s.upgradeFailed to Warn
        state.done -> s.upgraded.format(state.to) to Wisp
        state.activeIndex >= 0 -> names[state.activeIndex] to Wisp
        else -> s.upgradingTitle to Wisp
    }

    ScreenFrame(state.label.ifBlank { s.upgradingTitle }, onBack = onBack) {
        Column(
            modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Spacer(Modifier.size(4.dp))

            Text(headline, style = MaterialTheme.typography.titleLarge, color = tint)
            if (state.from.isNotBlank()) {
                Text(
                    if (state.from == state.to) state.to else "${state.from}  →  ${state.to}",
                    style = MaterialTheme.typography.labelSmall,
                    color = Dim,
                )
            }

            Spacer(Modifier.size(2.dp))

            Column {
                names.forEachIndexed { i, name ->
                    if (i > 0) Connector(filled = states[i - 1] == StepState.DONE)
                    StepRow(name, states[i], timerFor(i, states[i], state, now))
                }
            }

            state.error?.let {
                Text(it, style = MaterialTheme.typography.labelSmall, color = Warn)
            }
            if (state.error == null && state.detail.isNotBlank()) {
                Text(
                    state.detail,
                    fontFamily = PlexMono,
                    style = MaterialTheme.typography.labelSmall,
                    color = Moss,
                    maxLines = 2,
                )
            }

            // Collapsible logs (closed by default) — same affordance as ProvisioningScreen.
            if (state.log.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth().clickable { logsOpen = !logsOpen }.padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        if (logsOpen) LeshiyIcons.ChevronDown else LeshiyIcons.ChevronRight,
                        null,
                        tint = Moss,
                        modifier = Modifier.size(16.dp),
                    )
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

            when {
                state.done -> PrimaryButton(s.doneAction, onClick = onDone, modifier = Modifier.fillMaxWidth())
                state.error != null -> PrimaryButton(s.back, onClick = onBack, modifier = Modifier.fillMaxWidth())
            }
        }
    }
}

/** Elapsed for a step: live while active, frozen at its final duration once done. */
private fun timerFor(i: Int, st: StepState, state: UpgradeState, now: Long): String? = when (st) {
    StepState.ACTIVE -> formatElapsed(now - state.activeSince)
    StepState.DONE -> state.stepMs[i]?.let { formatElapsed(it) }
    else -> null
}

/** The line between two nodes; fills once the step above it is done. */
@Composable
private fun Connector(filled: Boolean) {
    Box(
        Modifier
            .padding(start = 10.dp)
            .width(2.dp)
            .height(14.dp)
            .background(if (filled) Wisp else BorderCol),
    )
}

@Composable
private fun StepRow(name: String, state: StepState, timer: String?) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        StepNode(state)
        Spacer(Modifier.width(12.dp))
        Text(
            name,
            style = MaterialTheme.typography.bodyMedium,
            color = when (state) {
                StepState.DONE -> MaterialTheme.colorScheme.onBackground
                StepState.ACTIVE -> Wisp
                StepState.FAILED -> Warn
                StepState.PENDING -> Dim
            },
            modifier = Modifier.weight(1f),
        )
        if (timer != null) {
            Text(timer, fontFamily = PlexMono, style = MaterialTheme.typography.labelSmall, color = Dim)
        }
    }
}

@Composable
private fun StepNode(state: StepState) {
    Box(Modifier.size(22.dp), contentAlignment = Alignment.Center) {
        if (state == StepState.ACTIVE) PulsingHalo()
        when (state) {
            StepState.DONE -> Box(
                Modifier.size(18.dp).background(Wisp, CircleShape),
                contentAlignment = Alignment.Center,
            ) { Icon(LeshiyIcons.Check, null, tint = Bg0, modifier = Modifier.size(11.dp)) }

            StepState.FAILED -> Box(
                Modifier.size(18.dp).background(Warn, CircleShape),
                contentAlignment = Alignment.Center,
            ) { Icon(LeshiyIcons.Close, null, tint = Bg0, modifier = Modifier.size(11.dp)) }

            StepState.ACTIVE -> Box(Modifier.size(12.dp).background(Wisp, CircleShape))
            StepState.PENDING -> Box(Modifier.size(12.dp).border(1.5.dp, BorderCol, CircleShape))
        }
    }
}

/** The "working, duration unknown" signal — the honest substitute for a percentage. */
@Composable
private fun PulsingHalo() {
    val t = rememberInfiniteTransition(label = "halo")
    val scale by t.animateFloat(
        initialValue = 1f,
        targetValue = 1.5f,
        animationSpec = infiniteRepeatable(tween(900), RepeatMode.Reverse),
        label = "scale",
    )
    val alpha by t.animateFloat(
        initialValue = 0.35f,
        targetValue = 0.05f,
        animationSpec = infiniteRepeatable(tween(900), RepeatMode.Reverse),
        label = "alpha",
    )
    Box(Modifier.size(22.dp).scale(scale).alpha(alpha).background(Wisp, CircleShape))
}
