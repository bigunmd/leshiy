package dev.leshiy.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarVisuals
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.leshiy.data.UiMessageKind
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Panel
import dev.leshiy.ui.theme.Wisp

/** Snackbar payload that also carries the [UiMessageKind], so the host can pick its actions. */
class LeshiySnackbarVisuals(
    override val message: String,
    val kind: UiMessageKind,
) : SnackbarVisuals {
    override val actionLabel: String? = null
    override val withDismissAction: Boolean = false
    override val duration: SnackbarDuration =
        if (kind == UiMessageKind.CONNECTION_FAILURE) SnackbarDuration.Long else SnackbarDuration.Short
}

/**
 * Deep Bog snackbar host. A connection failure renders Retry + Switch server (Material3 supports
 * only one native action, so the content is custom); anything else renders a Dismiss.
 */
@Composable
fun LeshiySnackbarHost(
    hostState: SnackbarHostState,
    onRetry: () -> Unit,
    onSwitch: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val s = LocalStrings.current
    SnackbarHost(hostState, modifier = modifier) { data ->
        val kind = (data.visuals as? LeshiySnackbarVisuals)?.kind ?: UiMessageKind.PLAIN
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = Panel,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    data.visuals.message,
                    modifier = Modifier.weight(1f),
                    color = MaterialTheme.colorScheme.onBackground,
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.width(8.dp))
                if (kind == UiMessageKind.CONNECTION_FAILURE) {
                    Action(s.snSwitchServer, Dim, FontWeight.Medium) { onSwitch(); data.dismiss() }
                    Action(s.snRetry, Wisp, FontWeight.SemiBold) { onRetry(); data.dismiss() }
                } else {
                    Action(s.snDismiss, Wisp, FontWeight.Medium) { data.dismiss() }
                }
            }
        }
    }
}

@Composable
private fun Action(text: String, color: androidx.compose.ui.graphics.Color, weight: FontWeight, onClick: () -> Unit) {
    Text(
        text,
        color = color,
        fontWeight = weight,
        style = MaterialTheme.typography.labelLarge,
        modifier = Modifier.clip(RoundedCornerShape(8.dp)).clickable(onClick = onClick).padding(horizontal = 8.dp, vertical = 6.dp),
    )
}
