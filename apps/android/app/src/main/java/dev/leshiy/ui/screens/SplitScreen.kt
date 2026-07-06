package dev.leshiy.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.data.PerAppMode
import dev.leshiy.ui.AppsViewModel
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Wisp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun SplitScreen(vm: AppsViewModel, onBack: () -> Unit) {
    val mode by vm.mode.collectAsStateWithLifecycle()
    val apps by vm.apps.collectAsStateWithLifecycle()
    val enabled = mode != PerAppMode.OFF

    ScreenFrame("Split tunnel", onBack = onBack) {
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                Column {
                    SegmentedMode(mode) { vm.setMode(it) }
                    Spacer(Modifier.size(8.dp))
                    Text(
                        when (mode) {
                            PerAppMode.OFF -> "All apps go through the VPN."
                            PerAppMode.INCLUDE -> "Only the checked apps go through the VPN."
                            PerAppMode.EXCLUDE -> "Checked apps bypass the VPN; everything else is tunneled."
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = Dim,
                    )
                    Spacer(Modifier.size(4.dp))
                    SectionLabel("Apps")
                }
            }
            items(apps, key = { it.pkg }) { row ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp)
                        .graphicsLayer { alpha = if (enabled) 1f else 0.4f },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    AppIcon(row.pkg)
                    Spacer(Modifier.width(12.dp))
                    Text(
                        row.label,
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onBackground,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Checkbox(checked = row.checked, enabled = enabled) { if (enabled) vm.toggle(row.pkg) }
                }
            }
        }
    }
}

@Composable
private fun SegmentedMode(mode: PerAppMode, onSelect: (PerAppMode) -> Unit) {
    Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surface, border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline)) {
        Row(Modifier.padding(3.dp), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
            PerAppMode.entries.forEach { m ->
                val sel = m == mode
                Surface(
                    onClick = { onSelect(m) },
                    shape = RoundedCornerShape(9.dp),
                    color = if (sel) Wisp else androidx.compose.ui.graphics.Color.Transparent,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(
                        m.name.lowercase().replaceFirstChar { it.uppercase() },
                        modifier = Modifier.padding(vertical = 8.dp),
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        color = if (sel) Bg0 else Dim,
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
            }
        }
    }
}

@Composable
private fun Checkbox(checked: Boolean, enabled: Boolean, onToggle: () -> Unit) {
    val shape = RoundedCornerShape(7.dp)
    Surface(
        onClick = onToggle,
        enabled = enabled,
        shape = shape,
        color = if (checked) Wisp else androidx.compose.ui.graphics.Color.Transparent,
        border = androidx.compose.foundation.BorderStroke(1.5.dp, if (checked) Wisp else MaterialTheme.colorScheme.outline),
        modifier = Modifier.size(24.dp),
    ) {
        if (checked) {
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                Icon(LeshiyIcons.Check, null, tint = Bg0, modifier = Modifier.size(15.dp))
            }
        }
    }
}

/** Real launcher icon for a package, loaded off the main thread. */
@Composable
private fun AppIcon(pkg: String) {
    val context = LocalContext.current
    val bitmap by produceState<ImageBitmap?>(initialValue = null, pkg) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                context.packageManager.getApplicationIcon(pkg).toBitmap(72, 72).asImageBitmap()
            }.getOrNull()
        }
    }
    Box(
        modifier = Modifier.size(32.dp).clip(RoundedCornerShape(8.dp)),
        contentAlignment = Alignment.Center,
    ) {
        val bmp = bitmap
        if (bmp != null) {
            Image(bmp, contentDescription = null, modifier = Modifier.size(32.dp))
        } else {
            Icon(LeshiyIcons.Server, null, tint = Dim, modifier = Modifier.size(18.dp))
        }
    }
}
