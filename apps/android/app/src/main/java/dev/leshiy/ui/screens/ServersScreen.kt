package dev.leshiy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.ProfilesViewModel
import dev.leshiy.ui.components.Field
import dev.leshiy.ui.components.IconBtn
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.Wisp

@Composable
fun ServersScreen(
    vm: ProfilesViewModel,
    scannedUri: String,
    onScan: () -> Unit,
    onConsumeScan: () -> Unit,
    onBack: () -> Unit,
) {
    val profiles by vm.profiles.collectAsStateWithLifecycle()
    val clipboard = LocalClipboardManager.current
    var name by remember { mutableStateOf("") }
    var uri by remember { mutableStateOf("") }
    // Absorb a QR scan into the URI field.
    androidx.compose.runtime.LaunchedEffect(scannedUri) {
        if (scannedUri.isNotEmpty()) {
            uri = scannedUri
            onConsumeScan()
        }
    }

    ScreenFrame("Servers", onBack = onBack) {
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item { SectionLabel("Saved servers") }
            if (profiles.isEmpty()) {
                item {
                    Text(
                        "No servers yet. Paste a leshiy:// link or scan a QR code below.",
                        style = MaterialTheme.typography.labelSmall,
                        color = Dim,
                    )
                }
            }
            items(profiles, key = { it.id }) { p ->
                PanelCard(onClick = { vm.activate(p.id) }) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            LeshiyIcons.Wisp, null,
                            tint = if (p.isActive) Wisp else Moss,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(p.name, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(
                                if (p.isActive) "active" else "tap to select",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (p.isActive) Wisp else Dim,
                            )
                        }
                        IconBtn(LeshiyIcons.Trash, "Remove", tint = MaterialTheme.colorScheme.error) { vm.remove(p.id) }
                    }
                }
            }

            item { Spacer(Modifier.size(8.dp)); SectionLabel("Add a server") }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Field(name, { name = it }, "Name (optional)")
                    Field(
                        uri, { uri = it }, "leshiy:// link",
                        trailing = {
                            Row {
                                IconBtn(LeshiyIcons.Clipboard, "Paste from clipboard", tint = Wisp) {
                                    clipboard.getText()?.text?.trim()?.let { if (it.isNotEmpty()) uri = it }
                                }
                                IconBtn(LeshiyIcons.Qr, "Scan QR", tint = Wisp, onClick = onScan)
                            }
                        },
                    )
                    PrimaryButton(
                        "Add server",
                        onClick = {
                            if (vm.add(uri, name)) { uri = ""; name = "" }
                        },
                        enabled = uri.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }
    }
}
