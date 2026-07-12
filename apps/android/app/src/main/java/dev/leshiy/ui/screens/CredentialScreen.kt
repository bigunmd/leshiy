package dev.leshiy.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.ManageViewModel
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.QrCard
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.qrImageBitmap
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.PlexMono
import dev.leshiy.ui.theme.Wisp

/** The issued credential: a QR to scan on another device, plus copy / save / share. */
@Composable
fun CredentialScreen(
    vm: ManageViewModel,
    onSaveToProfiles: (String, String) -> Unit,
    onBack: () -> Unit,
) {
    val s = LocalStrings.current
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val credential by vm.credential.collectAsStateWithLifecycle()

    val cred = credential
    if (cred == null) {
        ScreenFrame(s.credential, onBack = onBack) {}
        return
    }

    val qr = remember(cred.uri) { qrImageBitmap(cred.uri) }
    var saved by remember(cred.uri) { mutableStateOf(false) }
    var note by remember(cred.uri) { mutableStateOf<String?>(null) }

    ScreenFrame(cred.label, onBack = onBack) {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(s.credentialHint, style = MaterialTheme.typography.labelSmall, color = Dim)

            QrCard(qr, modifier = Modifier.padding(horizontal = 24.dp))

            SectionLabel(s.leshiyLink)
            PanelCard {
                Text(cred.uri, fontFamily = PlexMono, style = MaterialTheme.typography.labelSmall, color = Wisp)
            }

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                CredAction(LeshiyIcons.Clipboard, s.copyLink, Modifier.weight(1f)) {
                    clipboard.setText(AnnotatedString(cred.uri))
                    note = s.copied
                }
                CredAction(LeshiyIcons.Wisp, if (saved) s.saved else s.saveToProfiles, Modifier.weight(1f), enabled = !saved) {
                    onSaveToProfiles(cred.uri, cred.label)
                    saved = true
                    note = s.savedToProfiles
                }
                CredAction(LeshiyIcons.Share, s.share, Modifier.weight(1f)) {
                    val send = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, cred.uri)
                    }
                    context.startActivity(Intent.createChooser(send, s.share))
                }
            }
            note?.let { Text(it, style = MaterialTheme.typography.labelSmall, color = Wisp, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth()) }
        }
    }
}

/** A square-ish icon+label tile used for the credential actions. */
@Composable
private fun CredAction(
    icon: ImageVector,
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    val tint = if (enabled) Wisp else Dim
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(14.dp),
        color = Color.Transparent,
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = modifier,
    ) {
        Column(
            modifier = Modifier.padding(vertical = 14.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(icon, null, tint = tint, modifier = Modifier.size(20.dp))
            Text(label, style = MaterialTheme.typography.labelSmall, color = tint, fontWeight = FontWeight.Medium, maxLines = 1)
        }
    }
}
