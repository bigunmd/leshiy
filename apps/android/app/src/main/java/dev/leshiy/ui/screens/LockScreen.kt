package dev.leshiy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Wisp

/**
 * Shown over [dev.leshiy.ui.components.Atmosphere] while the app is locked. The tunnel keeps running
 * underneath — this only gates the UI. [onUnlock] re-launches the biometric prompt.
 */
@Composable
fun LockScreen(onUnlock: () -> Unit) {
    val s = LocalStrings.current
    Column(
        modifier = Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).padding(horizontal = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(LeshiyIcons.Shield, contentDescription = null, tint = Wisp, modifier = Modifier.size(56.dp))
        Spacer(Modifier.size(20.dp))
        Text("LESHIY", fontWeight = FontWeight.Bold, letterSpacing = 3.sp, fontSize = 20.sp, color = MaterialTheme.colorScheme.onBackground)
        Spacer(Modifier.size(8.dp))
        Text(s.lockPrompt, style = MaterialTheme.typography.bodyMedium, color = Dim, textAlign = TextAlign.Center)
        Spacer(Modifier.size(28.dp))
        PrimaryButton(s.lockUnlock, onClick = onUnlock)
    }
}
