package dev.leshiy.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

// Deep Bog is a dark-only identity — no light scheme, matching the desktop GUI.
private val DeepBog = darkColorScheme(
    primary = Wisp,
    onPrimary = Bg0,
    secondary = Moss,
    background = Bg0,
    onBackground = Foreground,
    surface = Panel,
    onSurface = Foreground,
    surfaceVariant = Bg1,
    onSurfaceVariant = Dim,
    error = Warn,
    onError = Bg0,
)

@Composable
fun LeshiyTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DeepBog,
        typography = LeshiyTypography,
        content = content,
    )
}
