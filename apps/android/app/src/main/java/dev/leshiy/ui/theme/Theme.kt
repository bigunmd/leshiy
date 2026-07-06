package dev.leshiy.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

// Deep Bog is a dark-only identity — no light scheme, matching the desktop GUI.
private val DeepBog = darkColorScheme(
    primary = Wisp,
    onPrimary = Bg0,
    secondary = Moss,
    onSecondary = Bg0,
    background = Bg0,
    onBackground = Foreground,
    surface = Panel,
    onSurface = Foreground,
    surfaceVariant = Accent,
    onSurfaceVariant = Dim,
    outline = BorderCol,
    outlineVariant = BorderCol,
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
