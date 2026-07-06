package dev.leshiy.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.layout.Box
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.Fog1
import dev.leshiy.ui.theme.Fog2
import dev.leshiy.ui.theme.Fog3
import dev.leshiy.ui.theme.Vignette

/**
 * Ambient Deep Bog backdrop: layered fog radials + a vignette, matching the desktop GUI's
 * `.atmosphere`. Draws behind everything; static (no animation) to stay battery-friendly.
 */
@Composable
fun Atmosphere(content: @Composable () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Bg0)
            .drawBehind {
                val w = size.width
                val h = size.height
                drawRect(
                    Brush.radialGradient(
                        listOf(Fog1, Color.Transparent),
                        center = Offset(w * 0.5f, h * 0.32f),
                        radius = maxOf(w, h) * 0.45f,
                    ),
                )
                drawRect(
                    Brush.radialGradient(
                        listOf(Fog2, Color.Transparent),
                        center = Offset(w * 0.7f, h * 0.8f),
                        radius = maxOf(w, h) * 0.55f,
                    ),
                )
                drawRect(
                    Brush.radialGradient(
                        listOf(Fog3, Color.Transparent),
                        center = Offset(w * 0.2f, h * 0.7f),
                        radius = maxOf(w, h) * 0.5f,
                    ),
                )
                drawRect(
                    Brush.radialGradient(
                        listOf(Color.Transparent, Vignette),
                        center = Offset(w * 0.5f, h * 0.38f),
                        radius = maxOf(w, h) * 0.9f,
                    ),
                )
            },
    ) {
        content()
    }
}
