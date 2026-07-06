package dev.leshiy.ui.components

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.unit.dp
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.BorderCol
import dev.leshiy.ui.theme.EmberBorder
import dev.leshiy.ui.theme.EmberText
import dev.leshiy.ui.theme.Panel
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.WarnBright
import dev.leshiy.ui.theme.Wisp
import dev.leshiy.ui.theme.WispBright
import uniffi.leshiy_mobile.ConnState

private data class OrbSkin(
    val border: Color,
    val icon: Color,
    val tint: Color,
    val glow: Color,
)

private fun skin(state: ConnState): OrbSkin = when (state) {
    ConnState.CONNECTED -> OrbSkin(Wisp, WispBright, Wisp.copy(alpha = 0.30f), Wisp)
    ConnState.CONNECTING, ConnState.RECONNECTING ->
        OrbSkin(BorderCol, WispBright, Wisp.copy(alpha = 0.10f), Wisp)
    ConnState.FAILED -> OrbSkin(Warn, WarnBright, Warn.copy(alpha = 0.14f), Warn)
    ConnState.DISCONNECTED -> OrbSkin(EmberBorder, EmberText, Panel, EmberBorder)
}

/**
 * The signature connect control: a 168dp orb whose glow, border and animation encode the tunnel
 * state — ember (idle), pulse + spinner (connecting), breathe (connected), shake (error).
 */
@Composable
fun ConnectOrb(
    state: ConnState,
    enabled: Boolean,
    onToggle: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val s = skin(state)
    val busy = state == ConnState.CONNECTING || state == ConnState.RECONNECTING

    val transition = rememberInfiniteTransition(label = "orb")
    // Glow breathes for the live/connecting states; a slow ember flicker at idle.
    val glowAlpha by transition.animateFloat(
        initialValue = if (state == ConnState.CONNECTED) 0.35f else 0.18f,
        targetValue = when (state) {
            ConnState.CONNECTED -> 0.6f
            ConnState.CONNECTING, ConnState.RECONNECTING -> 0.55f
            ConnState.FAILED -> 0.45f
            ConnState.DISCONNECTED -> 0.3f
        },
        animationSpec = infiniteRepeatable(
            tween(if (busy) 1400 else 3400), RepeatMode.Reverse,
        ),
        label = "glow",
    )
    val breathe by transition.animateFloat(
        initialValue = 1f,
        targetValue = if (state == ConnState.CONNECTED) 1.03f else 1f,
        animationSpec = infiniteRepeatable(tween(3200), RepeatMode.Reverse),
        label = "breathe",
    )
    val spin by transition.animateFloat(
        initialValue = 0f, targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(900), RepeatMode.Restart),
        label = "spin",
    )
    val shake by transition.animateFloat(
        initialValue = 0f,
        targetValue = if (state == ConnState.FAILED) 1f else 0f,
        animationSpec = infiniteRepeatable(tween(90), RepeatMode.Reverse),
        label = "shake",
    )

    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val pressScale = if (pressed && enabled) 0.9f else 1f

    Box(
        modifier = modifier
            .size(168.dp)
            .scale(pressScale * breathe),
        contentAlignment = Alignment.Center,
    ) {
        // Colored halo behind the core.
        Box(
            modifier = Modifier
                .size(168.dp)
                .drawBehind {
                    drawCircle(
                        Brush.radialGradient(
                            listOf(s.glow.copy(alpha = glowAlpha), Color.Transparent),
                            center = center,
                            radius = size.minDimension * 0.5f,
                        ),
                    )
                },
        )

        // Spinner arc while connecting.
        if (busy) {
            Box(
                modifier = Modifier
                    .size(152.dp)
                    .drawBehind {
                        rotate(spin) {
                            drawArc(
                                color = Wisp,
                                startAngle = 0f,
                                sweepAngle = 90f,
                                useCenter = false,
                                style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round),
                            )
                        }
                    },
            )
        }

        // Core disc.
        Box(
            modifier = Modifier
                .size(144.dp)
                .graphicsLayer {
                    if (state == ConnState.FAILED) translationX = (shake * 2f - 1f) * 3.dp.toPx()
                }
                .clip(CircleShape)
                .drawBehind {
                    drawCircle(
                        Brush.radialGradient(
                            listOf(s.tint, Bg0),
                            center = Offset(size.width * 0.5f, size.height * 0.38f),
                            radius = size.minDimension * 0.62f,
                        ),
                    )
                }
                .border(BorderStroke(2.dp, s.border), CircleShape)
                .clickableOrb(enabled, interaction, onToggle),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = LeshiyIcons.Power,
                contentDescription = "toggle connection",
                tint = s.icon,
                modifier = Modifier.size(48.dp),
            )
        }
    }
}

private fun Modifier.clickableOrb(
    enabled: Boolean,
    interaction: MutableInteractionSource,
    onToggle: () -> Unit,
): Modifier = clickable(
    interactionSource = interaction,
    indication = null,
    enabled = enabled,
    onClick = onToggle,
)
