package dev.leshiy.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.BorderCol
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Panel
import dev.leshiy.ui.theme.Wisp

/** Small inline spinner sized for buttons and pills. */
@Composable
fun Spinner(size: Int = 18, color: Color = Wisp, stroke: Int = 2) {
    CircularProgressIndicator(
        modifier = Modifier.size(size.dp),
        color = color,
        strokeWidth = stroke.dp,
    )
}

/** Filled (wisp) primary button that shows a spinner in place of its label while [loading]. */
@Composable
fun LoadingButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    loading: Boolean = false,
) {
    Button(
        onClick = onClick,
        enabled = enabled && !loading,
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Wisp,
            contentColor = Bg0,
            disabledContainerColor = Panel,
            disabledContentColor = Dim,
        ),
    ) {
        if (loading) Spinner(color = Bg0) else Text(text, fontWeight = FontWeight.SemiBold)
    }
}

/** Bordered secondary/danger action; swaps its label for a spinner while [loading]. */
@Composable
fun OutlineButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    loading: Boolean = false,
    danger: Boolean = false,
) {
    val tint = if (danger) MaterialTheme.colorScheme.error else Wisp
    Surface(
        onClick = onClick,
        enabled = enabled && !loading,
        shape = RoundedCornerShape(12.dp),
        color = Color.Transparent,
        border = BorderStroke(1.dp, if (danger) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline),
        modifier = modifier,
    ) {
        Box(Modifier.padding(vertical = 12.dp), contentAlignment = Alignment.Center) {
            if (loading) Spinner(color = tint) else {
                Text(text, style = MaterialTheme.typography.labelLarge, color = tint, fontWeight = FontWeight.Medium)
            }
        }
    }
}

/** A status chip: a colored dot (or spinner while [loading]) + a label, in a rounded pill. */
@Composable
fun StatusPill(label: String, dot: Color, loading: Boolean, modifier: Modifier = Modifier) {
    val shape = RoundedCornerShape(50)
    Row(
        modifier = modifier
            .clip(shape)
            .background(Panel)
            .border(1.dp, BorderCol, shape)
            .padding(horizontal = 14.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (loading) {
            Spinner(size = 12, color = dot, stroke = 2)
        } else {
            Box(Modifier.size(9.dp).clip(RoundedCornerShape(50)).background(dot))
        }
        Spacer(Modifier.width(9.dp))
        Text(label, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onBackground)
    }
}

/** A QR code on a light card — dark modules need a light quiet zone to scan reliably. */
@Composable
fun QrCard(bitmap: ImageBitmap, modifier: Modifier = Modifier) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = Color.White,
        modifier = modifier,
    ) {
        Image(
            bitmap = bitmap,
            contentDescription = null,
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1f)
                .padding(16.dp),
        )
    }
}
