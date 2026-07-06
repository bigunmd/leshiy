package dev.leshiy.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.BorderCol
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.Panel
import dev.leshiy.ui.theme.PlexMono
import dev.leshiy.ui.theme.Wisp

/** Sub-screen frame: safe-area insets + a back bar (title + optional trailing action). */
@Composable
fun ScreenFrame(
    title: String,
    onBack: (() -> Unit)? = null,
    trailing: @Composable (() -> Unit)? = null,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .padding(horizontal = 20.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (onBack != null) {
                IconBtn(LeshiyIcons.Back, dev.leshiy.ui.i18n.LocalStrings.current.back, tint = Dim, onClick = onBack)
                Spacer(Modifier.width(6.dp))
            }
            Text(
                title,
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Spacer(Modifier.weight(1f))
            trailing?.invoke()
        }
        content()
    }
}

/** Mono, uppercase, wide-tracked section label. */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        fontFamily = PlexMono,
        fontSize = 10.sp,
        letterSpacing = 2.sp,
        color = Moss,
        modifier = modifier.padding(vertical = 8.dp),
    )
}

/** Rounded panel surface with a hairline border — the standard content container. */
@Composable
fun PanelCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    val shape = RoundedCornerShape(16.dp)
    var m = modifier
        .fillMaxWidth()
        .clip(shape)
        .background(Panel)
        .border(1.dp, BorderCol, shape)
    if (onClick != null) m = m.clickable(onClick = onClick)
    Column(modifier = m.padding(16.dp)) { content() }
}

/** Primary (wisp) action button. */
@Composable
fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Wisp,
            contentColor = Bg0,
            disabledContainerColor = Panel,
            disabledContentColor = Dim,
        ),
    ) { Text(text, fontWeight = FontWeight.SemiBold) }
}

/** Icon-only ghost button. */
@Composable
fun IconBtn(icon: ImageVector, desc: String, tint: Color = Dim, onClick: () -> Unit) {
    Icon(
        imageVector = icon,
        contentDescription = desc,
        tint = tint,
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .clickable(onClick = onClick)
            .padding(8.dp)
            .size(20.dp),
    )
}

/** Deep Bog styled text field. */
@Composable
fun Field(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    trailing: @Composable (() -> Unit)? = null,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        trailingIcon = trailing,
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Wisp,
            unfocusedBorderColor = BorderCol,
            focusedLabelColor = Wisp,
            unfocusedLabelColor = Dim,
            cursorColor = Wisp,
            focusedContainerColor = Bg0,
            unfocusedContainerColor = Bg0,
        ),
    )
}

/** Settings-hub / list row: leading icon, title + subtitle, trailing chevron or content. */
@Composable
fun NavRow(
    icon: ImageVector,
    title: String,
    subtitle: String? = null,
    tint: Color = Wisp,
    onClick: () -> Unit,
) {
    PanelCard(onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = tint, modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(title, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground)
                if (subtitle != null) {
                    Text(subtitle, style = MaterialTheme.typography.labelSmall, color = Dim, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            Icon(LeshiyIcons.ChevronRight, null, tint = Moss, modifier = Modifier.size(18.dp))
        }
    }
}
