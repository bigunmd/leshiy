package dev.leshiy.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.components.NavRow
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.i18n.Lang
import dev.leshiy.ui.i18n.LangState
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp

@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onServers: () -> Unit,
    onSplit: () -> Unit,
    onDeploy: () -> Unit,
    onManage: () -> Unit,
) {
    val s = LocalStrings.current
    val context = LocalContext.current
    val lang by LangState.lang.collectAsStateWithLifecycle()

    ScreenFrame(s.settings, onBack = onBack) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            SectionLabel(s.secConnection)
            NavRow(LeshiyIcons.Server, s.servers, s.serversSub, tint = Wisp, onClick = onServers)
            NavRow(LeshiyIcons.Shield, s.splitTunnel, s.splitSub, tint = Wisp, onClick = onSplit)

            Spacer(Modifier.size(6.dp))
            SectionLabel(s.secYourServers)
            NavRow(LeshiyIcons.Rocket, s.deploy, s.deploySub, tint = Wisp, onClick = onDeploy)
            NavRow(LeshiyIcons.Gear, s.manage, s.manageSub, tint = Warn, onClick = onManage)

            Spacer(Modifier.size(6.dp))
            SectionLabel(s.language)
            Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surface, border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)) {
                Row(Modifier.padding(3.dp), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                    LangSeg("English", lang == Lang.EN, Modifier.weight(1f)) { LangState.set(context, Lang.EN) }
                    LangSeg("Русский", lang == Lang.RU, Modifier.weight(1f)) { LangState.set(context, Lang.RU) }
                }
            }
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.LangSeg(text: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(9.dp),
        color = if (selected) Wisp else Color.Transparent,
        modifier = modifier,
    ) {
        Text(
            text,
            modifier = Modifier.padding(vertical = 9.dp),
            textAlign = TextAlign.Center,
            color = if (selected) Bg0 else Dim,
            style = MaterialTheme.typography.labelLarge,
        )
    }
}
