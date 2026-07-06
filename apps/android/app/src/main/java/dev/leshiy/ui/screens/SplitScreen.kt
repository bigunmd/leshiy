package dev.leshiy.ui.screens

import android.os.Build
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.data.PerAppMode
import dev.leshiy.data.SplitKind
import dev.leshiy.ui.AppsViewModel
import dev.leshiy.ui.SplitViewModel
import dev.leshiy.ui.components.Field
import dev.leshiy.ui.components.IconBtn
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.PlexMono
import dev.leshiy.ui.theme.Wisp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun SplitScreen(appsVm: AppsViewModel, splitVm: SplitViewModel, onBack: () -> Unit) {
    val kind by splitVm.kind.collectAsStateWithLifecycle()

    ScreenFrame(LocalStrings.current.splitTunnel, onBack = onBack) {
        KindToggle(kind) { splitVm.setKind(it) }
        Spacer(Modifier.size(12.dp))
        when (kind) {
            SplitKind.APP -> AppSplit(appsVm)
            SplitKind.NETWORK -> NetSplit(splitVm)
        }
    }
}

/* ---------- By app ---------- */

@Composable
private fun ColumnScope.AppSplit(vm: AppsViewModel) {
    val mode by vm.mode.collectAsStateWithLifecycle()
    val apps by vm.apps.collectAsStateWithLifecycle()
    val enabled = mode != PerAppMode.OFF
    var query by remember { mutableStateOf("") }
    val shown = remember(apps, query) {
        if (query.isBlank()) apps else apps.filter { it.label.contains(query.trim(), ignoreCase = true) }
    }

    val s = LocalStrings.current
    ModeSelector(mode) { vm.setMode(it) }
    Spacer(Modifier.size(8.dp))
    Hint(
        when (mode) {
            PerAppMode.OFF -> s.hintAppOff
            PerAppMode.INCLUDE -> s.hintAppInclude
            PerAppMode.EXCLUDE -> s.hintAppExclude
        },
    )
    Spacer(Modifier.size(10.dp))
    Field(query, { query = it }, s.searchApps, trailing = { Icon(LeshiyIcons.Search, null, tint = Dim, modifier = Modifier.size(18.dp)) })
    SectionLabel("${s.apps}${if (query.isNotBlank()) " · ${shown.size}" else ""}")

    LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(shown, key = { it.pkg }) { row ->
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp).graphicsLayer { alpha = if (enabled) 1f else 0.4f },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                AppIcon(row.pkg)
                Spacer(Modifier.width(12.dp))
                Text(row.label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onBackground, maxLines = 1, overflow = TextOverflow.Ellipsis)
                CheckBox(row.checked, enabled) { if (enabled) vm.toggle(row.pkg) }
            }
        }
    }
}

/* ---------- By network (CIDR/IP) ---------- */

@Composable
private fun ColumnScope.NetSplit(vm: SplitViewModel) {
    val mode by vm.netMode.collectAsStateWithLifecycle()
    val cidrs by vm.cidrs.collectAsStateWithLifecycle()
    val domains by vm.domains.collectAsStateWithLifecycle()
    var input by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    val excludeUnsupported = mode == PerAppMode.EXCLUDE && Build.VERSION.SDK_INT < 33
    val s = LocalStrings.current

    ModeSelector(mode) { vm.setNetMode(it) }
    Spacer(Modifier.size(8.dp))
    Hint(
        when (mode) {
            PerAppMode.OFF -> s.hintNetOff
            PerAppMode.INCLUDE -> s.hintNetInclude
            PerAppMode.EXCLUDE -> s.hintNetExclude
        },
    )
    if (excludeUnsupported) {
        Spacer(Modifier.size(4.dp))
        Text(s.excludeUnsupported, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
    }
    SectionLabel(s.rules)

    LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        if (cidrs.isEmpty() && domains.isEmpty()) {
            item { Hint(s.nothingYet) }
        }
        items(cidrs, key = { "c:$it" }) { c ->
            RuleRow(LeshiyIcons.Shield, c) { vm.removeCidr(c) }
        }
        items(domains, key = { "d:$it" }) { d ->
            RuleRow(LeshiyIcons.Globe, d) { vm.removeDomain(d) }
        }
    }

    if (domains.isNotEmpty()) {
        Hint(s.domainNote)
        Spacer(Modifier.size(6.dp))
    }
    Field(input, { input = it; error = false }, s.ipCidrDomain)
    if (error) Text(s.invalidRule, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
    Spacer(Modifier.size(8.dp))
    PrimaryButton(
        s.addRule,
        onClick = { if (vm.addEntry(input)) input = "" else error = true },
        enabled = input.isNotBlank(),
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.size(8.dp))
}

@Composable
private fun RuleRow(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String, onRemove: () -> Unit) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, tint = Wisp, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(12.dp))
        Text(text, modifier = Modifier.weight(1f), fontFamily = PlexMono, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onBackground, maxLines = 1, overflow = TextOverflow.Ellipsis)
        IconBtn(LeshiyIcons.Trash, "Remove", tint = MaterialTheme.colorScheme.error, onClick = onRemove)
    }
}

/* ---------- shared ---------- */

@Composable
private fun KindToggle(kind: SplitKind, onSelect: (SplitKind) -> Unit) {
    val s = LocalStrings.current
    Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surface, border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)) {
        Row(Modifier.padding(3.dp), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
            SegItem(s.byApp, kind == SplitKind.APP, Modifier.weight(1f)) { onSelect(SplitKind.APP) }
            SegItem(s.byNetwork, kind == SplitKind.NETWORK, Modifier.weight(1f)) { onSelect(SplitKind.NETWORK) }
        }
    }
}

@Composable
private fun ModeSelector(mode: PerAppMode, onSelect: (PerAppMode) -> Unit) {
    val s = LocalStrings.current
    val label = { m: PerAppMode ->
        when (m) {
            PerAppMode.OFF -> s.modeOff
            PerAppMode.INCLUDE -> s.modeInclude
            PerAppMode.EXCLUDE -> s.modeExclude
        }
    }
    Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surface, border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)) {
        Row(Modifier.padding(3.dp), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
            PerAppMode.entries.forEach { m ->
                SegItem(label(m), m == mode, Modifier.weight(1f)) { onSelect(m) }
            }
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.SegItem(text: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(9.dp),
        color = if (selected) Wisp else Color.Transparent,
        modifier = modifier,
    ) {
        Text(
            text,
            modifier = Modifier.padding(vertical = 8.dp),
            textAlign = TextAlign.Center,
            color = if (selected) Bg0 else Dim,
            style = MaterialTheme.typography.labelLarge,
        )
    }
}

@Composable
private fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.labelSmall, color = Dim)
}

@Composable
private fun CheckBox(checked: Boolean, enabled: Boolean, onToggle: () -> Unit) {
    Surface(
        onClick = onToggle,
        enabled = enabled,
        shape = RoundedCornerShape(7.dp),
        color = if (checked) Wisp else Color.Transparent,
        border = BorderStroke(1.5.dp, if (checked) Wisp else MaterialTheme.colorScheme.outline),
        modifier = Modifier.size(24.dp),
    ) {
        if (checked) {
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                Icon(LeshiyIcons.Check, null, tint = Bg0, modifier = Modifier.size(15.dp))
            }
        }
    }
}

@Composable
private fun AppIcon(pkg: String) {
    val context = LocalContext.current
    val bitmap by androidx.compose.runtime.produceState<ImageBitmap?>(initialValue = null, pkg) {
        value = withContext(Dispatchers.IO) {
            runCatching { context.packageManager.getApplicationIcon(pkg).toBitmap(72, 72).asImageBitmap() }.getOrNull()
        }
    }
    Box(modifier = Modifier.size(32.dp).clip(RoundedCornerShape(8.dp)), contentAlignment = Alignment.Center) {
        val bmp = bitmap
        if (bmp != null) Image(bmp, null, modifier = Modifier.size(32.dp))
        else Icon(LeshiyIcons.Server, null, tint = Dim, modifier = Modifier.size(18.dp))
    }
}
