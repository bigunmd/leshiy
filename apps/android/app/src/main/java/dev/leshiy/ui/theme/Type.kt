package dev.leshiy.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import dev.leshiy.R

// Same faces as the desktop GUI: Bricolage Grotesque for UI, IBM Plex Mono for keys/counters.
val Bricolage = FontFamily(Font(R.font.bricolage_grotesque))
val PlexMono = FontFamily(Font(R.font.ibm_plex_mono))

val LeshiyTypography: Typography = Typography().let { base ->
    base.copy(
        displaySmall = base.displaySmall.copy(fontFamily = Bricolage),
        titleLarge = base.titleLarge.copy(fontFamily = Bricolage),
        bodyLarge = base.bodyLarge.copy(fontFamily = Bricolage),
        bodyMedium = base.bodyMedium.copy(fontFamily = Bricolage),
        labelLarge = base.labelLarge.copy(fontFamily = Bricolage),
        labelSmall = base.labelSmall.copy(fontFamily = PlexMono),
    )
}
