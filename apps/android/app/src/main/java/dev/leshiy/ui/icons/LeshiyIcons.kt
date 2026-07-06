package dev.leshiy.ui.icons

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.dp

// Deep Bog icon set — ported from apps/gui/src/components/icons.tsx. All single-color so
// `Icon(tint = ...)` recolors them. Paths are the same geometry as the desktop GUI.

private fun stroked(d: String, sw: Float = 2f, vp: Float = 24f): ImageVector =
    ImageVector.Builder("leshiy", 24.dp, 24.dp, vp, vp).apply {
        addPath(
            pathData = PathParser().parsePathString(d).toNodes(),
            stroke = SolidColor(Color.White),
            strokeLineWidth = sw,
            strokeLineCap = StrokeCap.Round,
            strokeLineJoin = StrokeJoin.Round,
        )
    }.build()

private fun filled(d: String, vp: Float = 24f): ImageVector =
    ImageVector.Builder("leshiy", 24.dp, 24.dp, vp, vp).apply {
        addPath(pathData = PathParser().parsePathString(d).toNodes(), fill = SolidColor(Color.White))
    }.build()

private fun mixed(strokeD: String, fillD: String, sw: Float = 1.6f): ImageVector =
    ImageVector.Builder("leshiy", 24.dp, 24.dp, 24f, 24f).apply {
        addPath(
            pathData = PathParser().parsePathString(strokeD).toNodes(),
            stroke = SolidColor(Color.White),
            strokeLineWidth = sw,
            strokeLineCap = StrokeCap.Round,
            strokeLineJoin = StrokeJoin.Round,
        )
        addPath(pathData = PathParser().parsePathString(fillD).toNodes(), fill = SolidColor(Color.White))
    }.build()

// Rounded square/rect as an SVG subpath.
private fun rr(x: Float, y: Float, w: Float, h: Float, r: Float): String =
    "M${x + r} ${y} h${w - 2 * r} a$r $r 0 0 1 $r $r v${h - 2 * r} a$r $r 0 0 1 -$r $r " +
        "h-${w - 2 * r} a$r $r 0 0 1 -$r -$r v-${h - 2 * r} a$r $r 0 0 1 $r -$r z "

object LeshiyIcons {
    val Power = stroked("M12 3.5 L12 12.5 M7.3 6.6 a7 7 0 1 0 9.4 0", sw = 2f)

    val Gear = stroked(
        "M12 8.9 a3.1 3.1 0 1 0 0.001 0 z " +
            "M19 12c0-.4 0-.8-.1-1.2l2-1.5-2-3.4-2.3 1a7 7 0 0 0-2-1.2L14.2 3H9.8l-.4 2.5" +
            "a7 7 0 0 0-2 1.2l-2.3-1-2 3.4 2 1.5c-.1.4-.1.8-.1 1.2s0 .8.1 1.2l-2 1.5 2 3.4 2.3-1" +
            "a7 7 0 0 0 2 1.2l.4 2.5h4.4l.4-2.5a7 7 0 0 0 2-1.2l2.3 1 2-3.4-2-1.5c.1-.4.1-.8.1-1.2Z",
        sw = 1.7f,
    )

    val Wisp = filled("M12 2.5c4.2 4.8 3.4 9.2 0 12.2C8.6 11.7 7.8 7.3 12 2.5Z")

    val ChevronDown = stroked("m6 9 6 6 6-6", sw = 2.2f)
    val ChevronRight = stroked("m9 6 6 6 -6 6", sw = 2.2f)
    val Back = stroked("M19 12 H5 M11 6 l-6 6 6 6", sw = 2f)

    val ArrowDown = filled("M6 9.5 1.2 4h9.6z", vp = 12f)
    val ArrowUp = filled("M6 2.5 10.8 8H1.2z", vp = 12f)
    val Bolt = filled("M13 2 4 14h6l-1 8 9-12h-6z")

    val Qr = mixed(
        strokeD = rr(3.5f, 3.5f, 6f, 6f, 1.2f) + rr(14.5f, 3.5f, 6f, 6f, 1.2f) + rr(3.5f, 14.5f, 6f, 6f, 1.2f),
        fillD = "M5.5 5.5 h2 v2 h-2z M16.5 5.5 h2 v2 h-2z M5.5 16.5 h2 v2 h-2z " +
            "M14 14 h2.4 v2.4 h-2.4z M18 14 h2.4 v2.4 h-2.4z M14 18 h2.4 v2.4 h-2.4z M18 18 h2.4 v2.4 h-2.4z",
    )

    val Check = stroked("M5 12 l4 4 L19 7", sw = 2.4f)
    val Plus = stroked("M12 5 V19 M5 12 H19", sw = 2f)
    val Trash = stroked(
        "M4 7 H20 M9 7 V5 a1 1 0 0 1 1 -1 h4 a1 1 0 0 1 1 1 V7 " +
            "M6 7 l1 13 a1 1 0 0 0 1 1 h8 a1 1 0 0 0 1 -1 l1 -13",
        sw = 1.7f,
    )

    // Settings-hub category glyphs.
    val Server = mixed(
        strokeD = rr(3f, 4f, 18f, 6f, 1.6f) + rr(3f, 14f, 18f, 6f, 1.6f),
        fillD = "M6.5 6.4 h2 v1.2 h-2z M6.5 16.4 h2 v1.2 h-2z",
        sw = 1.7f,
    )
    val Shield = stroked("M12 3 l7 3 v5 c0 4.5 -3 7.5 -7 9 c-4 -1.5 -7 -4.5 -7 -9 V6 z", sw = 1.7f)
    val Rocket = stroked(
        "M12 3 c3 2 4.5 5.5 4.5 9 l-2 2 h-5 l-2 -2 c0 -3.5 1.5 -7 4.5 -9 z " +
            "M9.5 16 l-2 3 M14.5 16 l2 3 M12 8.5 a1.4 1.4 0 1 0 0.001 0 z",
        sw = 1.6f,
    )
}
