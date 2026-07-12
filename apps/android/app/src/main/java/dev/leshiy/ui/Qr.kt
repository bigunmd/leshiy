package dev.leshiy.ui

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Encode [text] as a QR [ImageBitmap] — dark modules on a light background, the
 * high-contrast pairing scanners read most reliably. Encoding a leshiy:// URI is a
 * few milliseconds; call it inside `remember(text)` so it runs once per URI.
 */
fun qrImageBitmap(
    text: String,
    sizePx: Int = 512,
    dark: Int = Color.BLACK,
    light: Int = Color.WHITE,
): ImageBitmap {
    val hints = mapOf(
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
        EncodeHintType.MARGIN to 1,
    )
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
    val w = matrix.width
    val h = matrix.height
    val pixels = IntArray(w * h) { i -> if (matrix.get(i % w, i / w)) dark else light }
    return Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).apply {
        setPixels(pixels, 0, w, 0, 0, w, h)
    }.asImageBitmap()
}
