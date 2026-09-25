package dev.leshiy.ui.components

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.PersistableBundle
import android.view.Window
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalContext
import java.util.WeakHashMap

/** Screens currently asking for FLAG_SECURE, per window. Main-thread only. */
private val secureHolds = WeakHashMap<Window, Int>()

/**
 * Keep this screen out of screenshots, screen recordings and the Recents thumbnail while it is
 * shown — for screens that display links, QR codes, passphrases or SSH credentials.
 *
 * Reference-counted: during a navigation transition the incoming screen is composed before the
 * outgoing one is disposed, so a plain add/clear pair would drop the flag the new screen just set.
 */
@Composable
fun SecureWindow() {
    val window = LocalContext.current.findActivity()?.window ?: return
    DisposableEffect(window) {
        secureHolds[window] = (secureHolds[window] ?: 0) + 1
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            val left = (secureHolds[window] ?: 1) - 1
            if (left > 0) {
                secureHolds[window] = left
            } else {
                secureHolds.remove(window)
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
        }
    }
}

/**
 * Copy a secret (a `leshiy://` link) marked sensitive, so Android 13+ hides it in the clipboard
 * preview and keyboards with clipboard history/sync are told not to keep it.
 */
fun copySensitive(context: Context, text: String) {
    val clip = ClipData.newPlainText("leshiy", text)
    val key = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        ClipDescription.EXTRA_IS_SENSITIVE
    } else {
        "android.content.extra.IS_SENSITIVE"
    }
    clip.description.extras = PersistableBundle().apply { putBoolean(key, true) }
    context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(clip)
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
