package dev.leshiy.data

import android.content.Context
import uniffi.leshiy_mobile.ProfileManager
import java.io.File

/** Process-wide singleton `ProfileManager` over `filesDir/profiles.json`. */
object Profiles {
    @Volatile
    private var mgr: ProfileManager? = null

    fun manager(context: Context): ProfileManager =
        mgr ?: synchronized(this) {
            mgr ?: ProfileManager(
                File(context.applicationContext.filesDir, "profiles.json").absolutePath,
            ).also { mgr = it }
        }
}
