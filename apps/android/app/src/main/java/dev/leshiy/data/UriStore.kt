package dev.leshiy.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore("leshiy")
private val LAST_URI = stringPreferencesKey("last_uri")

/** Persists the last-used `leshiy://` URI so a reopened app restores it. */
class UriStore(private val context: Context) {
    val lastUri: Flow<String> = context.dataStore.data.map { it[LAST_URI] ?: "" }

    suspend fun save(uri: String) {
        context.dataStore.edit { it[LAST_URI] = uri }
    }
}
