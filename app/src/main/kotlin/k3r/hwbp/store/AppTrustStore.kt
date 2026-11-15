// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.store

import android.content.Context
import android.util.AtomicFile
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * A user-confirmed binding of a native app to an RP ID (trust on first use).
 * The app is the pair (package name, SHA-256 of its signing certificate): an
 * app re-signed with another key is a different app.
 */
data class AppTrust(
    val packageName: String,
    /** Lowercase hex. */
    val certSha256: String,
    /** Lowercase. */
    val rpId: String,
    /** false: sign-in only. true: may also create (and thereby replace) passkeys. */
    val registration: Boolean,
    val confirmedAt: Long,
) {
    internal fun sameBinding(o: AppTrust) =
        packageName == o.packageName && certSha256 == o.certSha256 && rpId == o.rpId

    internal fun toJson(): JSONObject = JSONObject()
        .put("packageName", packageName)
        .put("certSha256", certSha256)
        .put("rpId", rpId)
        .put("registration", registration)
        .put("confirmedAt", confirmedAt)

    internal companion object {
        fun fromJson(o: JSONObject) = AppTrust(
            packageName = o.getString("packageName"),
            certSha256 = o.getString("certSha256"),
            rpId = o.getString("rpId"),
            registration = o.getBoolean("registration"),
            confirmedAt = o.getLong("confirmedAt"),
        )
    }
}

/**
 * app_trust.json in [Context.getNoBackupFilesDir]. Sign-in and registration
 * trust are separate; registration trust includes sign-in.
 *
 * Unlike passkeys.json, anything unreadable here is dropped: the worst case is
 * that the user is asked to confirm a binding again.
 */
class AppTrustStore private constructor(dir: File) {
    private val file = AtomicFile(File(dir, FILE_NAME))
    private val lock = Any()

    fun all(): List<AppTrust> = synchronized(lock) { read() }

    fun allows(packageName: String, certSha256: String, rpId: String, registration: Boolean): Boolean =
        all().any {
            it.packageName == packageName && it.certSha256 == certSha256 && it.rpId == rpId.lowercase() &&
                (it.registration || !registration)
        }

    /** Records the binding. Never downgrades registration trust to sign-in only. */
    fun grant(packageName: String, certSha256: String, rpId: String, registration: Boolean) = synchronized(lock) {
        val new = AppTrust(packageName, certSha256, rpId.lowercase(), registration, System.currentTimeMillis())
        val list = read()
        val old = list.firstOrNull { it.sameBinding(new) }
        if (old != null && (old.registration || !registration)) return@synchronized
        write(list.filterNot { it.sameBinding(new) } + new)
    }

    fun revoke(trust: AppTrust) = synchronized(lock) {
        write(read().filterNot { it.sameBinding(trust) })
    }

    private fun read(): List<AppTrust> {
        if (!file.baseFile.exists()) return emptyList()
        return try {
            val arr = JSONArray(String(file.readFully(), Charsets.UTF_8))
            (0 until arr.length()).mapNotNull { i ->
                runCatching { AppTrust.fromJson(arr.getJSONObject(i)) }.getOrNull()
            }
        } catch (e: Exception) {
            Log.e("Hwbp", "$FILE_NAME is unreadable; no app is trusted", e)
            emptyList()
        }
    }

    private fun write(list: List<AppTrust>) {
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        val out = file.startWrite()
        try {
            out.write(arr.toString().toByteArray())
            file.finishWrite(out)
        } catch (t: Throwable) {
            file.failWrite(out)
            throw t
        }
    }

    companion object {
        private const val FILE_NAME = "app_trust.json"

        @Volatile private var instance: AppTrustStore? = null

        fun get(context: Context): AppTrustStore =
            instance ?: synchronized(this) {
                instance ?: AppTrustStore(context.applicationContext.noBackupFilesDir).also { instance = it }
            }
    }
}

/** `AB:CD:…`, the way `apksigner`/`keytool` print a SHA-256 certificate fingerprint. */
fun certFingerprint(certSha256Hex: String): String = certSha256Hex.uppercase().chunked(2).joinToString(":")
