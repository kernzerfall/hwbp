// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.provider

import android.content.Context
import androidx.credentials.provider.CallingAppInfo
import k3r.hwbp.core.bytes
import k3r.hwbp.proto.Caller
import k3r.hwbp.proto.caller

/**
 * Works out the WebAuthn origin of a request.
 *
 * - Privileged browsers (allowlisted by package + signing cert in
 *   `assets/privileged_browsers.json`, sourced from
 *   https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json) may assert a
 *   web origin and supply their own clientDataHash.
 * - Every other (native) app is rejected. Without a Digital Asset Links check
 *   it could claim any RP ID: phish assertions from RPs that accept
 *   `android:apk-key-hash:` origins, or destroy existing passkeys by registering
 *   with a guessed user.id (same-user replacement).
 *
 * TODO: an offline, user-managed allowlist of (package, signing cert, RP ID)
 *   for native apps.
 */
object CallerResolver {
    @Volatile private var allowlist: String? = null

    private fun allowlist(context: Context): String =
        allowlist ?: context.assets.open("privileged_browsers.json").bufferedReader().use { it.readText() }
            .also { allowlist = it }

    /**
     * Fails closed: native apps, callers that assert an origin without being
     * allowlisted, and an unreadable/malformed allowlist all throw [SecurityException].
     */
    fun resolve(context: Context, info: CallingAppInfo, clientDataHash: ByteArray?): Caller {
        val webOrigin = try {
            // null iff the caller asserted no origin; throws if it did but isn't
            // privileged (IllegalStateException) or the list is bad (IllegalArgumentException).
            info.getOrigin(allowlist(context))
        } catch (e: IllegalStateException) {
            throw SecurityException("${info.packageName} asserted a web origin but is not a privileged browser", e)
        } catch (e: IllegalArgumentException) {
            throw SecurityException("privileged browser allowlist is invalid", e)
        } catch (e: java.io.IOException) {
            throw SecurityException("privileged browser allowlist is unreadable", e)
        }
            ?: throw SecurityException("${info.packageName} is not a privileged browser; native app callers are not supported")
        return caller {
            origin = webOrigin.trimEnd('/')
            clientDataHash?.let { this.clientDataHash = it.bytes() }
        }
    }
}
