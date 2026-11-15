// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.provider

import android.content.Context
import androidx.credentials.provider.CallingAppInfo
import k3r.hwbp.core.B64
import k3r.hwbp.core.bytes
import k3r.hwbp.proto.Caller
import k3r.hwbp.proto.caller
import java.security.MessageDigest

/** Who is asking, as far as the OS can tell us. */
sealed interface ResolvedCaller {
    /** A privileged browser vouching for [origin] ("https://example.com"). */
    data class Browser(val origin: String) : ResolvedCaller {
        /** Browsers build clientDataJSON themselves and pass its hash. */
        fun toProto(clientDataHash: ByteArray?): Caller = caller {
            origin = this@Browser.origin
            clientDataHash?.let { this.clientDataHash = it.bytes() }
        }
    }

    /** A native app, identified by package name and its current signing certificate. */
    class App(val packageName: String, private val certSha256: ByteArray) : ResolvedCaller {
        /** Lowercase hex; the form stored in [k3r.hwbp.store.AppTrustStore]. */
        val certSha256Hex: String = certSha256.joinToString("") { "%02x".format(it) }

        /** The WebAuthn origin Android apps have: `android:apk-key-hash:<b64url sha256(cert)>`. */
        val origin: String = "android:apk-key-hash:" + B64.enc(certSha256)

        /**
         * [trustedRpId] must be an RP ID the user has bound this app to; Rust rejects
         * the request if it resolves to any other. Never carries a clientDataHash:
         * an app-supplied one would let the app choose the origin the RP sees.
         */
        fun toProto(trustedRpId: String): Caller = caller {
            origin = this@App.origin
            packageName = this@App.packageName
            this.trustedRpId = trustedRpId
        }
    }
}

/**
 * Works out who a request comes from.
 *
 * - Privileged browsers (allowlisted by package + signing cert in
 *   `assets/privileged_browsers.json`, sourced from
 *   https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json) may assert a
 *   web origin and supply their own clientDataHash.
 * - Every other caller is a native app. There is no Digital Asset Links check,
 *   so nothing links it to the RP's domain: it is only served for RP IDs the
 *   user has bound its (package, signing cert) to. See [AppBinding].
 */
object CallerResolver {
    @Volatile private var allowlist: String? = null

    private fun allowlist(context: Context): String =
        allowlist ?: context.assets.open("privileged_browsers.json").bufferedReader().use { it.readText() }
            .also { allowlist = it }

    /**
     * Fails closed with [SecurityException]: callers that assert an origin without
     * being allowlisted, an unreadable/malformed allowlist, and apps whose signing
     * certificate is ambiguous (multiple signers) or unavailable.
     */
    fun resolve(context: Context, info: CallingAppInfo): ResolvedCaller {
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
        if (webOrigin != null) return ResolvedCaller.Browser(webOrigin.trimEnd('/'))

        val signingInfo = info.signingInfo
        // With one signer this is the current certificate, not a rotated-out one.
        val signers = signingInfo.apkContentsSigners
        if (signingInfo.hasMultipleSigners() || signers == null || signers.size != 1) {
            throw SecurityException("${info.packageName} has no single signing certificate")
        }
        return ResolvedCaller.App(
            info.packageName,
            MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray()),
        )
    }
}
