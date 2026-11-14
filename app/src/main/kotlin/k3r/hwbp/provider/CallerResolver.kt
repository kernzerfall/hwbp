// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.provider

import android.content.Context
import androidx.credentials.provider.CallingAppInfo
import k3r.hwbp.core.B64
import k3r.hwbp.core.bytes
import k3r.hwbp.proto.Caller
import k3r.hwbp.proto.caller
import java.security.MessageDigest

/**
 * Works out the WebAuthn origin of a request.
 *
 * - Privileged browsers (allowlisted by package + signing cert in
 *   `assets/privileged_browsers.json`, sourced from
 *   https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json) may assert a
 *   web origin and supply their own clientDataHash.
 * - Every other app gets `android:apk-key-hash:<sha256(signing cert)>` and its
 *   clientDataHash, if any, is ignored.
 *
 * TODO(DAL): for native apps, verify the RP ID against
 *   https://<rpId>/.well-known/assetlinks.json before creating/using a passkey.
 *   That needs network access, which HWBP deliberately does not have yet. Until
 *   then, RPs must check the apk-key-hash origin server-side (as WebAuthn
 *   requires anyway).
 */
object CallerResolver {
    @Volatile private var allowlist: String? = null

    private fun allowlist(context: Context): String =
        allowlist ?: context.assets.open("privileged_browsers.json").bufferedReader().use { it.readText() }
            .also { allowlist = it }

    fun resolve(context: Context, info: CallingAppInfo, clientDataHash: ByteArray?): Caller {
        val webOrigin = runCatching { info.getOrigin(allowlist(context)) }.getOrNull()
        if (webOrigin != null) {
            return caller {
                origin = webOrigin.trimEnd('/')
                clientDataHash?.let { this.clientDataHash = it.bytes() }
            }
        }
        return caller {
            origin = apkKeyHashOrigin(info)
            packageName = info.packageName
        }
    }

    private fun apkKeyHashOrigin(info: CallingAppInfo): String {
        val signing = info.signingInfo
        val certs = if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
        val cert = certs?.firstOrNull() ?: throw SecurityException("calling app has no signing certificate")
        val hash = MessageDigest.getInstance("SHA-256").digest(cert.toByteArray())
        return "android:apk-key-hash:" + B64.enc(hash)
    }
}
