// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.provider

import android.app.Activity
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.Signature
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class UserVerificationException(val errorCode: Int, message: String) : Exception(message) {
    val cancelled: Boolean
        get() = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
            errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
}

/**
 * Authorises one signature with the StrongBox key. The authorisation token is
 * minted by the secure lock-screen / biometric HAL and checked by StrongBox
 * itself, so a compromised app process can't skip this step.
 */
object UserVerification {
    suspend fun authorize(
        activity: Activity,
        signature: Signature,
        title: String,
        subtitle: String?,
        description: String? = null,
    ): Signature =
        suspendCancellableCoroutine { cont ->
            val cancel = CancellationSignal()
            cont.invokeOnCancellation { cancel.cancel() }

            val prompt = BiometricPrompt.Builder(activity)
                .setTitle(title)
                .apply { subtitle?.let { setSubtitle(it) } }
                .apply { description?.let { setDescription(it) } }
                .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
                .setConfirmationRequired(true)
                .build()

            prompt.authenticate(
                BiometricPrompt.CryptoObject(signature),
                cancel,
                activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val sig = result.cryptoObject?.signature
                        if (sig == null) {
                            cont.resumeWithException(UserVerificationException(-1, "no CryptoObject returned"))
                        } else {
                            cont.resume(sig)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (cont.isActive) cont.resumeWithException(UserVerificationException(errorCode, errString.toString()))
                    }
                },
            )
        }
}
