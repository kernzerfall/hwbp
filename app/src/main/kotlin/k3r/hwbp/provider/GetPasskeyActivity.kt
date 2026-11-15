// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.provider

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import k3r.hwbp.core.B64
import k3r.hwbp.core.Core
import k3r.hwbp.keystore.StrongBoxKeys
import k3r.hwbp.store.CredentialStore
import k3r.hwbp.store.CredentialStoreException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Assertion ceremony for the credential the user picked in the system sheet.
 * Native apps must have been bound to the RP ID by the user, or are now
 * ([AppBinding]); a new binding is stored only once the sign-in has succeeded.
 */
class GetPasskeyActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return

        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = request?.credentialOptions?.filterIsInstance<GetPublicKeyCredentialOption>()?.firstOrNull()
        val credentialId = intent.getStringExtra(EXTRA_CREDENTIAL_ID)
        if (request == null || option == null || credentialId == null) {
            fail(GetCredentialUnknownException("not a passkey request"))
            return
        }
        val store = CredentialStore.get(this)
        val record = try {
            store.get(credentialId)
        } catch (e: CredentialStoreException) {
            Log.e(TAG, "assertion failed", e)
            fail(GetCredentialUnknownException(e.message))
            return
        }
        if (record == null) {
            fail(NoCredentialException("passkey no longer exists"))
            return
        }

        lifecycleScope.launch {
            try {
                var persistBinding = {}
                var appNote: String? = null
                val caller = when (val resolved = CallerResolver.resolve(this@GetPasskeyActivity, request.callingAppInfo)) {
                    is ResolvedCaller.Browser -> resolved.toProto(option.clientDataHash)
                    is ResolvedCaller.App -> {
                        val summary = Core.inspectAssertion(option.requestJson)
                        if (!summary.hasRpId()) throw SecurityException("rpId is required for app callers")
                        if (!record.rpId.equals(summary.rpId, ignoreCase = true)) {
                            throw SecurityException("credential is not registered for this RP")
                        }
                        persistBinding = AppBinding.require(
                            this@GetPasskeyActivity, resolved, summary.rpId,
                            registration = false, userId = record.userId, userName = record.userName,
                        )
                        appNote = "Requested by the app ${resolved.packageName}."
                        resolved.toProto(trustedRpId = summary.rpId)
                    }
                }
                val plan = Core.assertionBegin(option.requestJson, caller, B64.decBytes(record.credentialId), record.rpId)

                val nextCount = record.signCount + 1
                val toSign = Core.assertionAuthData(plan, nextCount.toInt())
                val authorised = UserVerification.authorize(
                    this@GetPasskeyActivity,
                    StrongBoxKeys.signatureFor(record.alias),
                    title = "Sign in to ${plan.rpId}",
                    subtitle = record.userName,
                    description = appNote,
                )
                val signature = withContext(Dispatchers.IO) {
                    authorised.update(toSign.toBeSigned.toByteArray())
                    authorised.sign()
                }
                val responseJson = Core.assertionFinish(
                    plan,
                    toSign.authenticatorData,
                    signature,
                    B64.decBytes(record.userId),
                    B64.decBytes(record.publicKeySpki),
                )
                store.updateSignCount(record.credentialId, nextCount)
                runCatching(persistBinding).onFailure { Log.e(TAG, "could not store the app binding", it) }

                val result = Intent()
                PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(responseJson)))
                setResult(RESULT_OK, result)
                finish()
            } catch (t: Throwable) {
                Log.w(TAG, "assertion failed", t)
                when (val f = t.toFailure()) {
                    Failure.Cancelled -> fail(GetCredentialCancellationException())
                    is Failure.Dom -> fail(GetPublicKeyCredentialDomException(f.error, f.message))
                }
            }
        }
    }

    private fun fail(e: GetCredentialException) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(result, e)
        setResult(RESULT_OK, result)
        finish()
    }

    companion object {
        const val EXTRA_CREDENTIAL_ID = "k3r.hwbp.CREDENTIAL_ID"
        private const val TAG = "HwbpGet"
    }
}
