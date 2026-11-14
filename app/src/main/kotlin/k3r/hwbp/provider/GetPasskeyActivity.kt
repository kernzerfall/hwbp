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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Assertion ceremony for the credential the user picked in the system sheet. */
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
        val record = store.get(credentialId)
        if (record == null) {
            fail(NoCredentialException("passkey no longer exists"))
            return
        }

        lifecycleScope.launch {
            try {
                val caller = CallerResolver.resolve(this@GetPasskeyActivity, request.callingAppInfo, option.clientDataHash)
                val plan = Core.assertionBegin(option.requestJson, caller, B64.decBytes(record.credentialId), record.rpId)

                val nextCount = record.signCount + 1
                val toSign = Core.assertionAuthData(plan, nextCount.toInt())
                val authorised = UserVerification.authorize(
                    this@GetPasskeyActivity,
                    StrongBoxKeys.signatureFor(record.alias),
                    title = "Sign in to ${plan.rpId}",
                    subtitle = record.userName,
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
