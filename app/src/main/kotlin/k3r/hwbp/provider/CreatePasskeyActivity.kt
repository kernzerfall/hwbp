// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.provider

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import k3r.hwbp.core.B64
import k3r.hwbp.core.Core
import k3r.hwbp.keystore.StrongBoxKeys
import k3r.hwbp.store.CredentialStore
import k3r.hwbp.store.PasskeyRecord
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Registration ceremony:
 *  1. Rust: parse + validate the request, pick a credential ID, compute clientDataHash.
 *  2. StrongBox: generate a key whose attestation challenge *is* clientDataHash.
 *  3. Rust: enforce the StrongBox attestation policy, build authenticatorData.
 *  4. BiometricPrompt: authorise one signature over authData || clientDataHash.
 *  5. Rust: verify that signature against the attested key, build the response.
 * Any failure after step 2 destroys the key.
 */
class CreatePasskeyActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return // ceremony already running / finished

        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val call = request?.callingRequest as? CreatePublicKeyCredentialRequest
        if (request == null || call == null) {
            fail(CreateCredentialUnknownException("not a passkey creation request"))
            return
        }

        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            Log.d(TAG, "requestJson from ${request.callingAppInfo.packageName}: ${call.requestJson}")
        }

        lifecycleScope.launch {
            try {
                val caller = CallerResolver.resolve(this@CreatePasskeyActivity, request.callingAppInfo, call.clientDataHash)
                val store = CredentialStore.get(this@CreatePasskeyActivity)
                // Rust only matches these against excludeCredentials; IDs are random
                // 256-bit values so passing every RP's IDs can't cause false matches.
                val plan = Core.registrationBegin(call.requestJson, caller, store.all().map { B64.decBytes(it.credentialId) })
                val credentialId = B64.enc(plan.credentialId)
                val alias = StrongBoxKeys.alias(credentialId)

                val chain = withContext(Dispatchers.IO) {
                    StrongBoxKeys.generate(alias, plan.clientData.hash.toByteArray())
                }
                try {
                    val toSign = Core.registrationAuthData(plan, chain)
                    val authorised = UserVerification.authorize(
                        this@CreatePasskeyActivity,
                        StrongBoxKeys.signatureFor(alias),
                        title = "Create passkey for ${plan.rpId}",
                        subtitle = plan.userName,
                    )
                    val signature = withContext(Dispatchers.IO) {
                        authorised.update(toSign.toBeSigned.toByteArray())
                        authorised.sign()
                    }
                    val result = Core.registrationFinish(plan, toSign.authenticatorData, signature, chain)

                    store.addReplacingSameUser(
                        PasskeyRecord(
                            credentialId = credentialId,
                            rpId = plan.rpId,
                            userId = B64.enc(plan.userId),
                            userName = plan.userName,
                            displayName = plan.userDisplayName,
                            createdAt = System.currentTimeMillis(),
                            signCount = 0,
                            publicKeySpki = B64.enc(result.publicKeySpki),
                            attestation = toSign.attestation,
                        ),
                    )
                    succeed(result.responseJson)
                } catch (t: Throwable) {
                    StrongBoxKeys.delete(alias)
                    throw t
                }
            } catch (t: Throwable) {
                Log.w(TAG, "registration failed", t)
                when (val f = t.toFailure()) {
                    Failure.Cancelled -> fail(CreateCredentialCancellationException())
                    is Failure.Dom -> fail(CreatePublicKeyCredentialDomException(f.error, f.message))
                }
            }
        }
    }

    private fun succeed(responseJson: String) {
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) responseJson.chunked(3000).forEach { Log.d(TAG, "responseJson: $it") }
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(responseJson))
        setResult(RESULT_OK, result)
        finish()
    }

    private fun fail(e: androidx.credentials.exceptions.CreateCredentialException) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialException(result, e)
        setResult(RESULT_OK, result)
        finish()
    }

    private companion object {
        const val TAG = "HwbpCreate"
    }
}
