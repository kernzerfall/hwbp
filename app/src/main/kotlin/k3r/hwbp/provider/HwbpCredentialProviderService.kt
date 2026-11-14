// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.provider

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import k3r.hwbp.R
import k3r.hwbp.core.B64
import k3r.hwbp.core.Core
import k3r.hwbp.keystore.StrongBoxKeys
import k3r.hwbp.store.CredentialStore

/**
 * Credential Manager entry point. The begin* calls must be fast and must not
 * show UI: they only advertise what we can do. The actual ceremony happens in
 * [CreatePasskeyActivity] / [GetPasskeyActivity] once the user picks an entry.
 */
class HwbpCredentialProviderService : CredentialProviderService() {

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            callback.onError(CreateCredentialUnknownException("HWBP only handles passkeys"))
            return
        }
        if (!StrongBoxKeys.isAvailable(this)) {
            // Refuse rather than silently degrading to the TEE.
            callback.onResult(BeginCreateCredentialResponse())
            return
        }
        val pi = PendingIntent.getActivity(
            this,
            REQUEST_CREATE,
            Intent(this, CreatePasskeyActivity::class.java).setPackage(packageName),
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val entry = CreateEntry.Builder(getString(R.string.create_entry_title), pi)
            .setDescription(getString(R.string.create_entry_description))
            .build()
        callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val store = CredentialStore.get(this)
        val entries = mutableListOf<CredentialEntry>()

        for (option in request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>()) {
            val summary = runCatching { Core.inspectAssertion(option.requestJson) }
                .onFailure { Log.w(TAG, "unparseable get request", it) }
                .getOrNull() ?: continue

            val allowed = summary.allowCredentialsList.mapTo(HashSet()) { B64.enc(it) }
            // No rpId in the request => it defaults to the caller's web origin host.
            val rpId = summary.rpId.takeIf { summary.hasRpId() } ?: request.callingAppInfo
                ?.let { runCatching { CallerResolver.resolve(this, it, null).origin }.getOrNull() }
                ?.removePrefix("https://")?.substringBefore('/')?.substringBefore(':')
                ?: continue

            for (rec in store.forRp(rpId)) {
                if (allowed.isNotEmpty() && rec.credentialId !in allowed) continue
                val intent = Intent(this, GetPasskeyActivity::class.java)
                    .setPackage(packageName)
                    .putExtra(GetPasskeyActivity.EXTRA_CREDENTIAL_ID, rec.credentialId)
                val pi = PendingIntent.getActivity(
                    this,
                    rec.credentialId.hashCode(),
                    intent,
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
                entries += PublicKeyCredentialEntry.Builder(this, rec.userName, pi, option)
                    .setDisplayName(rec.displayName)
                    .build()
            }
        }
        callback.onResult(BeginGetCredentialResponse.Builder().setCredentialEntries(entries).build())
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // We keep no session state.
        callback.onResult(null)
    }

    private companion object {
        const val TAG = "HwbpProvider"
        const val REQUEST_CREATE = 1
    }
}
