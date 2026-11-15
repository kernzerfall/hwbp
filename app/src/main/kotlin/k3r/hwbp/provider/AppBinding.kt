// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.provider

import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import k3r.hwbp.store.AppTrustStore
import k3r.hwbp.store.PasskeyRecord
import k3r.hwbp.store.certFingerprint
import k3r.hwbp.ui.HwbpTheme
import kotlinx.coroutines.CompletableDeferred
import java.text.DateFormat
import java.util.Date

/** The user refused to bind an app to an RP ID. Reported as a cancellation. */
class BindingDeclinedException : Exception("the user did not allow this app to use the RP ID")

/**
 * Trust on first use for native apps. HWBP does no Digital Asset Links check,
 * so it can't tell whether an app belongs to the RP ID it names. Instead, the
 * first time a (package, signing cert) uses an RP ID the user is shown both and
 * has to confirm the binding. This is no cryptographic link to the domain; it
 * only stops an app from using an RP ID silently.
 *
 * Sign-in and registration are confirmed separately. Registration trust
 * includes sign-in, not the other way round: registering can replace
 * (destroy) an existing passkey.
 */
internal object AppBinding {
    /**
     * Returns immediately if [app] is already bound to [rpId] for this kind of
     * ceremony; otherwise asks the user.
     *
     * @param userId base64url `user.id` the ceremony is for.
     * @param replaces registration only: passkeys the new one would replace.
     * @return call it once the ceremony has succeeded to persist a newly confirmed
     *   binding. A confirmation that isn't followed by user verification and a
     *   valid signature leaves no trust behind.
     * @throws BindingDeclinedException if the user declines.
     */
    suspend fun require(
        activity: ComponentActivity,
        app: ResolvedCaller.App,
        rpId: String,
        registration: Boolean,
        userId: String,
        userName: String,
        replaces: List<PasskeyRecord> = emptyList(),
    ): () -> Unit {
        val trust = AppTrustStore.get(activity)
        if (trust.allows(app.packageName, app.certSha256Hex, rpId, registration)) return {}

        val decision = CompletableDeferred<Boolean>()
        // Nothing may draw over (or tap through) this decision.
        activity.window.setHideOverlayWindows(true)
        activity.window.decorView.filterTouchesWhenObscured = true
        activity.setContent {
            HwbpTheme {
                BindingScreen(app, rpId, registration, userId, userName, replaces) { decision.complete(it) }
            }
        }
        val allowed = try {
            decision.await()
        } finally {
            activity.setContent {}
            activity.window.setHideOverlayWindows(false)
        }
        if (!allowed) throw BindingDeclinedException()
        return { trust.grant(app.packageName, app.certSha256Hex, rpId, registration) }
    }
}

@Composable
private fun BindingScreen(
    app: ResolvedCaller.App,
    rpId: String,
    registration: Boolean,
    userId: String,
    userName: String,
    replaces: List<PasskeyRecord>,
    onDecision: (Boolean) -> Unit,
) {
    BackHandler { onDecision(false) }
    Box(
        Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.6f)).safeDrawingPadding().padding(24.dp),
        contentAlignment = Alignment.Center,
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(
                Modifier.verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    if (registration) "Let this app create passkeys for $rpId?" else "Let this app sign in to $rpId?",
                    style = MaterialTheme.typography.headlineSmall,
                )
                Text(
                    "HWBP can't verify that this app belongs to $rpId. Allow it only if you trust the app " +
                        "and recognise it below. Once this " + (if (registration) "passkey is created" else "sign-in completes") +
                        ", you won't be asked again for this app and site.",
                )
                Field("Site (RP ID)", rpId)
                Field("App package", app.packageName)
                Field("App signing certificate (SHA-256)", certFingerprint(app.certSha256Hex))
                Field("Account", userName)
                Field("User ID (user.id, base64url)", userId)
                if (registration) {
                    if (replaces.isEmpty()) {
                        Field("Replaces an existing passkey", "No")
                    } else {
                        Field(
                            "Replaces an existing passkey",
                            "YES. Destroyed for good if you continue:\n" + replaces.joinToString("\n") {
                                "${it.userName}, created ${DateFormat.getDateInstance().format(Date(it.createdAt))}, " +
                                    "used ${it.signCount}×"
                            },
                            warn = true,
                        )
                    }
                }
                Text(
                    if (registration) {
                        "This also lets the app sign in to $rpId with passkeys stored here."
                    } else {
                        "This does not let the app create or replace passkeys."
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = { onDecision(false) }) { Text("Cancel") }
                    Button(onClick = { onDecision(true) }) { Text("Allow") }
                }
            }
        }
    }
}

@Composable
private fun Field(label: String, value: String, warn: Boolean = false) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Text(
            value,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium,
            color = if (warn) MaterialTheme.colorScheme.error else Color.Unspecified,
        )
    }
}
