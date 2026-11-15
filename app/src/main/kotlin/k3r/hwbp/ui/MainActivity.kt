// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.ui

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.credentials.CredentialManager
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import k3r.hwbp.R
import k3r.hwbp.core.Core
import k3r.hwbp.keystore.StrongBoxKeys
import k3r.hwbp.proto.AttestationReport
import k3r.hwbp.store.AppTrust
import k3r.hwbp.store.AppTrustStore
import k3r.hwbp.store.certFingerprint
import k3r.hwbp.store.CredentialStore
import k3r.hwbp.store.CredentialStoreException
import k3r.hwbp.store.DamagedEntry
import k3r.hwbp.store.PasskeyRecord
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.text.DateFormat
import java.util.Base64
import java.util.Date

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { HwbpTheme { HwbpScreen() } }
    }
}

private sealed interface SelfTest {
    data object Idle : SelfTest
    data object Running : SelfTest
    data class Passed(val report: AttestationReport) : SelfTest
    data class Failed(val reason: String) : SelfTest
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HwbpScreen() {
    val ctx = LocalContext.current
    val store = remember { CredentialStore.get(ctx) }
    val trustStore = remember { AppTrustStore.get(ctx) }
    var trusted by remember { mutableStateOf(emptyList<AppTrust>()) }
    var pendingRevoke by remember { mutableStateOf<AppTrust?>(null) }
    val scope = rememberCoroutineScope()
    var passkeys by remember { mutableStateOf(emptyList<PasskeyRecord>()) }
    var selfTest by remember { mutableStateOf<SelfTest>(SelfTest.Idle) }
    var pendingDelete by remember { mutableStateOf<PasskeyRecord?>(null) }
    var storeError by remember { mutableStateOf(false) }
    var damaged by remember { mutableStateOf(emptyList<DamagedEntry>()) }
    var pendingDamaged by remember { mutableStateOf<DamagedEntry?>(null) }
    var confirmReset by remember { mutableStateOf(false) }
    val strongBox = remember { StrongBoxKeys.isAvailable(ctx) }
    val chainInfo = remember { Core.version().chainVerification }
    val debuggable = remember { ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 }

    fun reload() = scope.launch {
        trusted = withContext(Dispatchers.IO) { trustStore.all() }.sortedByDescending { it.confirmedAt }
        try {
            val c = withContext(Dispatchers.IO) {
                store.pruneOrphans()
                store.sweepOrphanKeys()
                store.contents()
            }
            passkeys = c.records.sortedByDescending { it.createdAt }
            damaged = c.damaged
            storeError = false
        } catch (e: CredentialStoreException) {
            Log.e("Hwbp", "passkey store unreadable", e)
            passkeys = emptyList()
            damaged = emptyList()
            storeError = true
        }
    }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { reload() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("HWBP") },
                actions = {
                    IconButton(onClick = { ctx.startActivity(Intent(ctx, LicensesActivity::class.java)) }) {
                        Icon(painterResource(R.drawable.ic_licenses), contentDescription = "Open-source licenses")
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            contentPadding = PaddingValues(16.dp, padding.calculateTopPadding() + 8.dp, 16.dp, 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Hardware", style = MaterialTheme.typography.titleMedium)
                        Text(
                            if (strongBox) "StrongBox Keystore reported by this device."
                            else "No StrongBox on this device. HWBP will refuse to create passkeys.",
                        )
                        if (chainInfo.enabled) {
                            val snapshot = chainInfo.revocationSnapshotUnix
                                .takeIf { chainInfo.hasRevocationSnapshotUnix() }
                                ?.let { DateFormat.getDateInstance().format(Date(it * 1000)) } ?: "unknown date"
                            Text(
                                "Attestation chains are verified against pinned Google roots and a " +
                                    "revocation list of ${chainInfo.revokedEntries} entries ($snapshot).",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        } else {
                            Text(
                                "This build does not verify attestation chains. Device claims are checked, " +
                                    "but not who signed them.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                        when (val s = selfTest) {
                            SelfTest.Idle, SelfTest.Running -> {}
                            is SelfTest.Passed -> Text(
                                "Self-test passed: key generated inside StrongBox, attested, " +
                                    "user-auth bound.\n${describe(s.report)}",
                                color = MaterialTheme.colorScheme.primary,
                            )
                            is SelfTest.Failed -> Text("Self-test failed: ${s.reason}", color = MaterialTheme.colorScheme.error)
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                enabled = strongBox && selfTest != SelfTest.Running,
                                onClick = {
                                    selfTest = SelfTest.Running
                                    scope.launch {
                                        selfTest = withContext(Dispatchers.IO) {
                                            runCatching {
                                                val challenge = ByteArray(32).also(SecureRandom()::nextBytes)
                                                val chain = StrongBoxKeys.selfTest(challenge)
                                                if (debuggable) logChain(chain)
                                                Core.verifyAttestation(chain, challenge)
                                            }.fold({ SelfTest.Passed(it) }, { SelfTest.Failed(it.message ?: it.toString()) })
                                        }
                                    }
                                },
                            ) { Text(if (selfTest == SelfTest.Running) "Testing…" else "Run self-test") }
                            OutlinedButton(onClick = {
                                runCatching { CredentialManager.create(ctx).createSettingsPendingIntent().send() }
                            }) { Text("Enable provider") }
                        }
                    }
                }
            }

            item {
                Text(
                    "Passkeys (${passkeys.size})",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
                Text(
                    "Each passkey's private key exists only inside this phone's secure element. " +
                        "It can't be backed up, synced or exported. Lose the phone, lose the passkey: " +
                        "register a second authenticator with every account.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            if (storeError) {
                item {
                    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                "The passkey list (passkeys.json) is corrupt. HWBP won't create, use, delete " +
                                    "or clean up passkeys until it's reset. The keys in StrongBox are untouched.",
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                            Button(onClick = { confirmReset = true }) { Text("Reset passkey list") }
                        }
                    }
                }
            }

            items(passkeys, key = { it.credentialId }) { pk ->
                Card(Modifier.fillMaxWidth(), colors = CardDefaults.outlinedCardColors()) {
                    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(pk.rpId, style = MaterialTheme.typography.titleSmall)
                            Text(pk.displayName.takeIf { it != pk.userName }?.let { "$it · ${pk.userName}" } ?: pk.userName)
                            Text(
                                "Created ${DateFormat.getDateInstance().format(Date(pk.createdAt))} · " +
                                    "used ${pk.signCount}×",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Text(describe(pk.attestation), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                        }
                        Spacer(Modifier.width(8.dp))
                        TextButton(onClick = { pendingDelete = pk }) { Text("Delete") }
                    }
                }
            }

            if (trusted.isNotEmpty()) {
                item {
                    Text(
                        "Trusted apps (${trusted.size})",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                    Text(
                        "Apps you allowed to use a site's passkeys. HWBP can't verify that an app belongs " +
                            "to a site; it only remembers your answer. Revoke one to be asked again.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                items(trusted, key = { "trust:${it.packageName}:${it.certSha256}:${it.rpId}" }) { t ->
                    Card(Modifier.fillMaxWidth(), colors = CardDefaults.outlinedCardColors()) {
                        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(t.rpId, style = MaterialTheme.typography.titleSmall)
                                Text(t.packageName)
                                Text(
                                    (if (t.registration) "Create passkeys and sign in" else "Sign in only") +
                                        " · since ${DateFormat.getDateInstance().format(Date(t.confirmedAt))}",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                Text(
                                    certFingerprint(t.certSha256),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                )
                            }
                            Spacer(Modifier.width(8.dp))
                            TextButton(onClick = { pendingRevoke = t }) { Text("Revoke") }
                        }
                    }
                }
            }

            if (damaged.isNotEmpty()) {
                item {
                    Text(
                        "Unusable entries (${damaged.size})",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                    Text(
                        "Their metadata is damaged or lost, so they can't sign in. Their keys are kept " +
                            "until you destroy them." +
                            if (damaged.any { it.credentialId == null }) {
                                " Cleanup of leftover keys is paused while an entry without a credential ID exists."
                            } else {
                                ""
                            },
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                itemsIndexed(damaged, key = { i, _ -> "damaged:$i" }) { _, d ->
                    Card(Modifier.fillMaxWidth(), colors = CardDefaults.outlinedCardColors()) {
                        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(
                                    if (d.recovered) "Key without metadata" else "Damaged entry",
                                    style = MaterialTheme.typography.titleSmall,
                                )
                                Text(
                                    d.credentialId?.let { "Credential ${it.take(12)}…" } ?: "Credential ID unreadable",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                )
                                d.createdAt?.let {
                                    Text("Created ${DateFormat.getDateInstance().format(Date(it))}", style = MaterialTheme.typography.bodySmall)
                                }
                            }
                            Spacer(Modifier.width(8.dp))
                            TextButton(onClick = { pendingDamaged = d }) {
                                Text(if (d.credentialId != null) "Destroy" else "Remove")
                            }
                        }
                    }
                }
            }
        }
    }

    pendingDelete?.let { pk ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("Destroy passkey?") },
            text = {
                Text(
                    "The key for ${pk.userName} on ${pk.rpId} will be erased from the secure element. " +
                        "There is no copy anywhere. Remove it from the account's security settings too.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingDelete = null
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { store.delete(pk.credentialId) }
                        } catch (_: CredentialStoreException) {
                            // reload() shows the error.
                        }
                        reload()
                    }
                }) { Text("Destroy", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text("Cancel") } },
        )
    }

    pendingRevoke?.let { t ->
        AlertDialog(
            onDismissRequest = { pendingRevoke = null },
            title = { Text("Revoke trust?") },
            text = {
                Text(
                    "${t.packageName} will no longer be able to " +
                        (if (t.registration) "create passkeys for or sign in to" else "sign in to") +
                        " ${t.rpId} without asking you again. No passkey is deleted.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingRevoke = null
                    scope.launch {
                        runCatching { withContext(Dispatchers.IO) { trustStore.revoke(t) } }
                            .onFailure { Log.e("Hwbp", "revoke failed", it) }
                        reload()
                    }
                }) { Text("Revoke", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { pendingRevoke = null }) { Text("Cancel") } },
        )
    }

    pendingDamaged?.let { d ->
        AlertDialog(
            onDismissRequest = { pendingDamaged = null },
            title = { Text(if (d.credentialId != null) "Destroy key?" else "Remove entry?") },
            text = {
                Text(
                    if (d.credentialId != null) {
                        "The entry and its key will be erased from the secure element. Remove the passkey " +
                            "from the account's security settings too, if you know which one it was."
                    } else {
                        "The entry will be removed. Its key can't be identified; once no such entries are " +
                            "left, leftover keys without an entry are destroyed after an hour."
                    },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingDamaged = null
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { store.deleteDamaged(d) }
                        } catch (_: CredentialStoreException) {
                            // reload() shows the error.
                        }
                        reload()
                    }
                }) { Text(if (d.credentialId != null) "Destroy" else "Remove", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { pendingDamaged = null }) { Text("Cancel") } },
        )
    }

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text("Reset passkey list?") },
            text = {
                Text(
                    "The corrupt file is moved aside, not deleted. Every key in StrongBox is then listed as " +
                        "\"Key without metadata\". Those passkeys can't be used again, because their site and " +
                        "user handle were only stored in the file: register new ones and remove the old ones " +
                        "from your accounts. No key is destroyed unless you do it yourself.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmReset = false
                    scope.launch {
                        runCatching { withContext(Dispatchers.IO) { store.reset() } }
                            .onSuccess { Log.i("Hwbp", "corrupt passkey store moved to $it") }
                            .onFailure { Log.e("Hwbp", "reset failed", it) }
                        reload()
                    }
                }) { Text("Reset", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text("Cancel") } },
        )
    }
}

/** Debug builds only: dump the self-test chain (public certs) for `adb logcat -s HwbpSelfTest`. */
private fun logChain(chain: List<ByteArray>) {
    chain.forEachIndexed { i, der -> Log.i("HwbpSelfTest", "cert[$i] ${Base64.getEncoder().encodeToString(der)}") }
}

private fun describe(report: AttestationReport): String {
    val level = when (report.keyMintSecurityLevel) {
        2 -> "StrongBox"
        1 -> "TEE"
        0 -> "Software"
        else -> "?"
    }
    val boot = if (!report.hasVerifiedBootState()) "boot state ?" else when (report.verifiedBootState) {
        0 -> "verified boot"
        1 -> "self-signed boot"
        2 -> "unverified boot"
        3 -> "boot failed"
        else -> "boot state ?"
    }
    val locked = when {
        !report.hasDeviceLocked() -> "bootloader ?"
        report.deviceLocked -> "bootloader locked"
        else -> "bootloader UNLOCKED"
    }
    val chain = if (report.hasChain()) "root ${report.chain.root}" else "chain unverified"
    return "KeyMint v${report.keyMintVersion} · $level · $boot · $locked · $chain"
}
