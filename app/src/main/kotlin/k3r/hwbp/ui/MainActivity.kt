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
import k3r.hwbp.store.CredentialStore
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
    val scope = rememberCoroutineScope()
    var passkeys by remember { mutableStateOf(emptyList<PasskeyRecord>()) }
    var selfTest by remember { mutableStateOf<SelfTest>(SelfTest.Idle) }
    var pendingDelete by remember { mutableStateOf<PasskeyRecord?>(null) }
    val strongBox = remember { StrongBoxKeys.isAvailable(ctx) }
    val chainInfo = remember { Core.version().chainVerification }
    val debuggable = remember { ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 }

    fun reload() = scope.launch {
        passkeys = withContext(Dispatchers.IO) {
            store.pruneOrphans()
            store.sweepOrphanKeys()
            store.all().sortedByDescending { it.createdAt }
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
                        withContext(Dispatchers.IO) { store.delete(pk.credentialId) }
                        reload()
                    }
                }) { Text("Destroy", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text("Cancel") } },
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
