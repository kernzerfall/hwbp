// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.store

import android.content.Context
import android.util.AtomicFile
import k3r.hwbp.core.B64
import k3r.hwbp.keystore.StrongBoxKeys
import k3r.hwbp.proto.AttestationReport
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Non-secret passkey metadata. The private key itself never leaves StrongBox;
 * this is just what we need to list credentials and build responses.
 */
data class PasskeyRecord(
    val credentialId: String,
    val rpId: String,
    /** base64url user handle, returned as `userHandle` in assertions. */
    val userId: String,
    val userName: String,
    val displayName: String,
    val createdAt: Long,
    val signCount: Long,
    val publicKeySpki: String,
    /** Attestation report from the Rust policy at creation time. */
    val attestation: AttestationReport,
) {
    val alias: String get() = StrongBoxKeys.alias(credentialId)

    fun toJson(): JSONObject = JSONObject()
        .put("credentialId", credentialId)
        .put("rpId", rpId)
        .put("userId", userId)
        .put("userName", userName)
        .put("displayName", displayName)
        .put("createdAt", createdAt)
        .put("signCount", signCount)
        .put("publicKeySpki", publicKeySpki)
        .put("attestation", B64.enc(attestation.toByteArray()))

    companion object {
        fun fromJson(o: JSONObject) = PasskeyRecord(
            credentialId = o.getString("credentialId"),
            rpId = o.getString("rpId"),
            userId = o.getString("userId"),
            userName = o.getString("userName"),
            displayName = o.getString("displayName"),
            createdAt = o.getLong("createdAt"),
            signCount = o.getLong("signCount"),
            publicKeySpki = o.getString("publicKeySpki"),
            attestation = o.optString("attestation").takeIf { it.isNotEmpty() }
                ?.let { AttestationReport.parseFrom(B64.dec(it)) }
                ?: AttestationReport.getDefaultInstance(),
        )
    }
}

/**
 * Stored in [Context.getNoBackupFilesDir] so it is excluded from every backup
 * mechanism even if the manifest policy were relaxed.
 */
class CredentialStore private constructor(dir: File) {
    private val file = AtomicFile(File(dir, "passkeys.json"))
    private val lock = Any()

    fun all(): List<PasskeyRecord> = synchronized(lock) { read() }

    fun forRp(rpId: String): List<PasskeyRecord> = all().filter { it.rpId.equals(rpId, ignoreCase = true) }

    fun get(credentialId: String): PasskeyRecord? = all().firstOrNull { it.credentialId == credentialId }

    /**
     * Stores [record] and replaces any existing passkey for the same RP + user
     * handle, as WebAuthn requires for discoverable credentials.
     *
     * The new record is persisted *before* the old keys are destroyed, so a
     * failure at any point never leaves the account without a working passkey.
     * If we die between the write and the key deletion, the old keys become
     * record-less and [sweepOrphanKeys] removes them later.
     */
    fun addReplacingSameUser(record: PasskeyRecord): List<PasskeyRecord> {
        var replaced = emptyList<PasskeyRecord>()
        mutate { list ->
            val (same, rest) = list.partition {
                it.rpId.equals(record.rpId, ignoreCase = true) && it.userId == record.userId
            }
            replaced = same
            rest + record
        }
        replaced.forEach { StrongBoxKeys.delete(it.alias) }
        return replaced
    }

    fun updateSignCount(credentialId: String, signCount: Long) = mutate { list ->
        list.map { if (it.credentialId == credentialId) it.copy(signCount = signCount) else it }
    }

    /** Deletes the metadata *and* destroys the StrongBox key. Irreversible. */
    fun delete(credentialId: String) {
        StrongBoxKeys.delete(StrongBoxKeys.alias(credentialId))
        mutate { list -> list.filterNot { it.credentialId == credentialId } }
    }

    /**
     * Drops records whose key no longer exists (e.g. the user removed the screen
     * lock, which makes Android wipe auth-bound keys).
     */
    fun pruneOrphans(): Int {
        var removed = 0
        mutate { list ->
            list.filter { StrongBoxKeys.exists(it.alias) }.also { removed = list.size - it.size }
        }
        return removed
    }

    /**
     * The reverse of [pruneOrphans]: destroys Keystore keys that no record points
     * at, e.g. when the process was killed mid-registration after key generation.
     *
     * Only keys older than [minAgeMillis] are touched so that a registration in
     * progress (key generated, record not yet written) is never swept. Keys with
     * an unknown creation date are left alone.
     */
    fun sweepOrphanKeys(minAgeMillis: Long = ORPHAN_MIN_AGE_MILLIS): Int = synchronized(lock) {
        val known = read().mapTo(HashSet()) { it.alias }
        val cutoff = System.currentTimeMillis() - minAgeMillis
        StrongBoxKeys.credentialKeys()
            .filter { it.alias !in known && (it.created?.time ?: Long.MAX_VALUE) < cutoff }
            .onEach { StrongBoxKeys.delete(it.alias) }
            .size
    }

    private fun mutate(f: (List<PasskeyRecord>) -> List<PasskeyRecord>) = synchronized(lock) {
        write(f(read()))
    }

    private fun read(): List<PasskeyRecord> {
        if (!file.baseFile.exists()) return emptyList()
        val arr = JSONArray(String(file.readFully(), Charsets.UTF_8))
        return List(arr.length()) { PasskeyRecord.fromJson(arr.getJSONObject(it)) }
    }

    private fun write(records: List<PasskeyRecord>) {
        val out = file.startWrite()
        try {
            out.write(JSONArray(records.map { it.toJson() }).toString().toByteArray())
            file.finishWrite(out)
        } catch (t: Throwable) {
            file.failWrite(out)
            throw t
        }
    }

    companion object {
        /** No registration ceremony takes anywhere near this long. */
        const val ORPHAN_MIN_AGE_MILLIS = 60 * 60 * 1000L

        @Volatile private var instance: CredentialStore? = null

        fun get(context: Context): CredentialStore =
            instance ?: synchronized(this) {
                instance ?: CredentialStore(context.applicationContext.noBackupFilesDir).also { instance = it }
            }
    }
}
