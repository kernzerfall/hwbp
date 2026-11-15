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
import java.io.IOException

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
 * passkeys.json exists but isn't a readable JSON array. Never treated as "no
 * passkeys": that would make [CredentialStore.sweepOrphanKeys] destroy every key
 * and the next write overwrite the file. Every operation fails until the user
 * runs [CredentialStore.reset].
 */
class CredentialStoreException(message: String, cause: Throwable) : Exception(message, cause)

/**
 * An entry of passkeys.json that can't be used as a passkey: either a record that
 * failed to parse, or a stub written by [CredentialStore.reset] for a key whose
 * metadata was lost. It is kept verbatim on every write, and its key (if
 * [credentialId] is known) is never swept, until the user destroys it.
 */
class DamagedEntry internal constructor(
    internal val raw: Any,
    /** null if not even the credential ID could be read. */
    val credentialId: String?,
    val createdAt: Long?,
    /** true for stubs written by [CredentialStore.reset]. */
    val recovered: Boolean,
) {
    internal val rawText: String = raw.toString()
}

class StoreContents(val records: List<PasskeyRecord>, val damaged: List<DamagedEntry>)

/**
 * Stored in [Context.getNoBackupFilesDir] so it is excluded from every backup
 * mechanism even if the manifest policy were relaxed.
 *
 * Entries are parsed one by one: a damaged entry doesn't take the others down
 * (see [DamagedEntry]).
 */
class CredentialStore private constructor(private val dir: File) {
    private val file = AtomicFile(File(dir, FILE_NAME))
    private val lock = Any()

    fun contents(): StoreContents = synchronized(lock) { read() }

    fun all(): List<PasskeyRecord> = contents().records

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
    fun delete(credentialId: String) = synchronized(lock) {
        val c = read() // fail before touching the key if the store is unreadable
        StrongBoxKeys.delete(StrongBoxKeys.alias(credentialId))
        write(c.records.filterNot { it.credentialId == credentialId }, c.damaged)
    }

    /**
     * Removes a damaged entry and destroys its key, if known. Irreversible. If the
     * entry had no readable credential ID, its key (whichever it is) becomes an
     * orphan and [sweepOrphanKeys] destroys it later.
     */
    fun deleteDamaged(entry: DamagedEntry) = synchronized(lock) {
        val c = read()
        entry.credentialId?.let { StrongBoxKeys.delete(StrongBoxKeys.alias(it)) }
        val i = c.damaged.indexOfFirst { it.rawText == entry.rawText }
        if (i >= 0) write(c.records, c.damaged.filterIndexed { j, _ -> j != i })
    }

    /**
     * Recovery from an unreadable file: moves it aside (kept for manual repair) and
     * writes a [DamagedEntry] stub for every credential key in StrongBox, so no key
     * is swept and each can be destroyed individually. The passkeys themselves are
     * not usable again: RP ID and user handle are only in the lost file.
     *
     * @return the name of the file the corrupt store was moved to.
     */
    fun reset(): String = synchronized(lock) {
        val now = System.currentTimeMillis()
        val stubs = StrongBoxKeys.credentialKeys().map { key ->
            val stub = JSONObject()
                .put("credentialId", key.alias.removePrefix(StrongBoxKeys.alias("")))
                .put("recoveredAt", now)
            key.created?.let { stub.put("createdAt", it.time) }
            parseDamaged(stub)
        }
        val aside = "$FILE_NAME.corrupt-$now"
        val from = file.baseFile
        val to = File(dir, aside)
        val moved = from.exists()
        if (moved && !from.renameTo(to)) throw IOException("could not move ${from.name} aside")
        try {
            write(emptyList(), stubs)
        } catch (t: Throwable) {
            // A missing file reads as "no passkeys", which would let the sweep destroy every key.
            if (moved) to.renameTo(from)
            throw t
        }
        aside
    }

    /**
     * Drops records whose key no longer exists (e.g. the user removed the screen
     * lock, which makes Android wipe auth-bound keys). Damaged entries are kept.
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
     * Keys of damaged entries count as referenced. If any damaged entry has no
     * readable credential ID, nothing is swept: it could belong to any key.
     *
     * Only keys older than [minAgeMillis] are touched so that a registration in
     * progress (key generated, record not yet written) is never swept. Keys with
     * an unknown creation date are left alone.
     */
    fun sweepOrphanKeys(minAgeMillis: Long = ORPHAN_MIN_AGE_MILLIS): Int = synchronized(lock) {
        val c = read()
        if (c.damaged.any { it.credentialId == null }) return 0
        val known = HashSet<String>()
        c.records.mapTo(known) { it.alias }
        c.damaged.mapTo(known) { StrongBoxKeys.alias(it.credentialId!!) }
        val cutoff = System.currentTimeMillis() - minAgeMillis
        StrongBoxKeys.credentialKeys()
            .filter { it.alias !in known && (it.created?.time ?: Long.MAX_VALUE) < cutoff }
            .onEach { StrongBoxKeys.delete(it.alias) }
            .size
    }

    private fun mutate(f: (List<PasskeyRecord>) -> List<PasskeyRecord>) = synchronized(lock) {
        val c = read()
        write(f(c.records), c.damaged)
    }

    /**
     * AtomicFile writes to `passkeys.json.new` and renames it over the file, so an
     * interrupted write leaves the previous file intact; there is no backup file
     * to consider.
     *
     * @throws CredentialStoreException if the file exists but isn't a readable JSON array.
     */
    private fun read(): StoreContents {
        if (!file.baseFile.exists()) return StoreContents(emptyList(), emptyList())
        val arr = try {
            JSONArray(String(file.readFully(), Charsets.UTF_8))
        } catch (e: Exception) {
            throw CredentialStoreException("$FILE_NAME is unreadable or corrupt", e)
        }
        val records = ArrayList<PasskeyRecord>()
        val damaged = ArrayList<DamagedEntry>()
        for (i in 0 until arr.length()) {
            val raw = arr.opt(i)
            val record = (raw as? JSONObject)
                ?.takeUnless { it.has("recoveredAt") }
                ?.let { runCatching { PasskeyRecord.fromJson(it) }.getOrNull() }
            if (record != null) records += record else damaged += parseDamaged(raw ?: JSONObject.NULL)
        }
        return StoreContents(records, damaged)
    }

    private fun parseDamaged(raw: Any): DamagedEntry {
        val o = raw as? JSONObject
        return DamagedEntry(
            raw = raw,
            credentialId = o?.optString("credentialId")?.takeIf { it.isNotEmpty() },
            createdAt = o?.optLong("createdAt", -1)?.takeIf { it >= 0 },
            recovered = o?.has("recoveredAt") == true,
        )
    }

    private fun write(records: List<PasskeyRecord>, damaged: List<DamagedEntry>) {
        val arr = JSONArray()
        records.forEach { arr.put(it.toJson()) }
        damaged.forEach { arr.put(it.raw) }
        val out = file.startWrite()
        try {
            out.write(arr.toString().toByteArray())
            file.finishWrite(out)
        } catch (t: Throwable) {
            file.failWrite(out)
            throw t
        }
    }

    companion object {
        private const val FILE_NAME = "passkeys.json"

        /** No registration ceremony takes anywhere near this long. */
        const val ORPHAN_MIN_AGE_MILLIS = 60 * 60 * 1000L

        @Volatile private var instance: CredentialStore? = null

        fun get(context: Context): CredentialStore =
            instance ?: synchronized(this) {
                instance ?: CredentialStore(context.applicationContext.noBackupFilesDir).also { instance = it }
            }
    }
}
