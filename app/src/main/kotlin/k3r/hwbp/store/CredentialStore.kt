// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.store

import android.content.Context
import android.util.AtomicFile
import k3r.hwbp.core.B64
import k3r.hwbp.keystore.StrongBoxKeys
import k3r.hwbp.proto.AttestationReport
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener
import java.io.File
import java.io.IOException

/**
 * Non-secret passkey metadata. The private key itself never leaves StrongBox;
 * this is just what we need to list credentials and build responses.
 *
 * Only what a sign-in needs is mandatory in the file: [credentialId], [rpId],
 * [userId], [signCount] (a guessed counter could go backwards, which RPs read as
 * a cloned key) and [publicKeySpki]. Everything else is informational, and a
 * missing or malformed value doesn't make the passkey unusable.
 */
data class PasskeyRecord(
    val credentialId: String,
    val rpId: String,
    /** base64url user handle, returned as `userHandle` in assertions. */
    val userId: String,
    val userName: String,
    val displayName: String,
    /** null if missing or malformed in the file. */
    val createdAt: Long?,
    val signCount: Long,
    val publicKeySpki: String,
    /** Attestation report from the Rust policy at creation time; null if missing or malformed in the file. */
    val attestation: AttestationReport?,
) {
    val alias: String get() = StrongBoxKeys.alias(credentialId)

    fun toJson(): JSONObject = JSONObject()
        .put("credentialId", credentialId)
        .put("rpId", rpId)
        .put("userId", userId)
        .put("userName", userName)
        .put("displayName", displayName)
        .putOpt("createdAt", createdAt)
        .put("signCount", signCount)
        .put("publicKeySpki", publicKeySpki)
        .putOpt("attestation", attestation?.let { B64.enc(it.toByteArray()) })

    companion object {
        const val UNKNOWN_USER = "Unknown account"

        /** @throws org.json.JSONException if a mandatory field is missing or has the wrong type. */
        fun fromJson(o: JSONObject): PasskeyRecord {
            fun text(key: String) = (o.opt(key) as? String)?.takeIf { it.isNotEmpty() }
            val userName = text("userName") ?: text("displayName") ?: UNKNOWN_USER
            return PasskeyRecord(
                credentialId = o.getString("credentialId"),
                rpId = o.getString("rpId"),
                userId = o.getString("userId"),
                userName = userName,
                displayName = text("displayName") ?: userName,
                createdAt = (o.opt("createdAt") as? Number)?.toLong(),
                signCount = o.getLong("signCount"),
                publicKeySpki = o.getString("publicKeySpki"),
                attestation = text("attestation")
                    ?.let { runCatching { AttestationReport.parseFrom(B64.dec(it)) }.getOrNull() },
            )
        }
    }
}

/**
 * passkeys.json can't be used: it is unreadable, was written by a newer schema
 * version, or is missing although passkey keys exist. Never treated as "no
 * passkeys": that would make [CredentialStore.sweepOrphanKeys] destroy every key
 * and the next write overwrite the file. Every operation fails until the user
 * runs [CredentialStore.reset].
 */
class CredentialStoreException(message: String, cause: Throwable? = null) : Exception(message, cause)

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
 * Format: `{"version": 1, "passkeys": [...]}`. Schema 0 was the bare array; it
 * is rewritten in the current format the first time it is read.
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
     * Recovery from an unusable file: moves it aside if it exists (kept for manual
     * repair) and
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
        val records = f(c.records)
        // Unchanged (e.g. a prune that found nothing): leave the file as it is.
        if (records != c.records) write(records, c.damaged)
    }

    /**
     * AtomicFile writes to `passkeys.json.new` and renames it over the file, so an
     * interrupted write leaves the previous file intact; there is no backup file
     * to consider.
     *
     * @throws CredentialStoreException see there.
     */
    private fun read(): StoreContents {
        if (!file.baseFile.exists()) {
            // Either nothing was ever stored, or the file was lost. Telling them
            // apart matters: "no passkeys" lets the sweep destroy every key.
            val keys = try {
                StrongBoxKeys.credentialKeys().size
            } catch (e: Exception) {
                throw CredentialStoreException("$FILE_NAME is missing and Keystore can't be listed", e)
            }
            if (keys > 0) throw CredentialStoreException("$FILE_NAME is missing but $keys passkey key(s) exist")
            // Written now, so that from here on a missing file always means a lost one
            // (registration reads the store before it generates its key).
            write(emptyList(), emptyList())
            return StoreContents(emptyList(), emptyList())
        }
        val version: Int
        val arr: JSONArray
        try {
            when (val root = JSONTokener(String(file.readFully(), Charsets.UTF_8)).nextValue()) {
                is JSONArray -> {
                    version = 0
                    arr = root
                }
                is JSONObject -> {
                    version = root.getInt("version")
                    arr = root.getJSONArray("passkeys")
                }
                else -> throw JSONException("neither an object nor an array")
            }
        } catch (e: Exception) {
            throw CredentialStoreException("$FILE_NAME is unreadable or corrupt", e)
        }
        if (version !in 0..SCHEMA_VERSION) {
            throw CredentialStoreException("$FILE_NAME has schema version $version; this build reads up to $SCHEMA_VERSION")
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
        // Schema 0 -> 1 only wraps the array; entries are unchanged.
        if (version < SCHEMA_VERSION) write(records, damaged)
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
            out.write(JSONObject().put("version", SCHEMA_VERSION).put("passkeys", arr).toString().toByteArray())
            file.finishWrite(out)
        } catch (t: Throwable) {
            file.failWrite(out)
            throw t
        }
    }

    companion object {
        private const val FILE_NAME = "passkeys.json"

        /** Bump when a change to the file or its entries needs a migration in [read]. */
        private const val SCHEMA_VERSION = 1

        /** No registration ceremony takes anywhere near this long. */
        const val ORPHAN_MIN_AGE_MILLIS = 60 * 60 * 1000L

        @Volatile private var instance: CredentialStore? = null

        fun get(context: Context): CredentialStore =
            instance ?: synchronized(this) {
                instance ?: CredentialStore(context.applicationContext.noBackupFilesDir).also { instance = it }
            }
    }
}
