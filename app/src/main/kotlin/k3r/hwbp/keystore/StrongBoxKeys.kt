// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.keystore

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Date

class StrongBoxException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * All private-key operations live here. Keys are:
 *  - generated *inside* StrongBox (no TEE or software fallback, ever),
 *  - non-exportable (an Android Keystore property; there is no API to get them out),
 *  - usable only after a fresh user authentication per signature,
 *  - usable only while the device is unlocked,
 *  - attested, with the attestation challenge bound to the WebAuthn clientDataHash.
 */
object StrongBoxKeys {
    private const val PROVIDER = "AndroidKeyStore"
    private const val PREFIX = "hwbp.cred."
    private const val SELF_TEST_ALIAS = "hwbp.selftest"

    fun alias(credentialId: String) = PREFIX + credentialId

    fun isAvailable(context: Context): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    /**
     * Generates a P-256 signing key in StrongBox and returns its attestation chain
     * (leaf first). The caller must still run the chain through the Rust policy.
     */
    fun generate(alias: String, attestationChallenge: ByteArray): List<ByteArray> {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(true)
            .setAttestationChallenge(attestationChallenge)
            .setUserAuthenticationRequired(true)
            // timeout 0 => every single signature needs its own authentication.
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            // true would make enrolling a new fingerprint silently destroy every passkey.
            .setInvalidatedByBiometricEnrollment(false)
            .setUnlockedDeviceRequired(true)
            .build()

        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).run {
                initialize(spec)
                generateKeyPair()
            }
        } catch (e: StrongBoxUnavailableException) {
            throw StrongBoxException("StrongBox is not available on this device", e)
        }

        try {
            val level = keyInfo(alias).securityLevel
            if (level != KeyProperties.SECURITY_LEVEL_STRONGBOX) {
                throw StrongBoxException("Keystore placed the key at security level $level, not StrongBox")
            }
            val chain = keyStore().getCertificateChain(alias)
                ?: throw StrongBoxException("Keystore returned no attestation chain")
            return chain.map { it.encoded }
        } catch (t: Throwable) {
            delete(alias)
            throw t
        }
    }

    private fun privateKey(alias: String): PrivateKey =
        keyStore().getKey(alias, null) as? PrivateKey
            ?: throw StrongBoxException("No key for $alias (was it deleted, or the lock screen removed?)")

    private fun keyInfo(alias: String): KeyInfo {
        val key = privateKey(alias)
        return KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
    }

    /**
     * A Signature initialised with the StrongBox key. It is unusable until it has
     * been authorised by BiometricPrompt via a CryptoObject.
     */
    fun signatureFor(alias: String): Signature =
        Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey(alias)) }

    fun exists(alias: String): Boolean = keyStore().containsAlias(alias)

    /** A passkey key in Keystore, whether or not any record still points at it. */
    class StoredKey(val alias: String, val created: Date?)

    /** Every passkey key HWBP owns in Keystore (self-test key excluded). */
    fun credentialKeys(): List<StoredKey> {
        val ks = keyStore()
        return ks.aliases().toList()
            .filter { it.startsWith(PREFIX) }
            .map { StoredKey(it, runCatching { ks.getCreationDate(it) }.getOrNull()) }
    }

    fun delete(alias: String) {
        runCatching { keyStore().deleteEntry(alias) }
    }

    /**
     * Generates and immediately destroys a throwaway key with the same parameters
     * passkeys use, returning its attestation chain. Used by the UI self-test.
     */
    fun selfTest(challenge: ByteArray): List<ByteArray> =
        try {
            generate(SELF_TEST_ALIAS, challenge)
        } finally {
            delete(SELF_TEST_ALIAS)
        }
}
