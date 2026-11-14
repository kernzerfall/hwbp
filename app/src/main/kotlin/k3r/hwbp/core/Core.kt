// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.core

import com.google.protobuf.ByteString
import k3r.hwbp.proto.AssertionPlan
import k3r.hwbp.proto.AssertionSummary
import k3r.hwbp.proto.AttestationReport
import k3r.hwbp.proto.Caller
import k3r.hwbp.proto.ErrorCode
import k3r.hwbp.proto.RegistrationFinishResponse
import k3r.hwbp.proto.RegistrationPlan
import k3r.hwbp.proto.RequestKt
import k3r.hwbp.proto.Response
import k3r.hwbp.proto.ToSign
import k3r.hwbp.proto.VersionResponse
import k3r.hwbp.proto.assertionAuthDataRequest
import k3r.hwbp.proto.assertionBeginRequest
import k3r.hwbp.proto.assertionFinishRequest
import k3r.hwbp.proto.assertionInspectRequest
import k3r.hwbp.proto.attestationVerifyRequest
import k3r.hwbp.proto.registrationAuthDataRequest
import k3r.hwbp.proto.registrationBeginRequest
import k3r.hwbp.proto.registrationFinishRequest
import k3r.hwbp.proto.request
import k3r.hwbp.proto.versionRequest
import java.util.Base64

/** JNI entry point implemented in `rust/src/lib.rs`. Takes a `Request`, returns a `Response`. */
internal object NativeCore {
    init {
        System.loadLibrary("hwbp_core")
    }

    @JvmStatic
    external fun invoke(request: ByteArray): ByteArray
}

/** An error reported by the Rust core. */
class CoreException(val code: ErrorCode, message: String) : Exception("${code.name}: $message")

internal object B64 {
    fun enc(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    fun enc(b: ByteString): String = enc(b.toByteArray())
    fun dec(s: String): ByteArray = Base64.getUrlDecoder().decode(s)
    fun decBytes(s: String): ByteString = ByteString.copyFrom(dec(s))
}

internal fun ByteArray.bytes(): ByteString = ByteString.copyFrom(this)

/**
 * Typed wrappers around the Rust dispatcher. Schema and semantics:
 * `proto/hwbp/v1/core.proto` and `rust/src/api.rs`.
 */
object Core {
    private fun call(expected: Response.ResultCase, build: RequestKt.Dsl.() -> Unit): Response {
        val response = Response.parseFrom(NativeCore.invoke(request(build).toByteArray()))
        when (response.resultCase) {
            expected -> return response
            Response.ResultCase.ERROR -> throw CoreException(response.error.code, response.error.message)
            else -> throw IllegalStateException("core returned ${response.resultCase}, expected $expected")
        }
    }

    fun version(): VersionResponse =
        call(Response.ResultCase.VERSION) { version = versionRequest {} }.version

    fun registrationBegin(requestJson: String, caller: Caller, existingCredentialIds: List<ByteString>): RegistrationPlan =
        call(Response.ResultCase.REGISTRATION_PLAN) {
            registrationBegin = registrationBeginRequest {
                this.requestJson = requestJson
                this.caller = caller
                this.existingCredentialIds += existingCredentialIds
            }
        }.registrationPlan

    /** Verifies the StrongBox attestation chain and returns the bytes to sign. */
    fun registrationAuthData(plan: RegistrationPlan, x5c: List<ByteArray>): ToSign =
        call(Response.ResultCase.TO_SIGN) {
            registrationAuthData = registrationAuthDataRequest {
                this.plan = plan
                this.x5C += x5c.map { it.bytes() }
            }
        }.toSign

    fun registrationFinish(
        plan: RegistrationPlan,
        authenticatorData: ByteString,
        signature: ByteArray,
        x5c: List<ByteArray>,
    ): RegistrationFinishResponse =
        call(Response.ResultCase.REGISTRATION_FINISH) {
            registrationFinish = registrationFinishRequest {
                this.plan = plan
                this.authenticatorData = authenticatorData
                this.signature = signature.bytes()
                this.x5C += x5c.map { it.bytes() }
            }
        }.registrationFinish

    fun inspectAssertion(requestJson: String): AssertionSummary =
        call(Response.ResultCase.ASSERTION_SUMMARY) {
            assertionInspect = assertionInspectRequest { this.requestJson = requestJson }
        }.assertionSummary

    fun assertionBegin(requestJson: String, caller: Caller, credentialId: ByteString, credentialRpId: String): AssertionPlan =
        call(Response.ResultCase.ASSERTION_PLAN) {
            assertionBegin = assertionBeginRequest {
                this.requestJson = requestJson
                this.caller = caller
                this.credentialId = credentialId
                this.credentialRpId = credentialRpId
            }
        }.assertionPlan

    fun assertionAuthData(plan: AssertionPlan, signCount: Int): ToSign =
        call(Response.ResultCase.TO_SIGN) {
            assertionAuthData = assertionAuthDataRequest {
                this.plan = plan
                this.signCount = signCount
            }
        }.toSign

    fun assertionFinish(
        plan: AssertionPlan,
        authenticatorData: ByteString,
        signature: ByteArray,
        userHandle: ByteString,
        publicKeySpki: ByteString,
    ): String =
        call(Response.ResultCase.ASSERTION_FINISH) {
            assertionFinish = assertionFinishRequest {
                this.plan = plan
                this.authenticatorData = authenticatorData
                this.signature = signature.bytes()
                this.userHandle = userHandle
                this.publicKeySpki = publicKeySpki
            }
        }.assertionFinish.responseJson

    /** Runs the full StrongBox attestation policy over a chain. Throws if it fails. */
    fun verifyAttestation(x5c: List<ByteArray>, challenge: ByteArray): AttestationReport =
        call(Response.ResultCase.ATTESTATION_REPORT) {
            attestationVerify = attestationVerifyRequest {
                this.x5C += x5c.map { it.bytes() }
                this.challenge = challenge.bytes()
            }
        }.attestationReport
}
