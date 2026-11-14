// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.provider

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.credentials.exceptions.domerrors.DataError
import androidx.credentials.exceptions.domerrors.DomError
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.domerrors.SecurityError
import androidx.credentials.exceptions.domerrors.UnknownError
import k3r.hwbp.core.CoreException
import k3r.hwbp.keystore.StrongBoxException
import k3r.hwbp.proto.ErrorCode

/** Outcome of a failed ceremony, already mapped to a WebAuthn DOMException. */
internal sealed interface Failure {
    data object Cancelled : Failure
    data class Dom(val error: DomError, val message: String) : Failure
}

internal fun Throwable.toFailure(): Failure = when (this) {
    is UserVerificationException ->
        if (cancelled) Failure.Cancelled else Failure.Dom(NotAllowedError(), message ?: "user verification failed")
    is CoreException -> Failure.Dom(
        when (code) {
            ErrorCode.ERROR_CODE_INVALID_STATE -> InvalidStateError()
            ErrorCode.ERROR_CODE_NOT_SUPPORTED -> NotSupportedError()
            ErrorCode.ERROR_CODE_NOT_ALLOWED -> NotAllowedError()
            ErrorCode.ERROR_CODE_SECURITY -> SecurityError()
            ErrorCode.ERROR_CODE_DATA -> DataError()
            else -> UnknownError()
        },
        message ?: code.name,
    )
    is StrongBoxException -> Failure.Dom(NotSupportedError(), message ?: "StrongBox unavailable")
    is KeyPermanentlyInvalidatedException -> Failure.Dom(NotAllowedError(), "this passkey's key was invalidated")
    is SecurityException -> Failure.Dom(SecurityError(), message ?: "security error")
    else -> Failure.Dom(UnknownError(), "${javaClass.simpleName}: $message")
}
