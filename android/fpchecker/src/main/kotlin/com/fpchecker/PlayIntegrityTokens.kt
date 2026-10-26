package com.fpchecker

import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

/**
 * Play Integrity Standard API wrapper. Any failure or timeout yields null (no proof);
 * identify must never fail because of Integrity.
 */
internal class PlayIntegrityTokens(
    context: Context,
    private val cloudProjectNumber: Long,
    private val timeoutMillis: Long,
) {
    private val manager: StandardIntegrityManager = IntegrityManagerFactory.createStandard(context.applicationContext)
    private val lock = Mutex()
    private var provider: StandardIntegrityTokenProvider? = null

    /** Prepares the provider ahead of the request so the token call is fast. Failures are ignored. */
    suspend fun warmUp() {
        withTimeoutOrNull(timeoutMillis) {
            try {
                currentProvider(forceFresh = false)
            } catch (e: CancellationException) {
                throw e
            } catch (e: VirtualMachineError) {
                throw e
            } catch (_: Throwable) {
                null
            }
        }
    }

    suspend fun token(requestHash: String): String? =
        withTimeoutOrNull(timeoutMillis) {
            try {
                requestWithRetry(requestHash)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                null
            }
        }

    /** Prepared provider is cached; if a request fails, re-prepare once and retry. */
    private suspend fun requestWithRetry(requestHash: String): String? {
        val first = currentProvider(forceFresh = false)
        first?.let { requestToken(it, requestHash) }?.let { return it }
        val second = currentProvider(forceFresh = true) ?: return null
        return requestToken(second, requestHash)
    }

    private suspend fun currentProvider(forceFresh: Boolean): StandardIntegrityTokenProvider? =
        lock.withLock {
            if (!forceFresh) provider?.let { return it }
            provider = null
            val request = PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber).build()
            val fresh = manager.prepareIntegrityToken(request).awaitOrNull()
            provider = fresh
            fresh
        }

    private suspend fun requestToken(provider: StandardIntegrityTokenProvider, requestHash: String): String? {
        val request = StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()
        return provider.request(request).awaitOrNull()?.token()
    }

    private suspend fun <T> Task<T>.awaitOrNull(): T? = suspendCancellableCoroutine { cont ->
        addOnSuccessListener { if (cont.isActive) cont.resume(it) }
        addOnFailureListener { if (cont.isActive) cont.resume(null) }
        addOnCanceledListener { if (cont.isActive) cont.resume(null) }
    }
}
