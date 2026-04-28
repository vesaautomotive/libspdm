/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SM3 digest Wrapper Implementations.
 *
 * Lifecycle: new -> init -> update* -> final -> free
 *   _new     allocates an EVP_MD_CTX; does NOT install the digest algorithm.
 *   _init    installs EVP_sm3() via EVP_DigestInit_ex; safe to call again to reset.
 *   _update  feeds data incrementally; NULL data allowed only when data_size == 0.
 *   _final   writes the 32-byte digest; does not free ctx (caller owns lifetime).
 *   _free    releases the ctx; NULL-safe.
 *
 * Thread safety: a single EVP_MD_CTX must not be shared across threads without
 * external synchronization. Two threads each with their own context may call
 * these functions concurrently without coordination.
 *
 * ERR queue: this wrapper does not touch the OpenSSL ERR queue on failure;
 * callers that inspect ERR_peek_error() at their own boundaries see consistent
 * behavior with all other libspdm_*_hash wrappers.
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>

/**
 * Allocates one EVP_MD_CTX for subsequent SM3-256 use.
 *
 * @return  Pointer to the allocated context, or NULL on allocation failure.
 **/
void *libspdm_sm3_256_new(void)
{
    return EVP_MD_CTX_new();
}

/**
 * Releases the specified EVP_MD_CTX context. NULL-safe.
 *
 * @param[in]  sm3_256_ctx  Pointer to the context to be released.
 **/
void libspdm_sm3_256_free(void *sm3_context)
{
    EVP_MD_CTX_free((EVP_MD_CTX *)sm3_context);
}

/**
 * Initializes sm3_context with EVP_sm3() for subsequent hashing.
 *
 * If sm3_context is NULL, then return false.
 *
 * @param[out]  sm3_context  Pointer to an allocated SM3 context.
 *
 * @retval true   Initialization succeeded.
 * @retval false  Initialization failed or sm3_context is NULL.
 **/
bool libspdm_sm3_256_init(void *sm3_context)
{
    EVP_MD_CTX *ctx = sm3_context;

    if (ctx == NULL) {
        return false;
    }

    return EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) == 1;
}

/**
 * Makes a copy of an existing SM3 context.
 *
 * If sm3_context is NULL, then return false.
 * If new_sm3_context is NULL, then return false.
 * Duplicating a context that has not yet been initialized via _init returns false.
 *
 * @param[in]  sm3_context      Pointer to the source SM3 context.
 * @param[out] new_sm3_context  Pointer to the destination SM3 context.
 *
 * @retval true   Copy succeeded.
 * @retval false  Copy failed, or either pointer is NULL.
 **/
bool libspdm_sm3_256_duplicate(const void *sm3_context, void *new_sm3_context)
{
    if (sm3_context == NULL || new_sm3_context == NULL) {
        return false;
    }

    return EVP_MD_CTX_copy_ex((EVP_MD_CTX *)new_sm3_context,
                              (const EVP_MD_CTX *)sm3_context) == 1;
}

/**
 * Digests the input data and updates the SM3 context.
 *
 * May be called multiple times. If data is NULL, data_size must be 0
 * (a no-op that returns true); any other combination returns false.
 *
 * If sm3_context is NULL, then return false.
 *
 * @param[in,out]  sm3_context  Pointer to the SM3 context.
 * @param[in]      data         Pointer to the data buffer to be hashed.
 * @param[in]      data_size    Size of data buffer in bytes.
 *
 * @retval true   Digest update succeeded.
 * @retval false  Digest update failed.
 **/
bool libspdm_sm3_256_update(void *sm3_context, const void *data,
                            size_t data_size)
{
    EVP_MD_CTX *ctx = sm3_context;

    if (ctx == NULL) {
        return false;
    }

    if (data == NULL) {
        return data_size == 0;
    }

    return EVP_DigestUpdate(ctx, data, data_size) == 1;
}

/**
 * Completes SM3 computation and writes the 32-byte digest to hash_value.
 *
 * The context must not be used for further updates after this call.
 * The context is not freed here; the caller must call libspdm_sm3_256_free().
 *
 * If sm3_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in,out]  sm3_context  Pointer to the SM3 context.
 * @param[out]     hash_value   Buffer that receives the SM3 digest (32 bytes).
 *
 * @retval true   Digest computation succeeded.
 * @retval false  Digest computation failed.
 **/
bool libspdm_sm3_256_final(void *sm3_context, uint8_t *hash_value)
{
    EVP_MD_CTX *ctx = sm3_context;
    unsigned int out_len = 0;

    if (ctx == NULL || hash_value == NULL) {
        return false;
    }

    if (EVP_DigestFinal_ex(ctx, hash_value, &out_len) != 1) {
        return false;
    }

    return out_len == LIBSPDM_SM3_256_DIGEST_SIZE;
}

/**
 * Computes the SM3 digest of data in a single call.
 *
 * If hash_value is NULL, then return false.
 * If data is NULL, data_size must be 0; the empty-input SM3 digest is returned.
 *
 * @param[in]   data        Pointer to the data buffer to be hashed.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[out]  hash_value  Buffer that receives the SM3 digest (32 bytes).
 *
 * @retval true   Digest computation succeeded.
 * @retval false  Digest computation failed.
 **/
bool libspdm_sm3_256_hash_all(const void *data, size_t data_size,
                              uint8_t *hash_value)
{
    EVP_MD_CTX *ctx = NULL;
    unsigned int out_len = 0;
    bool result = false;

    if (hash_value == NULL) {
        return false;
    }

    if (data == NULL && data_size != 0) {
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) != 1) {
        goto cleanup;
    }

    if (data_size != 0) {
        if (EVP_DigestUpdate(ctx, data, data_size) != 1) {
            goto cleanup;
        }
    }

    if (EVP_DigestFinal_ex(ctx, hash_value, &out_len) != 1) {
        goto cleanup;
    }

    result = (out_len == LIBSPDM_SM3_256_DIGEST_SIZE);

cleanup:
    EVP_MD_CTX_free(ctx);
    return result;
}
