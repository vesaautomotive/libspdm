/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * AEAD (SM4-GCM) Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>

/* SM4-GCM fixed parameter sizes (per SPDM spec and doc comments). */
#define LIBSPDM_SM4_GCM_KEY_SIZE  16U
#define LIBSPDM_SM4_GCM_IV_SIZE   12U
#define LIBSPDM_SM4_GCM_TAG_SIZE  16U

/**
 * Performs AEAD SM4-GCM authenticated encryption on a data buffer and additional authenticated data (AAD).
 *
 * iv_size must be 12, otherwise false is returned.
 * key_size must be 16, otherwise false is returned.
 * tag_size must be 16, otherwise false is returned.
 *
 * @param[in]   key         Pointer to the encryption key.
 * @param[in]   key_size     size of the encryption key in bytes.
 * @param[in]   iv          Pointer to the IV value.
 * @param[in]   iv_size      size of the IV value in bytes.
 * @param[in]   a_data       Pointer to the additional authenticated data (AAD).
 * @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
 * @param[in]   data_in      Pointer to the input data buffer to be encrypted.
 * @param[in]   data_in_size  size of the input data buffer in bytes.
 * @param[out]  tag_out      Pointer to a buffer that receives the authentication tag output.
 * @param[in]   tag_size     size of the authentication tag in bytes.
 * @param[out]  data_out     Pointer to a buffer that receives the encryption output.
 * @param[out]  data_out_size size of the output data buffer in bytes.
 *
 * @retval true   AEAD SM4-GCM authenticated encryption succeeded.
 * @retval false  AEAD SM4-GCM authenticated encryption failed.
 *
 **/
bool libspdm_aead_sm4_gcm_encrypt(const uint8_t *key, size_t key_size,
                                  const uint8_t *iv, size_t iv_size,
                                  const uint8_t *a_data, size_t a_data_size,
                                  const uint8_t *data_in, size_t data_in_size,
                                  uint8_t *tag_out, size_t tag_size,
                                  uint8_t *data_out, size_t *data_out_size)
{
    bool ret_value = false;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int out_len = 0;
    int total_len = 0;

    /* Fixed-size and range validation. */
    if (key_size != LIBSPDM_SM4_GCM_KEY_SIZE || iv_size != LIBSPDM_SM4_GCM_IV_SIZE ||
        tag_size != LIBSPDM_SM4_GCM_TAG_SIZE) {
        goto done;
    }
    if (data_in_size > INT_MAX || a_data_size > INT_MAX) {
        goto done;
    }
    if (data_out_size != NULL &&
        (*data_out_size > INT_MAX || *data_out_size < data_in_size)) {
        goto done;
    }

    /* Null-pointer validation. */
    if (key == NULL || iv == NULL || tag_out == NULL) {
        goto done;
    }
    if ((a_data_size > 0 && a_data == NULL) ||
        (data_in_size > 0 && (data_in == NULL || data_out == NULL))) {
        goto done;
    }

    /* Fetch SM4-GCM from the default provider. Returns NULL if unavailable. */
    cipher = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
    if (cipher == NULL) {
        goto done;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto done;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            (int)LIBSPDM_SM4_GCM_IV_SIZE, NULL) != 1) {
        goto done;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        goto done;
    }

    /* Feed AAD — skipped entirely when a_data_size == 0 to avoid NULL+0. */
    if (a_data_size > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &out_len, a_data, (int)a_data_size) != 1) {
            goto done;
        }
    }

    /* Encrypt payload — skipped entirely when data_in_size == 0. */
    if (data_in_size > 0) {
        if (EVP_EncryptUpdate(ctx, data_out, &out_len, data_in, (int)data_in_size) != 1) {
            goto done;
        }
        total_len = out_len;
    }

    /*
     * GCM Final always produces 0 additional bytes; the canonical
     * Update+Final accumulation pattern is kept for robustness.
     * When data_out is NULL (data_in_size == 0, total_len == 0) the
     * output pointer is passed as NULL — safe because no bytes are written.
     */
    if (EVP_EncryptFinal_ex(ctx, (data_out != NULL) ? (data_out + total_len) : NULL,
                            &out_len) != 1) {
        goto done;
    }
    total_len += out_len;

    /* Retrieve the authentication tag. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_size, tag_out) != 1) {
        goto done;
    }

    ret_value = true;

done:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);

    if (!ret_value) {
        /* Zero the output buffer so callers cannot observe partial/garbage ciphertext. */
        if (data_out != NULL && data_in_size > 0) {
            libspdm_zero_mem(data_out, data_in_size);
        }
        if (data_out_size != NULL) {
            *data_out_size = 0;
        }
    } else {
        if (data_out_size != NULL) {
            *data_out_size = data_in_size;
        }
    }

    return ret_value;
}

/**
 * Performs AEAD SM4-GCM authenticated decryption on a data buffer and additional authenticated data (AAD).
 *
 * iv_size must be 12, otherwise false is returned.
 * key_size must be 16, otherwise false is returned.
 * tag_size must be 16, otherwise false is returned.
 * If additional authenticated data verification fails, false is returned.
 *
 * @param[in]   key         Pointer to the encryption key.
 * @param[in]   key_size     size of the encryption key in bytes.
 * @param[in]   iv          Pointer to the IV value.
 * @param[in]   iv_size      size of the IV value in bytes.
 * @param[in]   a_data       Pointer to the additional authenticated data (AAD).
 * @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
 * @param[in]   data_in      Pointer to the input data buffer to be decrypted.
 * @param[in]   data_in_size  size of the input data buffer in bytes.
 * @param[in]   tag         Pointer to a buffer that contains the authentication tag.
 * @param[in]   tag_size     size of the authentication tag in bytes.
 * @param[out]  data_out     Pointer to a buffer that receives the decryption output.
 * @param[out]  data_out_size size of the output data buffer in bytes.
 *
 * @retval true   AEAD SM4-GCM authenticated decryption succeeded.
 * @retval false  AEAD SM4-GCM authenticated decryption failed.
 *
 **/
bool libspdm_aead_sm4_gcm_decrypt(const uint8_t *key, size_t key_size,
                                  const uint8_t *iv, size_t iv_size,
                                  const uint8_t *a_data, size_t a_data_size,
                                  const uint8_t *data_in, size_t data_in_size,
                                  const uint8_t *tag, size_t tag_size,
                                  uint8_t *data_out, size_t *data_out_size)
{
    bool ret_value = false;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int out_len = 0;
    int total_len = 0;

    /* Fixed-size and range validation. */
    if (key_size != LIBSPDM_SM4_GCM_KEY_SIZE || iv_size != LIBSPDM_SM4_GCM_IV_SIZE ||
        tag_size != LIBSPDM_SM4_GCM_TAG_SIZE) {
        goto done;
    }
    if (data_in_size > INT_MAX || a_data_size > INT_MAX) {
        goto done;
    }
    if (data_out_size != NULL &&
        (*data_out_size > INT_MAX || *data_out_size < data_in_size)) {
        goto done;
    }

    /* Null-pointer validation. */
    if (key == NULL || iv == NULL || tag == NULL) {
        goto done;
    }
    if ((a_data_size > 0 && a_data == NULL) ||
        (data_in_size > 0 && (data_in == NULL || data_out == NULL))) {
        goto done;
    }

    /* Fetch SM4-GCM from the default provider. Returns NULL if unavailable. */
    cipher = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
    if (cipher == NULL) {
        goto done;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto done;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            (int)LIBSPDM_SM4_GCM_IV_SIZE, NULL) != 1) {
        goto done;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        goto done;
    }

    /* Feed AAD — skipped entirely when a_data_size == 0 to avoid NULL+0. */
    if (a_data_size > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &out_len, a_data, (int)a_data_size) != 1) {
            goto done;
        }
    }

    /* Decrypt payload — skipped entirely when data_in_size == 0. */
    if (data_in_size > 0) {
        if (EVP_DecryptUpdate(ctx, data_out, &out_len, data_in, (int)data_in_size) != 1) {
            goto done;
        }
        total_len = out_len;
    }

    /*
     * SET_TAG must be called before Final so OpenSSL knows what to verify.
     * The cast to void* is required by the EVP_CIPHER_CTX_ctrl API; the tag
     * buffer is only read, not written.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_size,
                            (void *)tag) != 1) {
        goto done;
    }

    /*
     * EVP_DecryptFinal_ex verifies the GCM authentication tag. A return value
     * of 0 means tag mismatch (or any other Final-stage failure). The != 1
     * check routes tag-mismatch into the fail-closed epilogue below, which
     * zeros data_out so that unauthenticated plaintext is never visible to
     * callers.
     *
     * GCM Final always produces 0 additional bytes; the canonical
     * Update+Final accumulation pattern is kept for robustness.
     */
    if (EVP_DecryptFinal_ex(ctx, (data_out != NULL) ? (data_out + total_len) : NULL,
                            &out_len) != 1) {
        goto done;
    }
    total_len += out_len;

    ret_value = true;

done:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);

    if (!ret_value) {
        /*
         * Zero the output buffer unconditionally on any failure path.
         * EVP_DecryptUpdate may have written tentative plaintext into
         * data_out before tag verification failed — those bytes are
         * unauthenticated and must not be visible to the caller.
         */
        if (data_out != NULL && data_in_size > 0) {
            libspdm_zero_mem(data_out, data_in_size);
        }
        if (data_out_size != NULL) {
            *data_out_size = 0;
        }
    } else {
        if (data_out_size != NULL) {
            *data_out_size = data_in_size;
        }
    }

    return ret_value;
}
