/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Shang-Mi2 Asymmetric Wrapper Implementation.
 *
 * OpenSSL 3.x provider-correct implementation. All DSA functions operate on
 * a private libspdm_sm2_ctx_t wrapper that owns an EVP_PKEY*, enabling
 * provider-correct key import (fromdata + public_check) and key regeneration
 * (generate + swap) without touching the public void* ABI.
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

bool libspdm_test_ecc_sig_bin_to_der(const uint8_t *signature, size_t sig_size,
                                     uint8_t *der, size_t *der_len_in_out);

/* SM2 public key size: 32-byte X coordinate + 32-byte Y coordinate. */
#define SM2_COORD_SIZE     32U
#define SM2_PUB_KEY_SIZE   64U  /* SM2_COORD_SIZE * 2 */
/* DER overhead for two 33-byte INTEGERs inside a SEQUENCE. */
#define SM2_DER_SIG_MAX_SIZE  ((SM2_COORD_SIZE + 1U) * 2U + 6U)

/* =========================================================================
 * Private wrapper context (file-static, never exposed in any header).
 *
 * Callers see only opaque void*.  The wrapper allows set_pub_key and
 * generate_key to replace the inner EVP_PKEY via fromdata/generate-and-swap
 * without an ABI break (no void** needed in the public API).
 * =========================================================================*/

typedef struct {
    uint32_t magic;
    EVP_PKEY *pkey;
} libspdm_sm2_ctx_t;

#define LIBSPDM_SM2_CTX_MAGIC 0x534D3243u /* "SM2C" */

/**
 * Returns the inner EVP_PKEY* from an opaque sm2_context pointer.
 * Returns NULL when sm2_context is NULL.
 **/
static EVP_PKEY *sm2_pkey(const void *ctx)
{
    const libspdm_sm2_ctx_t *wrapper;
    if (ctx == NULL) {
        return NULL;
    }
    wrapper = (const libspdm_sm2_ctx_t *)ctx;
    if (wrapper->magic == LIBSPDM_SM2_CTX_MAGIC) {
        return wrapper->pkey;
    }
    /* Backward-compatibility path: some parsers still return raw EVP_PKEY*. */
    return (EVP_PKEY *)ctx;
}

/**
 * Returns true when pkey is an SM2 key, false otherwise (including NULL).
 *
 * Uses EVP_PKEY_is_a() on OpenSSL 3.x (the canonical provider-aware test)
 * and falls back to EVP_PKEY_id() on older builds.  An explicit NULL guard
 * is required because both EVP_PKEY_is_a(NULL,...) and EVP_PKEY_id(NULL)
 * dereference the pointer internally.
 **/
static bool sm2_pkey_is_sm2(const EVP_PKEY *pkey)
{
    const EC_KEY *ec_key;
    const EC_GROUP *ec_group;
    int curve_nid;

    if (pkey == NULL) {
        return false;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (EVP_PKEY_is_a(pkey, "SM2") == 1) {
        return true;
    }
#endif
    if (EVP_PKEY_id(pkey) == EVP_PKEY_SM2) {
        return true;
    }
    if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
        ec_key = EVP_PKEY_get0_EC_KEY((EVP_PKEY *)pkey);
        if (ec_key == NULL) {
            return false;
        }
        ec_group = EC_KEY_get0_group(ec_key);
        if (ec_group == NULL) {
            return false;
        }
        curve_nid = EC_GROUP_get_curve_name(ec_group);
        if (curve_nid == NID_sm2) {
            return true;
        }
    }
    return false;
}

/* =========================================================================
 * DER signature codec (safe OpenSSL 3.x implementation).
 *
 * Phase 2: replaced the old hand-rolled parsers that used LIBSPDM_ASSERT for
 * input validation (unsafe when asserts are compiled out on attacker-supplied
 * peer DER).  Now delegates to d2i_ECDSA_SIG / i2d_ECDSA_SIG.
 * =========================================================================*/

/**
 * Converts a DER-encoded ECDSA/SM2 signature to the raw R||S binary form
 * used by libspdm (each component zero-padded to half_size bytes).
 *
 * Returns true on success, false on any malformed input.
 * Not declared static so unit tests can exercise it directly with crafted DER.
 **/
bool ecc_sig_der_to_bin(const uint8_t *der, size_t der_len,
                               uint8_t *signature, size_t sig_size)
{
    const uint8_t *der_ptr = der;
    const BIGNUM *bn_r = NULL;
    const BIGNUM *bn_s = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    size_t half_size = 0;
    bool ret_val = false;

    ecdsa_sig = d2i_ECDSA_SIG(NULL, &der_ptr, (long)der_len);
    if (ecdsa_sig == NULL) {
        return false;
    }
    ECDSA_SIG_get0(ecdsa_sig, &bn_r, &bn_s);
    half_size = sig_size / 2;
    if ((BN_bn2binpad(bn_r, signature, (int)half_size) == (int)half_size) &&
        (BN_bn2binpad(bn_s, signature + half_size, (int)half_size) == (int)half_size)) {
        ret_val = true;
    }
    ECDSA_SIG_free(ecdsa_sig);
    return ret_val;
}

/**
 * Converts the raw R||S binary form (each component zero-padded to half_size)
 * to DER-encoded ECDSA/SM2 signature.
 *
 * Returns true on success, false on allocation failure, malformed input,
 * or if the output buffer is too small.  On any failure path *der_len_in_out
 * and the contents of *der are left unchanged.
 *
 * Implementation note: i2d_ECDSA_SIG(sig, &p) writes into *p as soon as p is
 * non-NULL, so the size check MUST happen before the write.  We use the
 * canonical OpenSSL two-call pattern: first i2d_ECDSA_SIG(sig, NULL) to query
 * the required encoded length, then validate against the caller's buffer,
 * then do the actual serialization.
 **/
static bool ecc_sig_bin_to_der(const uint8_t *signature, size_t sig_size,
                               uint8_t *der, size_t *der_len_in_out)
{
    size_t half_size = 0;
    BIGNUM *bn_r = NULL;
    BIGNUM *bn_s = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    uint8_t *der_out = NULL;
    int required_len = 0;
    int encoded_len = 0;
    bool ret_val = false;

    if (signature == NULL || der == NULL || der_len_in_out == NULL ||
        sig_size == 0U || (sig_size & 1U) != 0U) {
        return false;
    }

    half_size = sig_size / 2;
    bn_r = BN_bin2bn(signature, (int)half_size, NULL);
    bn_s = BN_bin2bn(signature + half_size, (int)half_size, NULL);
    ecdsa_sig = ECDSA_SIG_new();
    if (bn_r == NULL || bn_s == NULL || ecdsa_sig == NULL) {
        goto done;
    }

    if (ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s) != 1) {
        goto done;
    }
    /* set0 took ownership on success; null out so cleanup doesn't double-free. */
    bn_r = NULL;
    bn_s = NULL;

    /* Size query first — passing NULL means "return required length, no write". */
    required_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
    if (required_len <= 0 || (size_t)required_len > *der_len_in_out) {
        goto done;
    }

    der_out = der;
    encoded_len = i2d_ECDSA_SIG(ecdsa_sig, &der_out);
    if (encoded_len != required_len) {
        goto done;
    }

    *der_len_in_out = (size_t)encoded_len;
    ret_val = true;

done:
    /* BN_free / ECDSA_SIG_free are NULL-safe. */
    BN_free(bn_r);
    BN_free(bn_s);
    ECDSA_SIG_free(ecdsa_sig);
    return ret_val;
}

/**
 * Unit-test helper: exposes raw-RS to DER conversion validation for negative tests.
 *
 * This function intentionally forwards to the internal helper so tests can verify
 * fail-closed behavior (especially undersized output buffers) without duplicating
 * DER conversion logic in test code.
 **/
bool libspdm_test_ecc_sig_bin_to_der(const uint8_t *signature, size_t sig_size,
                                     uint8_t *der, size_t *der_len_in_out)
{
    return ecc_sig_bin_to_der(signature, sig_size, der, der_len_in_out);
}

/* =========================================================================
 * SM2-DSA public API
 * =========================================================================*/

/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID (ignored; SM2 has a fixed curve)
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *          If the allocations fails, sm2_new_by_nid() returns NULL.
 *
 **/
void *libspdm_sm2_dsa_new_by_nid(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int32_t result = 0;
    libspdm_sm2_ctx_t *ctx = NULL;

    (void)nid; /* SM2 has a fixed curve; NID is not used. */

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (pkey_ctx == NULL) {
        return NULL;
    }
    result = EVP_PKEY_keygen_init(pkey_ctx);
    if (result <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    result = EVP_PKEY_generate(pkey_ctx, &pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    if (result <= 0 || pkey == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    ctx = (libspdm_sm2_ctx_t *)allocate_zero_pool(sizeof(*ctx));
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    ctx->magic = LIBSPDM_SM2_CTX_MAGIC;
    ctx->pkey = pkey;
    return (void *)ctx;
}

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 *
 **/
void libspdm_sm2_dsa_free(void *sm2_context)
{
    libspdm_sm2_ctx_t *ctx = (libspdm_sm2_ctx_t *)sm2_context;
    EVP_PKEY *pkey;

    if (ctx == NULL) {
        return;
    }
    if (ctx->magic != LIBSPDM_SM2_CTX_MAGIC) {
        /* Backward-compatibility path for raw EVP_PKEY* contexts. */
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_sm2_dsa_free: legacy raw EVP_PKEY context=%p\n",
                       sm2_context));
        EVP_PKEY_free((EVP_PKEY *)sm2_context);
        return;
    }
    pkey = ctx->pkey;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "libspdm_sm2_dsa_free: enter ctx=%p pkey=%p\n",
                   ctx, pkey));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "libspdm_sm2_dsa_free: calling EVP_PKEY_free pkey=%p\n",
                   pkey));
    EVP_PKEY_free(pkey);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "libspdm_sm2_dsa_free: EVP_PKEY_free done\n"));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "libspdm_sm2_dsa_free: calling free_pool ctx=%p\n",
                   ctx));
    free_pool(ctx);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "libspdm_sm2_dsa_free: free_pool done\n"));
}

/**
 * Sets the public key component into the established sm2 context.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 * The key is validated to be on the SM2 curve before being imported.
 * If validation fails, the existing context key is left unchanged.
 *
 * @param[in, out]  ec_context      Pointer to sm2 context being set.
 * @param[in]       public         Pointer to the buffer to receive generated public X,Y.
 * @param[in]       public_size     The size of public buffer in bytes.
 *
 * @retval  true   sm2 public key component was set successfully.
 * @retval  false  Invalid sm2 public key component.
 *
 **/
bool libspdm_sm2_dsa_set_pub_key(void *sm2_context, const uint8_t *public_key,
                                 size_t public_key_size)
{
    libspdm_sm2_ctx_t *ctx = (libspdm_sm2_ctx_t *)sm2_context;
    uint8_t pub_uncompressed[1 + SM2_PUB_KEY_SIZE];
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *new_pkey = NULL;
    EVP_PKEY_CTX *fromdata_ctx = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;
    bool ret_val = false;

    if (ctx == NULL || public_key == NULL) {
        return false;
    }
    if (public_key_size != SM2_PUB_KEY_SIZE) {
        return false;
    }
    if (!sm2_pkey_is_sm2(ctx->pkey)) {
        return false;
    }

    /* Build uncompressed EC point: 0x04 || X || Y */
    pub_uncompressed[0] = 0x04;
    libspdm_copy_mem(pub_uncompressed + 1, sizeof(pub_uncompressed) - 1,
                     public_key, SM2_PUB_KEY_SIZE);

    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        return false;
    }
    if (OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        "SM2", 0) <= 0 ||
        OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         pub_uncompressed,
                                         sizeof(pub_uncompressed)) <= 0) {
        OSSL_PARAM_BLD_free(param_bld);
        return false;
    }
    params = OSSL_PARAM_BLD_to_param(param_bld);
    OSSL_PARAM_BLD_free(param_bld);
    if (params == NULL) {
        return false;
    }

    fromdata_ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if ((fromdata_ctx != NULL) &&
        (EVP_PKEY_fromdata_init(fromdata_ctx) > 0) &&
        (EVP_PKEY_fromdata(fromdata_ctx, &new_pkey,
                           EVP_PKEY_PUBLIC_KEY, params) > 0)) {
        ret_val = true;
    }
    EVP_PKEY_CTX_free(fromdata_ctx);
    OSSL_PARAM_free(params);

    /*
     * CRITICAL: EVP_PKEY_fromdata validates the DER encoding but does NOT
     * perform a point-on-curve check by default.  Call EVP_PKEY_public_check
     * explicitly to reject off-curve, all-zero, and malformed points that
     * could be supplied by a malicious SPDM peer.
     */
    if (ret_val) {
        check_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, new_pkey, NULL);
        if ((check_ctx != NULL) && (EVP_PKEY_public_check(check_ctx) == 1)) {
            ret_val = true;
        } else {
            ret_val = false;
        }
        EVP_PKEY_CTX_free(check_ctx);
    }

    if (ret_val) {
        EVP_PKEY_free(ctx->pkey);
        ctx->pkey = new_pkey;   /* swap: atomically replaces the key */
    } else {
        EVP_PKEY_free(new_pkey);
    }
    return ret_val;
}

/**
 * Gets the public key component from the established sm2 context.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * @param[in, out]  sm2_context     Pointer to sm2 context being set.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   sm2 key component was retrieved successfully.
 * @retval  false  Invalid sm2 key component.
 *
 **/
bool libspdm_sm2_dsa_get_pub_key(void *sm2_context, uint8_t *public_key,
                                 size_t *public_key_size)
{
    EVP_PKEY *pkey = NULL;
    uint8_t pub_uncompressed[1 + SM2_PUB_KEY_SIZE];
    size_t out_len = 0;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *ec_group = NULL;
    const EC_POINT *ec_pub = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *tmp_pub = NULL;
    const BIGNUM *ec_priv = NULL;
    size_t ec_oct_len = 0;

    if (sm2_context == NULL || public_key_size == NULL) {
        return false;
    }
    if (public_key == NULL && *public_key_size != 0) {
        return false;
    }

    pkey = sm2_pkey(sm2_context);
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }

    if (*public_key_size < SM2_PUB_KEY_SIZE) {
        *public_key_size = SM2_PUB_KEY_SIZE;
        return false;
    }
    *public_key_size = SM2_PUB_KEY_SIZE;

    if (public_key == NULL) {
        return true;
    }

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub_uncompressed,
                                        sizeof(pub_uncompressed),
                                        &out_len) <= 0 ||
        out_len != sizeof(pub_uncompressed) || pub_uncompressed[0] != 0x04) {
        /* Some OpenSSL EC/SM2 private-key contexts may not expose PUB_KEY via OSSL_PARAM.
         * Fall back to extracting/deriving the EC public point directly. */
        ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        if (ec_key == NULL) {
            return false;
        }
        ec_group = EC_KEY_get0_group(ec_key);
        ec_pub = EC_KEY_get0_public_key(ec_key);
        if (ec_group == NULL) {
            EC_KEY_free(ec_key);
            return false;
        }
        if (ec_pub == NULL) {
            ec_priv = EC_KEY_get0_private_key(ec_key);
            if (ec_priv == NULL) {
                EC_KEY_free(ec_key);
                return false;
            }
            tmp_pub = EC_POINT_new(ec_group);
            bn_ctx = BN_CTX_new();
            if (tmp_pub == NULL || bn_ctx == NULL ||
                EC_POINT_mul(ec_group, tmp_pub, ec_priv, NULL, NULL, bn_ctx) != 1) {
                EC_POINT_free(tmp_pub);
                BN_CTX_free(bn_ctx);
                EC_KEY_free(ec_key);
                return false;
            }
            ec_pub = tmp_pub;
        }

        ec_oct_len = EC_POINT_point2oct(ec_group, ec_pub,
                                        POINT_CONVERSION_UNCOMPRESSED,
                                        pub_uncompressed, sizeof(pub_uncompressed), bn_ctx);
        EC_POINT_free(tmp_pub);
        BN_CTX_free(bn_ctx);
        EC_KEY_free(ec_key);
        if (ec_oct_len != sizeof(pub_uncompressed) || pub_uncompressed[0] != 0x04) {
            return false;
        }
    }

    libspdm_copy_mem(public_key, *public_key_size,
                     pub_uncompressed + 1, SM2_PUB_KEY_SIZE);
    return true;
}

bool libspdm_sm2_dsa_get_priv_key(void *sm2_context, uint8_t *private_key,
                                  size_t *private_key_size)
{
    EVP_PKEY *pkey;
    BIGNUM *priv_bn;
    bool ret_val;

    if (sm2_context == NULL || private_key_size == NULL) {
        return false;
    }
    if (private_key == NULL && *private_key_size != 0) {
        return false;
    }
    if (*private_key_size < SM2_COORD_SIZE) {
        *private_key_size = SM2_COORD_SIZE;
        return false;
    }
    *private_key_size = SM2_COORD_SIZE;

    pkey = sm2_pkey(sm2_context);
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }
    if (private_key == NULL) {
        return true;
    }

    priv_bn = NULL;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) <= 0 ||
        priv_bn == NULL) {
        BN_clear_free(priv_bn);
        return false;
    }
    ret_val = (BN_bn2binpad(priv_bn, private_key, SM2_COORD_SIZE) == SM2_COORD_SIZE);
    BN_clear_free(priv_bn);
    return ret_val;
}

/**
 * Validates key components of sm2 context.
 * NOTE: This function performs integrity checks on all the sm2 key material, so
 *      the sm2 key structure must contain all the private key data.
 *
 * If sm2_context is NULL, then return false.
 *
 * @param[in]  sm2_context  Pointer to sm2 context to check.
 *
 * @retval  true   sm2 key components are valid.
 * @retval  false  sm2 key components are not valid.
 *
 **/
bool libspdm_sm2_dsa_check_key(const void *sm2_context)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;
    bool ret_val = false;

    if (sm2_context == NULL) {
        return false;
    }

    pkey = sm2_pkey(sm2_context);
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }

    check_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if ((check_ctx != NULL) && (EVP_PKEY_pairwise_check(check_ctx) == 1)) {
        ret_val = true;
    }
    EVP_PKEY_CTX_free(check_ctx);
    return ret_val;
}

/**
 * Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * X is the first half of public with size being public_size / 2,
 * Y is the second half of public with size being public_size / 2.
 * sm2 context is updated accordingly.
 * If the public buffer is too small to hold the public X, Y, false is returned and
 * public_size is set to the required buffer size to obtain the public X, Y.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * If sm2_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  sm2_context     Pointer to the sm2 context.
 * @param[out]      public_data     Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   sm2 public X,Y generation succeeded.
 * @retval false  sm2 public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_sm2_dsa_generate_key(void *sm2_context, uint8_t *public_data,
                                  size_t *public_size)
{
    libspdm_sm2_ctx_t *ctx = (libspdm_sm2_ctx_t *)sm2_context;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *new_pkey = NULL;
    int32_t result = 0;
    uint8_t pub_uncompressed[1 + SM2_PUB_KEY_SIZE];
    size_t out_len = 0;

    if (ctx == NULL || public_size == NULL) {
        return false;
    }
    if (public_data == NULL && *public_size != 0) {
        return false;
    }
    if (!sm2_pkey_is_sm2(ctx->pkey)) {
        return false;
    }

    if (*public_size < SM2_PUB_KEY_SIZE) {
        *public_size = SM2_PUB_KEY_SIZE;
        return false;
    }
    *public_size = SM2_PUB_KEY_SIZE;

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (pkey_ctx == NULL) {
        return false;
    }
    result = EVP_PKEY_keygen_init(pkey_ctx);
    if (result <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    result = EVP_PKEY_generate(pkey_ctx, &new_pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    if (result <= 0 || new_pkey == NULL) {
        EVP_PKEY_free(new_pkey);
        return false;
    }

    EVP_PKEY_free(ctx->pkey);
    ctx->pkey = new_pkey;

    if (public_data == NULL) {
        return true;
    }

    if (EVP_PKEY_get_octet_string_param(ctx->pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub_uncompressed,
                                        sizeof(pub_uncompressed),
                                        &out_len) <= 0 ||
        out_len != sizeof(pub_uncompressed) || pub_uncompressed[0] != 0x04) {
        return false;
    }

    libspdm_zero_mem(public_data, *public_size);
    libspdm_copy_mem(public_data, *public_size,
                     pub_uncompressed + 1, SM2_PUB_KEY_SIZE);
    return true;
}

/* =========================================================================
 * SM2 key-exchange fallback path
 *
 * Full GB/T 32918.3 support lives in sm2_kex_adapter.c and is compiled when
 * LIBSPDM_SM2_KEY_EXCHANGE_FULL_GBT_32918_3_SUPPORT is enabled.
 *
 * The functions below are retained only as the explicit fallback behavior when
 * that flag is disabled at build time; they intentionally return false.
 * =========================================================================*/
#if !LIBSPDM_SM2_KEY_EXCHANGE_FULL_GBT_32918_3_SUPPORT

/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *          If the allocations fails, sm2_new_by_nid() returns NULL.
 *
 **/
void *libspdm_sm2_key_exchange_new_by_nid(size_t nid)
{
    (void)nid;
    /* Build-time fallback when full GB/T 32918.3 support is disabled. */
    return NULL;
}

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 *
 **/
void libspdm_sm2_key_exchange_free(void *sm2_context)
{
    (void)sm2_context;
    /* Build-time fallback when full GB/T 32918.3 support is disabled. */
}

/**
 * Initialize the specified sm2 context.
 *
 * @param[in]  sm2_context   Pointer to the sm2 context.
 * @param[in]  hash_nid      hash NID, only SM3 is valid.
 * @param[in]  id_a          the ID-A of the key exchange context.
 * @param[in]  id_a_size     size of ID-A key exchange context.
 * @param[in]  id_b          the ID-B of the key exchange context.
 * @param[in]  id_b_size     size of ID-B key exchange context.
 * @param[in]  is_initiator  if the caller is initiator.
 *
 * @retval true   sm2 context is initialized.
 * @retval false  sm2 context is not initialized.
 **/
bool libspdm_sm2_key_exchange_init(void *sm2_context, size_t hash_nid,
                                   const uint8_t *id_a, size_t id_a_size,
                                   const uint8_t *id_b, size_t id_b_size,
                                   bool is_initiator)
{
    (void)sm2_context;
    (void)hash_nid;
    (void)id_a;
    (void)id_a_size;
    (void)id_b;
    (void)id_b_size;
    (void)is_initiator;
    /* Build-time fallback when full GB/T 32918.3 support is disabled. */
    return false;
}

/**
 * Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * @param[in, out]  sm2_context     Pointer to the sm2 context.
 * @param[out]      public_data     Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   sm2 public X,Y generation succeeded.
 * @retval false  sm2 public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_sm2_key_exchange_generate_key(void *sm2_context, uint8_t *public_data,
                                           size_t *public_size)
{
    (void)sm2_context;
    (void)public_data;
    (void)public_size;
    /* Build-time fallback when full GB/T 32918.3 support is disabled. */
    return false;
}

/**
 * Computes exchanged common key, based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * @param[in, out]  sm2_context       Pointer to the sm2 context.
 * @param[in]       peer_public       Pointer to the peer's public X,Y.
 * @param[in]       peer_public_size  Size of peer's public X,Y in bytes.
 * @param[out]      key               Pointer to the buffer to receive generated key.
 * @param[in]       key_size          On input, the size of key buffer in bytes.
 *
 * @retval true   sm2 exchanged key generation succeeded.
 * @retval false  sm2 exchanged key generation failed.
 *
 **/
bool libspdm_sm2_key_exchange_compute_key(void *sm2_context,
                                          const uint8_t *peer_public,
                                          size_t peer_public_size, uint8_t *key,
                                          size_t *key_size)
{
    (void)sm2_context;
    (void)peer_public;
    (void)peer_public_size;
    (void)key;
    (void)key_size;
    /* Build-time fallback when full GB/T 32918.3 support is disabled. */
    return false;
}
#endif /* !LIBSPDM_SM2_KEY_EXCHANGE_FULL_GBT_32918_3_SUPPORT */

/* =========================================================================
 * SM2-DSA sign / verify
 *
 * Invariant I1 (must not be regressed): the SM2 user ID must be set on the
 * EVP_PKEY_CTX BEFORE attaching it to the EVP_MD_CTX, and the EVP_MD_CTX
 * must be configured BEFORE calling EVP_DigestSignInit/EVP_DigestVerifyInit:
 *
 *   1. pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL)
 *   2. if (id_a_size != 0) EVP_PKEY_CTX_set1_id(pkey_ctx, id_a, id_a_size)
 *   3. EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx)
 *   4. EVP_DigestSignInit / EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey)
 *
 * Reordering steps 2/3/4 produces signatures that look structurally valid
 * but fail verification because Z_A is computed from the wrong ID.
 * =========================================================================*/

/**
 * Carries out the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.
 *
 * This function carries out the SM2 signature.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If sm2_context is NULL, then return false.
 * If message is NULL, then return false.
 * hash_nid must be SM3_256.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * The id_a_size must be smaller than 2^16-1.
 * The sig_size is 64. first 32-byte is R, second 32-byte is S.
 *
 * @param[in]       sm2_context   Pointer to sm2 context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       id_a          the ID-A of the signing context.
 * @param[in]       id_a_size     size of ID-A signing context.
 * @param[in]       message      Pointer to octet message to be signed (before hash).
 * @param[in]       size         size of the message in bytes.
 * @param[out]      signature    Pointer to buffer to receive SM2 signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in SM2.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_sm2_dsa_sign(const void *sm2_context, size_t hash_nid,
                          const uint8_t *id_a, size_t id_a_size,
                          const uint8_t *message, size_t size,
                          uint8_t *signature, size_t *sig_size)
{
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    size_t half_size = 0;
    int32_t result = 0;
    uint8_t der_signature[SM2_DER_SIG_MAX_SIZE];
    size_t der_sig_size = 0;

    if (sm2_context == NULL || message == NULL) {
        return false;
    }
    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    pkey = sm2_pkey(sm2_context);
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }
    half_size = SM2_COORD_SIZE;

    if (*sig_size < half_size * 2U) {
        *sig_size = half_size * 2U;
        return false;
    }
    *sig_size = half_size * 2U;
    libspdm_zero_mem(signature, *sig_size);

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SM3_256:
        break;
    default:
        return false;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return false;
    }
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    /* Invariant I1 step 2: set SM2 user ID before attaching ctx. */
    if (id_a_size != 0) {
        result = EVP_PKEY_CTX_set1_id(pkey_ctx, id_a, (int)id_a_size);
        if (result <= 0) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }
    }

    /* Invariant I1 step 3: attach before DigestSignInit. */
    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

    /* Invariant I1 step 4. */
    result = EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);
    if (result != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    der_sig_size = sizeof(der_signature);
    result = EVP_DigestSign(md_ctx, der_signature, &der_sig_size, message, size);
    if (result != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);

    if (!ecc_sig_der_to_bin(der_signature, der_sig_size, signature, *sig_size)) {
        return false;
    }

    return true;
}

/**
 * Verifies the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.
 *
 * If sm2_context is NULL, then return false.
 * If message is NULL, then return false.
 * If signature is NULL, then return false.
 * hash_nid must be SM3_256.
 *
 * The id_a_size must be smaller than 2^16-1.
 * The sig_size is 64. first 32-byte is R, second 32-byte is S.
 *
 * @param[in]  sm2_context   Pointer to SM2 context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  id_a          the ID-A of the signing context.
 * @param[in]  id_a_size     size of ID-A signing context.
 * @param[in]  message      Pointer to octet message to be checked (before hash).
 * @param[in]  size         size of the message in bytes.
 * @param[in]  signature    Pointer to SM2 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in SM2.
 * @retval  false  Invalid signature or invalid sm2 context.
 *
 **/
bool libspdm_sm2_dsa_verify(const void *sm2_context, size_t hash_nid,
                            const uint8_t *id_a, size_t id_a_size,
                            const uint8_t *message, size_t size,
                            const uint8_t *signature, size_t sig_size)
{
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    size_t half_size = 0;
    int32_t result = 0;
    uint8_t der_signature[SM2_DER_SIG_MAX_SIZE];
    size_t der_sig_size = 0;

    if (sm2_context == NULL || message == NULL || signature == NULL) {
        return false;
    }
    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    pkey = sm2_pkey(sm2_context);
    if (!sm2_pkey_is_sm2(pkey)) {
        return false;
    }
    half_size = SM2_COORD_SIZE;

    if (sig_size != half_size * 2U) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SM3_256:
        break;
    default:
        return false;
    }

    der_sig_size = sizeof(der_signature);
    if (!ecc_sig_bin_to_der((uint8_t *)signature, sig_size,
                            der_signature, &der_sig_size)) {
        return false;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return false;
    }
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    /* Invariant I1 step 2: set SM2 user ID before attaching ctx. */
    if (id_a_size != 0) {
        result = EVP_PKEY_CTX_set1_id(pkey_ctx, id_a, (int)id_a_size);
        if (result <= 0) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }
    }

    /* Invariant I1 step 3: attach before DigestVerifyInit. */
    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

    /* Invariant I1 step 4. */
    result = EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);
    if (result != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    result = EVP_DigestVerify(md_ctx, der_signature, der_sig_size, message, size);
    if (result != 1) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    return true;
}
