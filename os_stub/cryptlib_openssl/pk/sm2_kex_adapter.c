/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_crypt_lib.h"

#if LIBSPDM_SM2_KEY_EXCHANGE_FULL_GBT_32918_3_SUPPORT

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#define SM2_COORD_SIZE      32U
#define SM2_PUB_SIZE        (SM2_COORD_SIZE * 2U)
#define SM2_MAX_ID_LEN      8191U
#ifndef LIBSPDM_SM2_KEX_TEST_HOOKS
#define LIBSPDM_SM2_KEX_TEST_HOOKS 0
#endif

typedef struct {
    EC_GROUP *group;
    BIGNUM *order;
    bool initialized;
    bool is_initiator;

    uint8_t *id_a;
    size_t id_a_size;
    uint8_t *id_b;
    size_t id_b_size;

    BIGNUM *own_static_priv;
    EC_POINT *own_static_pub;
    EC_POINT *peer_static_pub;

    BIGNUM *own_eph_priv;
    EC_POINT *own_eph_pub;

    bool static_priv_set;
    bool static_pub_self_set;
    bool static_pub_peer_set;
} libspdm_sm2_kex_ctx_t;

static void sm2_kex_zero_and_free(uint8_t *ptr, size_t size)
{
    if (ptr != NULL) {
        libspdm_zero_mem(ptr, size);
        free_pool(ptr);
    }
}

static void sm2_kex_free_point(EC_POINT *point)
{
    EC_POINT_free(point);
}

static bool sm2_kex_bn_to_fixed32(const BIGNUM *bn, uint8_t out[SM2_COORD_SIZE])
{
    return (BN_bn2binpad(bn, out, SM2_COORD_SIZE) == SM2_COORD_SIZE);
}

static bool sm2_kex_import_public_xy(libspdm_sm2_kex_ctx_t *ctx,
                                     const uint8_t *pub_xy, size_t pub_xy_size,
                                     EC_POINT **out_point)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    EC_POINT *point = NULL;
    BN_CTX *bn_ctx = NULL;
    bool ret = false;

    if ((ctx == NULL) || (pub_xy == NULL) || (out_point == NULL) ||
        (pub_xy_size != SM2_PUB_SIZE)) {
        return false;
    }

    x = BN_bin2bn(pub_xy, SM2_COORD_SIZE, NULL);
    y = BN_bin2bn(pub_xy + SM2_COORD_SIZE, SM2_COORD_SIZE, NULL);
    point = EC_POINT_new(ctx->group);
    bn_ctx = BN_CTX_new();
    if ((x == NULL) || (y == NULL) || (point == NULL) || (bn_ctx == NULL)) {
        goto done;
    }

    if (EC_POINT_set_affine_coordinates(ctx->group, point, x, y, bn_ctx) != 1) {
        goto done;
    }
    if (EC_POINT_is_on_curve(ctx->group, point, bn_ctx) != 1) {
        goto done;
    }
    if (EC_POINT_is_at_infinity(ctx->group, point) == 1) {
        goto done;
    }

    *out_point = point;
    point = NULL;
    ret = true;

done:
    BN_free(x);
    BN_free(y);
    sm2_kex_free_point(point);
    BN_CTX_free(bn_ctx);
    return ret;
}

static bool sm2_kex_export_public_xy(libspdm_sm2_kex_ctx_t *ctx,
                                     const EC_POINT *point,
                                     uint8_t *pub_xy, size_t *pub_xy_size)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *bn_ctx = NULL;
    bool ret = false;

    if ((ctx == NULL) || (point == NULL) || (pub_xy_size == NULL)) {
        return false;
    }
    if (*pub_xy_size < SM2_PUB_SIZE) {
        *pub_xy_size = SM2_PUB_SIZE;
        return false;
    }
    if (pub_xy == NULL) {
        *pub_xy_size = SM2_PUB_SIZE;
        return false;
    }

    x = BN_new();
    y = BN_new();
    bn_ctx = BN_CTX_new();
    if ((x == NULL) || (y == NULL) || (bn_ctx == NULL)) {
        goto done;
    }

    if (EC_POINT_get_affine_coordinates(ctx->group, point, x, y, bn_ctx) != 1) {
        goto done;
    }
    if (!sm2_kex_bn_to_fixed32(x, pub_xy) ||
        !sm2_kex_bn_to_fixed32(y, pub_xy + SM2_COORD_SIZE)) {
        goto done;
    }

    *pub_xy_size = SM2_PUB_SIZE;
    ret = true;

done:
    BN_free(x);
    BN_free(y);
    BN_CTX_free(bn_ctx);
    return ret;
}

static bool sm2_kex_sm3_hash(const uint8_t *in1, size_t in1_size,
                             const uint8_t *in2, size_t in2_size,
                             uint8_t out[LIBSPDM_MAX_HASH_SIZE])
{
    EVP_MD_CTX *md_ctx;
    bool ret = false;
    unsigned int out_size = 0;

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return false;
    }

    if ((EVP_DigestInit_ex(md_ctx, EVP_sm3(), NULL) == 1) &&
        ((in1_size == 0) || (EVP_DigestUpdate(md_ctx, in1, in1_size) == 1)) &&
        ((in2_size == 0) || (EVP_DigestUpdate(md_ctx, in2, in2_size) == 1)) &&
        (EVP_DigestFinal_ex(md_ctx, out, &out_size) == 1) &&
        (out_size == 32)) {
        ret = true;
    }

    EVP_MD_CTX_free(md_ctx);
    return ret;
}

static bool sm2_kex_sm3_kdf(const uint8_t *input, size_t input_size,
                            uint8_t *out_key, size_t out_size)
{
    uint8_t digest[32];
    uint8_t ct_be[4];
    size_t copied = 0;
    uint32_t ct = 1;
    size_t to_copy;

    if ((input == NULL) || (out_key == NULL) || (out_size == 0)) {
        return false;
    }

    while (copied < out_size) {
        ct_be[0] = (uint8_t)((ct >> 24) & 0xFF);
        ct_be[1] = (uint8_t)((ct >> 16) & 0xFF);
        ct_be[2] = (uint8_t)((ct >> 8) & 0xFF);
        ct_be[3] = (uint8_t)(ct & 0xFF);

        if (!sm2_kex_sm3_hash(input, input_size, ct_be, sizeof(ct_be), digest)) {
            libspdm_zero_mem(digest, sizeof(digest));
            return false;
        }
        to_copy = ((out_size - copied) > sizeof(digest)) ? sizeof(digest) : (out_size - copied);
        libspdm_copy_mem(out_key + copied, out_size - copied, digest, to_copy);
        copied += to_copy;
        ct++;
    }

    libspdm_zero_mem(digest, sizeof(digest));
    return true;
}

static bool sm2_kex_compute_za(const uint8_t *id, size_t id_size,
                               const uint8_t pub_xy[SM2_PUB_SIZE],
                               uint8_t out_za[32])
{
    static const uint8_t sm2_a[32] = {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
    };
    static const uint8_t sm2_b[32] = {
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
        0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
        0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
        0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93
    };
    static const uint8_t sm2_gx[32] = {
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
        0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
        0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
    };
    static const uint8_t sm2_gy[32] = {
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
        0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
    };
    EVP_MD_CTX *md_ctx = NULL;
    uint8_t entl[2];
    unsigned int out_size = 0;
    bool ret = false;

    if ((id == NULL) || (pub_xy == NULL) || (out_za == NULL) ||
        (id_size == 0) || (id_size > SM2_MAX_ID_LEN)) {
        return false;
    }

    entl[0] = (uint8_t)(((id_size * 8) >> 8) & 0xFF);
    entl[1] = (uint8_t)((id_size * 8) & 0xFF);

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return false;
    }

    if ((EVP_DigestInit_ex(md_ctx, EVP_sm3(), NULL) == 1) &&
        (EVP_DigestUpdate(md_ctx, entl, sizeof(entl)) == 1) &&
        (EVP_DigestUpdate(md_ctx, id, id_size) == 1) &&
        (EVP_DigestUpdate(md_ctx, sm2_a, sizeof(sm2_a)) == 1) &&
        (EVP_DigestUpdate(md_ctx, sm2_b, sizeof(sm2_b)) == 1) &&
        (EVP_DigestUpdate(md_ctx, sm2_gx, sizeof(sm2_gx)) == 1) &&
        (EVP_DigestUpdate(md_ctx, sm2_gy, sizeof(sm2_gy)) == 1) &&
        (EVP_DigestUpdate(md_ctx, pub_xy, SM2_PUB_SIZE) == 1) &&
        (EVP_DigestFinal_ex(md_ctx, out_za, &out_size) == 1) &&
        (out_size == 32)) {
        ret = true;
    }

    EVP_MD_CTX_free(md_ctx);
    return ret;
}

static bool sm2_kex_compute_x_hat(const uint8_t x_bytes[32], uint8_t out_x_hat[32])
{
    BIGNUM *x = NULL;
    BIGNUM *mod = NULL;
    BIGNUM *mask_part = NULL;
    BIGNUM *x_hat = NULL;
    BN_CTX *bn_ctx = NULL;
    bool ret = false;

    x = BN_bin2bn(x_bytes, 32, NULL);
    mod = BN_new();
    mask_part = BN_new();
    x_hat = BN_new();
    bn_ctx = BN_CTX_new();
    if ((x == NULL) || (mod == NULL) || (mask_part == NULL) || (x_hat == NULL) || (bn_ctx == NULL)) {
        goto done;
    }

    if ((BN_one(mod) != 1) || (BN_lshift(mod, mod, 127) != 1)) {
        goto done;
    }
    if ((BN_mod(mask_part, x, mod, bn_ctx) != 1) || (BN_add(x_hat, mask_part, mod) != 1)) {
        goto done;
    }
    if (!sm2_kex_bn_to_fixed32(x_hat, out_x_hat)) {
        goto done;
    }

    ret = true;

done:
    BN_free(x);
    BN_free(mod);
    BN_free(mask_part);
    BN_free(x_hat);
    BN_CTX_free(bn_ctx);
    return ret;
}

static bool sm2_kex_scalar_from_32(libspdm_sm2_kex_ctx_t *ctx,
                                   const uint8_t scalar[32],
                                   BIGNUM **out_bn)
{
    BIGNUM *bn = NULL;

    if ((ctx == NULL) || (scalar == NULL) || (out_bn == NULL)) {
        return false;
    }

    bn = BN_bin2bn(scalar, 32, NULL);
    if (bn == NULL) {
        return false;
    }
    if (BN_is_zero(bn) || BN_is_negative(bn) || (BN_cmp(bn, ctx->order) >= 0)) {
        BN_free(bn);
        return false;
    }

    *out_bn = bn;
    return true;
}

static bool sm2_kex_copy_id(const uint8_t *id, size_t id_size, uint8_t **out_id, size_t *out_id_size)
{
    uint8_t *copy;

    if ((id == NULL) || (out_id == NULL) || (out_id_size == NULL) ||
        (id_size == 0) || (id_size > SM2_MAX_ID_LEN)) {
        return false;
    }

    copy = allocate_pool(id_size);
    if (copy == NULL) {
        return false;
    }
    libspdm_copy_mem(copy, id_size, id, id_size);
    *out_id = copy;
    *out_id_size = id_size;
    return true;
}

void *libspdm_sm2_key_exchange_new_by_nid(size_t nid)
{
    libspdm_sm2_kex_ctx_t *ctx;

    if (nid != LIBSPDM_CRYPTO_NID_SM2_KEY_EXCHANGE_P256) {
        return NULL;
    }

    ctx = allocate_zero_pool(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->group = EC_GROUP_new_by_curve_name(NID_sm2);
    ctx->order = BN_new();
    if ((ctx->group == NULL) || (ctx->order == NULL)) {
        libspdm_sm2_key_exchange_free(ctx);
        return NULL;
    }
    if (EC_GROUP_get_order(ctx->group, ctx->order, NULL) != 1) {
        libspdm_sm2_key_exchange_free(ctx);
        return NULL;
    }
    ctx->initialized = false;
    return ctx;
}

void libspdm_sm2_key_exchange_free(void *sm2_context)
{
    libspdm_sm2_kex_ctx_t *ctx;

    ctx = (libspdm_sm2_kex_ctx_t *)sm2_context;
    if (ctx == NULL) {
        return;
    }

    sm2_kex_zero_and_free(ctx->id_a, ctx->id_a_size);
    sm2_kex_zero_and_free(ctx->id_b, ctx->id_b_size);
    BN_clear_free(ctx->own_static_priv);
    sm2_kex_free_point(ctx->own_static_pub);
    sm2_kex_free_point(ctx->peer_static_pub);
    BN_clear_free(ctx->own_eph_priv);
    sm2_kex_free_point(ctx->own_eph_pub);
    BN_free(ctx->order);
    EC_GROUP_free(ctx->group);
    libspdm_zero_mem(ctx, sizeof(*ctx));
    free_pool(ctx);
}

bool libspdm_sm2_key_exchange_init(void *sm2_context, size_t hash_nid,
                                   const uint8_t *id_a, size_t id_a_size,
                                   const uint8_t *id_b, size_t id_b_size,
                                   bool is_initiator)
{
    libspdm_sm2_kex_ctx_t *ctx;
    uint8_t *new_id_a = NULL;
    uint8_t *new_id_b = NULL;
    size_t new_id_a_size = 0;
    size_t new_id_b_size = 0;

    ctx = (libspdm_sm2_kex_ctx_t *)sm2_context;
    if ((ctx == NULL) || (hash_nid != LIBSPDM_CRYPTO_NID_SM3_256)) {
        return false;
    }
    if (!sm2_kex_copy_id(id_a, id_a_size, &new_id_a, &new_id_a_size) ||
        !sm2_kex_copy_id(id_b, id_b_size, &new_id_b, &new_id_b_size)) {
        sm2_kex_zero_and_free(new_id_a, new_id_a_size);
        sm2_kex_zero_and_free(new_id_b, new_id_b_size);
        return false;
    }

    sm2_kex_zero_and_free(ctx->id_a, ctx->id_a_size);
    sm2_kex_zero_and_free(ctx->id_b, ctx->id_b_size);
    ctx->id_a = new_id_a;
    ctx->id_a_size = new_id_a_size;
    ctx->id_b = new_id_b;
    ctx->id_b_size = new_id_b_size;
    ctx->is_initiator = is_initiator;
    ctx->initialized = true;
    return true;
}

bool libspdm_sm2_key_exchange_set_static_priv(
    void *sm2_context, const uint8_t *priv_d, size_t priv_d_size)
{
    libspdm_sm2_kex_ctx_t *ctx;
    BIGNUM *new_priv = NULL;

    ctx = (libspdm_sm2_kex_ctx_t *)sm2_context;
    if ((ctx == NULL) || !ctx->initialized || (priv_d_size != 32)) {
        return false;
    }
    if (!sm2_kex_scalar_from_32(ctx, priv_d, &new_priv)) {
        return false;
    }

    BN_clear_free(ctx->own_static_priv);
    ctx->own_static_priv = new_priv;
    ctx->static_priv_set = true;
    return true;
}

bool libspdm_sm2_key_exchange_set_static_pub_self(
    void *sm2_context, const uint8_t *pub_xy, size_t pub_xy_size)
{
    libspdm_sm2_kex_ctx_t *ctx;
    EC_POINT *point = NULL;

    ctx = (libspdm_sm2_kex_ctx_t *)sm2_context;
    if ((ctx == NULL) || !ctx->initialized) {
        return false;
    }
    if (!sm2_kex_import_public_xy(ctx, pub_xy, pub_xy_size, &point)) {
        return false;
    }

    sm2_kex_free_point(ctx->own_static_pub);
    ctx->own_static_pub = point;
    ctx->static_pub_self_set = true;
    return true;
}

bool libspdm_sm2_key_exchange_set_static_pub_peer(
    void *sm2_context, const uint8_t *pub_xy, size_t pub_xy_size)
{
    libspdm_sm2_kex_ctx_t *ctx;
    EC_POINT *point = NULL;

    ctx = (libspdm_sm2_kex_ctx_t *)sm2_context;
    if ((ctx == NULL) || !ctx->initialized) {
        return false;
    }
    if (!sm2_kex_import_public_xy(ctx, pub_xy, pub_xy_size, &point)) {
        return false;
    }

    sm2_kex_free_point(ctx->peer_static_pub);
    ctx->peer_static_pub = point;
    ctx->static_pub_peer_set = true;
    return true;
}

bool libspdm_sm2_key_exchange_generate_key(void *sm2_context, uint8_t *public_data,
                                           size_t *public_size)
{
    libspdm_sm2_kex_ctx_t *ctx;
    BIGNUM *new_r = NULL;
    EC_POINT *new_r_pub = NULL;
    BN_CTX *bn_ctx = NULL;

    ctx = (libspdm_sm2_kex_ctx_t *)sm2_context;
    if ((ctx == NULL) || !ctx->initialized || (public_size == NULL)) {
        return false;
    }
    if (*public_size < SM2_PUB_SIZE) {
        *public_size = SM2_PUB_SIZE;
        return false;
    }
    if (public_data == NULL) {
        return false;
    }

    new_r = BN_new();
    new_r_pub = EC_POINT_new(ctx->group);
    bn_ctx = BN_CTX_new();
    if ((new_r == NULL) || (new_r_pub == NULL) || (bn_ctx == NULL)) {
        BN_free(new_r);
        sm2_kex_free_point(new_r_pub);
        BN_CTX_free(bn_ctx);
        return false;
    }

    do {
        if (BN_priv_rand_range(new_r, ctx->order) != 1) {
            BN_free(new_r);
            sm2_kex_free_point(new_r_pub);
            BN_CTX_free(bn_ctx);
            return false;
        }
    } while (BN_is_zero(new_r));

    if (EC_POINT_mul(ctx->group, new_r_pub, new_r, NULL, NULL, bn_ctx) != 1) {
        BN_free(new_r);
        sm2_kex_free_point(new_r_pub);
        BN_CTX_free(bn_ctx);
        return false;
    }
    if (!sm2_kex_export_public_xy(ctx, new_r_pub, public_data, public_size)) {
        BN_free(new_r);
        sm2_kex_free_point(new_r_pub);
        BN_CTX_free(bn_ctx);
        return false;
    }

    BN_clear_free(ctx->own_eph_priv);
    sm2_kex_free_point(ctx->own_eph_pub);
    ctx->own_eph_priv = new_r;
    ctx->own_eph_pub = new_r_pub;
    BN_CTX_free(bn_ctx);
    return true;
}

bool libspdm_sm2_key_exchange_compute_key(void *sm2_context,
                                          const uint8_t *peer_public,
                                          size_t peer_public_size, uint8_t *key,
                                          size_t *key_size)
{
    libspdm_sm2_kex_ctx_t *ctx;
    bool ret = false;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *peer_eph = NULL;
    EC_POINT *tmp = NULL;
    EC_POINT *u = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *x1_hat = NULL;
    BIGNUM *x2_hat = NULL;
    BIGNUM *t = NULL;
    BIGNUM *mul = NULL;
    uint8_t x_u[32];
    uint8_t y_u[32];
    uint8_t x1_bytes[32];
    uint8_t x2_bytes[32];
    uint8_t x1_hat_bytes[32];
    uint8_t x2_hat_bytes[32];
    uint8_t own_static_xy[SM2_PUB_SIZE];
    uint8_t peer_static_xy[SM2_PUB_SIZE];
    uint8_t za[32];
    uint8_t zb[32];
    uint8_t kdf_in[128];

    ctx = (libspdm_sm2_kex_ctx_t *)sm2_context;
    if ((ctx == NULL) || !ctx->initialized || (peer_public == NULL) ||
        (key == NULL) || (key_size == NULL) || (*key_size == 0)) {
        return false;
    }
    if (!ctx->static_priv_set || !ctx->static_pub_self_set || !ctx->static_pub_peer_set ||
        (ctx->own_eph_priv == NULL) || (ctx->own_eph_pub == NULL)) {
        return false;
    }

    bn_ctx = BN_CTX_new();
    peer_eph = NULL;
    tmp = EC_POINT_new(ctx->group);
    u = EC_POINT_new(ctx->group);
    x1 = BN_new();
    x2 = BN_new();
    x1_hat = NULL;
    x2_hat = NULL;
    t = BN_new();
    mul = BN_new();
    if ((bn_ctx == NULL) || (tmp == NULL) || (u == NULL) ||
        (x1 == NULL) || (x2 == NULL) || (t == NULL) || (mul == NULL)) {
        goto done;
    }

    if (!sm2_kex_import_public_xy(ctx, peer_public, peer_public_size, &peer_eph)) {
        goto done;
    }

    if ((EC_POINT_get_affine_coordinates(ctx->group, ctx->own_eph_pub, x1, NULL, bn_ctx) != 1) ||
        (EC_POINT_get_affine_coordinates(ctx->group, peer_eph, x2, NULL, bn_ctx) != 1) ||
        !sm2_kex_bn_to_fixed32(x1, x1_bytes) ||
        !sm2_kex_bn_to_fixed32(x2, x2_bytes) ||
        !sm2_kex_compute_x_hat(x1_bytes, x1_hat_bytes) ||
        !sm2_kex_compute_x_hat(x2_bytes, x2_hat_bytes)) {
        goto done;
    }

    BN_clear_free(x1_hat);
    BN_clear_free(x2_hat);
    x1_hat = NULL;
    x2_hat = NULL;
    if (!sm2_kex_scalar_from_32(ctx, x1_hat_bytes, &x1_hat) ||
        !sm2_kex_scalar_from_32(ctx, x2_hat_bytes, &x2_hat)) {
        goto done;
    }

    if ((BN_mod_mul(mul, x1_hat, ctx->own_eph_priv, ctx->order, bn_ctx) != 1) ||
        (BN_mod_add(t, ctx->own_static_priv, mul, ctx->order, bn_ctx) != 1) ||
        BN_is_zero(t)) {
        goto done;
    }

    if ((EC_POINT_mul(ctx->group, tmp, NULL, peer_eph, x2_hat, bn_ctx) != 1) ||
        (EC_POINT_add(ctx->group, tmp, tmp, ctx->peer_static_pub, bn_ctx) != 1) ||
        (EC_POINT_mul(ctx->group, u, NULL, tmp, t, bn_ctx) != 1) ||
        (EC_POINT_is_at_infinity(ctx->group, u) == 1)) {
        goto done;
    }

    {
        size_t pub_size = SM2_PUB_SIZE;
        if (!sm2_kex_export_public_xy(ctx, u, own_static_xy, &pub_size)) {
            goto done;
        }
    }
    libspdm_copy_mem(x_u, sizeof(x_u), own_static_xy, 32);
    libspdm_copy_mem(y_u, sizeof(y_u), own_static_xy + 32, 32);

    {
        size_t pub_size = SM2_PUB_SIZE;
        if (!sm2_kex_export_public_xy(ctx, ctx->own_static_pub, own_static_xy, &pub_size)) {
            goto done;
        }
        pub_size = SM2_PUB_SIZE;
        if (!sm2_kex_export_public_xy(ctx, ctx->peer_static_pub, peer_static_xy, &pub_size)) {
            goto done;
        }
    }

    if (ctx->is_initiator) {
        if (!sm2_kex_compute_za(ctx->id_a, ctx->id_a_size, own_static_xy, za) ||
            !sm2_kex_compute_za(ctx->id_b, ctx->id_b_size, peer_static_xy, zb)) {
            goto done;
        }
    } else {
        if (!sm2_kex_compute_za(ctx->id_a, ctx->id_a_size, peer_static_xy, za) ||
            !sm2_kex_compute_za(ctx->id_b, ctx->id_b_size, own_static_xy, zb)) {
            goto done;
        }
    }

    libspdm_copy_mem(kdf_in, sizeof(kdf_in), x_u, sizeof(x_u));
    libspdm_copy_mem(kdf_in + 32, sizeof(kdf_in) - 32, y_u, sizeof(y_u));
    libspdm_copy_mem(kdf_in + 64, sizeof(kdf_in) - 64, za, sizeof(za));
    libspdm_copy_mem(kdf_in + 96, sizeof(kdf_in) - 96, zb, sizeof(zb));
    ret = sm2_kex_sm3_kdf(kdf_in, sizeof(kdf_in), key, *key_size);

done:
    if (!ret) {
        libspdm_zero_mem(key, *key_size);
    }
    libspdm_zero_mem(x_u, sizeof(x_u));
    libspdm_zero_mem(y_u, sizeof(y_u));
    libspdm_zero_mem(x1_bytes, sizeof(x1_bytes));
    libspdm_zero_mem(x2_bytes, sizeof(x2_bytes));
    libspdm_zero_mem(x1_hat_bytes, sizeof(x1_hat_bytes));
    libspdm_zero_mem(x2_hat_bytes, sizeof(x2_hat_bytes));
    libspdm_zero_mem(own_static_xy, sizeof(own_static_xy));
    libspdm_zero_mem(peer_static_xy, sizeof(peer_static_xy));
    libspdm_zero_mem(za, sizeof(za));
    libspdm_zero_mem(zb, sizeof(zb));
    libspdm_zero_mem(kdf_in, sizeof(kdf_in));
    BN_CTX_free(bn_ctx);
    sm2_kex_free_point(tmp);
    sm2_kex_free_point(u);
    sm2_kex_free_point(peer_eph);
    BN_clear_free(x1);
    BN_clear_free(x2);
    BN_clear_free(x1_hat);
    BN_clear_free(x2_hat);
    BN_clear_free(t);
    BN_clear_free(mul);
    return ret;
}

#if LIBSPDM_SM2_KEX_TEST_HOOKS
bool libspdm_sm2_key_exchange_set_ephemeral_priv_for_test(
    void *sm2_context, const uint8_t *eph_d, size_t eph_d_size)
{
    libspdm_sm2_kex_ctx_t *ctx;
    BIGNUM *new_eph_priv = NULL;
    EC_POINT *new_eph_pub = NULL;
    BN_CTX *bn_ctx = NULL;
    bool ret = false;

    ctx = (libspdm_sm2_kex_ctx_t *)sm2_context;
    if ((ctx == NULL) || !ctx->initialized || (eph_d == NULL) ||
        (eph_d_size != SM2_COORD_SIZE)) {
        return false;
    }
    if (!sm2_kex_scalar_from_32(ctx, eph_d, &new_eph_priv)) {
        return false;
    }

    new_eph_pub = EC_POINT_new(ctx->group);
    bn_ctx = BN_CTX_new();
    if ((new_eph_pub == NULL) || (bn_ctx == NULL)) {
        goto done;
    }
    if (EC_POINT_mul(ctx->group, new_eph_pub, new_eph_priv, NULL, NULL, bn_ctx) != 1) {
        goto done;
    }

    BN_clear_free(ctx->own_eph_priv);
    sm2_kex_free_point(ctx->own_eph_pub);
    ctx->own_eph_priv = new_eph_priv;
    ctx->own_eph_pub = new_eph_pub;
    new_eph_priv = NULL;
    new_eph_pub = NULL;
    ret = true;

done:
    BN_clear_free(new_eph_priv);
    sm2_kex_free_point(new_eph_pub);
    BN_CTX_free(bn_ctx);
    return ret;
}

bool libspdm_sm2_key_exchange_get_ephemeral_pub_for_test(
    void *sm2_context, uint8_t *pub_xy, size_t *pub_xy_size)
{
    libspdm_sm2_kex_ctx_t *ctx;

    ctx = (libspdm_sm2_kex_ctx_t *)sm2_context;
    if ((ctx == NULL) || !ctx->initialized || (ctx->own_eph_pub == NULL)) {
        return false;
    }
    return sm2_kex_export_public_xy(ctx, ctx->own_eph_pub, pub_xy, pub_xy_size);
}

bool libspdm_sm2_kex_compute_za_for_test(const uint8_t *id, size_t id_size,
                                         const uint8_t pub_xy[SM2_PUB_SIZE],
                                         uint8_t out_za[32])
{
    return sm2_kex_compute_za(id, id_size, pub_xy, out_za);
}

bool libspdm_sm2_kex_compute_x_hat_for_test(const uint8_t x_bytes[32],
                                            uint8_t out_x_hat[32])
{
    return sm2_kex_compute_x_hat(x_bytes, out_x_hat);
}

bool libspdm_sm2_kex_sm3_kdf_for_test(const uint8_t *input, size_t input_size,
                                      uint8_t *out_key, size_t out_size)
{
    return sm2_kex_sm3_kdf(input, input_size, out_key, out_size);
}
#endif /* LIBSPDM_SM2_KEX_TEST_HOOKS */

#endif /* LIBSPDM_SM2_KEY_EXCHANGE_FULL_GBT_32918_3_SUPPORT */
