/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_SM2_H
#define CRYPTLIB_SM2_H
#ifndef LIBSPDM_SM2_KEX_TEST_HOOKS
#define LIBSPDM_SM2_KEX_TEST_HOOKS 0
#endif

/*=====================================================================================
 *    Shang-Mi2 Primitives
 *=====================================================================================*/

#if LIBSPDM_SM2_DSA_SUPPORT
/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *          If the allocations fails, sm2_new_by_nid() returns NULL.
 **/
extern void *libspdm_sm2_dsa_new_by_nid(size_t nid);

/**
 * Generates Shang-Mi2 context from DER-encoded public key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data    Pointer to the DER-encoded public key data.
 * @param[in]  der_size    Size of the DER-encoded public key data in bytes.
 * @param[out] sm2_context Pointer to newly generated SM2 context which contains the
 *                         SM2 public key component.
 *                         Use libspdm_sm2_free() function to free the resource.
 *
 * If der_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   SM2 context was generated successfully.
 * @retval  false  Invalid DER public key data.
 *
 **/
extern bool libspdm_sm2_get_public_key_from_der(const uint8_t *der_data,
                                                size_t der_size,
                                                void **sm2_context);

/**
 * Retrieve the SM2 private key from password-protected PEM key data.
 *
 * @param[in]  pem_data     Pointer to the PEM-encoded key data.
 * @param[in]  pem_size     Size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM data.
 * @param[out] sm2_context  Pointer to newly generated SM2 context containing
 *                          private key material.
 *
 * @retval  true   SM2 private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 */
extern bool libspdm_sm2_get_private_key_from_pem(const uint8_t *pem_data,
                                                 size_t pem_size,
                                                 const char *password,
                                                 void **sm2_context);

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 **/
extern void libspdm_sm2_dsa_free(void *sm2_context);

/**
 * Sets the public key component into the established SM2 context.
 */
extern bool libspdm_sm2_dsa_set_pub_key(void *sm2_context, const uint8_t *public_key,
                                        size_t public_key_size);

/**
 * Gets the public key component from the established SM2 context.
 */
extern bool libspdm_sm2_dsa_get_pub_key(void *sm2_context, uint8_t *public_key,
                                        size_t *public_key_size);

/**
 * Gets the private key component from the established SM2 context.
 */
extern bool libspdm_sm2_dsa_get_priv_key(void *sm2_context, uint8_t *private_key,
                                         size_t *private_key_size);

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
 * @param[in]       sm2_context  Pointer to sm2 context for signature generation.
 * @param[in]       hash_nid     hash NID
 * @param[in]       id_a         The ID-A of the signing context.
 * @param[in]       id_a_size    Size of ID-A signing context.
 * @param[in]       message      Pointer to octet message to be signed (before hash).
 * @param[in]       size         Size of the message in bytes.
 * @param[out]      signature    Pointer to buffer to receive SM2 signature.
 * @param[in, out]  sig_size     On input, the size of signature buffer in bytes.
 *                               On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in SM2.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
extern bool libspdm_sm2_dsa_sign(const void *sm2_context, size_t hash_nid,
                                 const uint8_t *id_a, size_t id_a_size,
                                 const uint8_t *message, size_t size,
                                 uint8_t *signature, size_t *sig_size);

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
 * @param[in]  sm2_context  Pointer to SM2 context for signature verification.
 * @param[in]  hash_nid     hash NID
 * @param[in]  id_a         The ID-A of the signing context.
 * @param[in]  id_a_size    Size of ID-A signing context.
 * @param[in]  message      Pointer to octet message to be checked (before hash).
 * @param[in]  size         Size of the message in bytes.
 * @param[in]  signature    Pointer to SM2 signature to be verified.
 * @param[in]  sig_size     Size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in SM2.
 * @retval  false  Invalid signature or invalid sm2 context.
 *
 **/
extern bool libspdm_sm2_dsa_verify(const void *sm2_context, size_t hash_nid,
                                   const uint8_t *id_a, size_t id_a_size,
                                   const uint8_t *message, size_t size,
                                   const uint8_t *signature, size_t sig_size);
#endif /* LIBSPDM_SM2_DSA_SUPPORT */

#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *          If the allocations fails, sm2_new_by_nid() returns NULL.
 **/
extern void *libspdm_sm2_key_exchange_new_by_nid(size_t nid);

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 *
 **/
extern void libspdm_sm2_key_exchange_free(void *sm2_context);

/**
 * Initialize the specified sm2 context.
 *
 * @param[in]  sm2_context   Pointer to the sm2 context to be released.
 * @param[in]  hash_nid      hash NID, only SM3 is valid.
 * @param[in]  id_a          The ID-A of the key exchange context.
 * @param[in]  id_a_size     Size of ID-A key exchange context.
 * @param[in]  id_b          The ID-B of the key exchange context.
 * @param[in]  id_b_size     Size of ID-B key exchange context.
 * @param[in]  is_initiator  If the caller is initiator.
 *
 * @retval true   sm2 context is initialized.
 * @retval false  sm2 context is not initialized.
 **/
extern bool libspdm_sm2_key_exchange_init(void *sm2_context, size_t hash_nid,
                                          const uint8_t *id_a, size_t id_a_size,
                                          const uint8_t *id_b, size_t id_b_size,
                                          bool is_initiator);

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
 * @param[in, out]  sm2_context  Pointer to the sm2 context.
 * @param[out]      public_data  Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size  On input, the size of public buffer in bytes.
 *                               On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   sm2 public X,Y generation succeeded.
 * @retval false  sm2 public X,Y generation failed.
 * @retval false  public_size is not large enough.
 **/
extern bool libspdm_sm2_key_exchange_generate_key(void *sm2_context, uint8_t *public_data,
                                                  size_t *public_size);

/**
 * Computes exchanged common key, based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * Given peer's public key (X, Y), this function computes the exchanged common key,
 * based on its own context including value of curve parameter and random secret.
 * X is the first half of peer_public with size being peer_public_size / 2,
 * Y is the second half of peer_public with size being peer_public_size / 2.
 *
 * If sm2_context is NULL, then return false.
 * If peer_public is NULL, then return false.
 * If peer_public_size is 0, then return false.
 * If key is NULL, then return false.
 *
 * The id_a_size and id_b_size must be smaller than 2^16-1.
 * The peer_public_size is 64. first 32-byte is X, second 32-byte is Y.
 * The key_size must be smaller than 2^32-1, limited by KDF function.
 *
 * @param[in, out]  sm2_context       Pointer to the sm2 context.
 * @param[in]       peer_public       Pointer to the peer's public X,Y.
 * @param[in]       peer_public_size  Size of peer's public X,Y in bytes.
 * @param[out]      key               Pointer to the buffer to receive generated key.
 * @param[in]       key_size          On input, the size of key buffer in bytes.
 *
 * @retval true   sm2 exchanged key generation succeeded.
 * @retval false  sm2 exchanged key generation failed.
 **/
extern bool libspdm_sm2_key_exchange_compute_key(void *sm2_context,
                                                 const uint8_t *peer_public,
                                                 size_t peer_public_size, uint8_t *key,
                                                 size_t *key_size);

#if LIBSPDM_SM2_KEY_EXCHANGE_FULL_GBT_32918_3_SUPPORT
/**
 * Set local static private scalar d for SM2 key exchange.
 *
 * @param[in,out] sm2_context  Pointer to the SM2 key exchange context.
 * @param[in]     priv_d       32-byte private scalar.
 * @param[in]     priv_d_size  Size of private scalar in bytes.
 *
 * @retval true   Static private key was accepted.
 * @retval false  Invalid key material or invalid context state.
 */
extern bool libspdm_sm2_key_exchange_set_static_priv(
    void *sm2_context, const uint8_t *priv_d, size_t priv_d_size);

/**
 * Set local static public key (X||Y) for SM2 key exchange.
 *
 * @param[in,out] sm2_context  Pointer to the SM2 key exchange context.
 * @param[in]     pub_xy       64-byte public key X||Y.
 * @param[in]     pub_xy_size  Size of public key in bytes.
 *
 * @retval true   Static public key was accepted.
 * @retval false  Invalid key material or invalid context state.
 */
extern bool libspdm_sm2_key_exchange_set_static_pub_self(
    void *sm2_context, const uint8_t *pub_xy, size_t pub_xy_size);

/**
 * Set peer static public key (X||Y) for SM2 key exchange.
 *
 * @param[in,out] sm2_context  Pointer to the SM2 key exchange context.
 * @param[in]     pub_xy       64-byte public key X||Y.
 * @param[in]     pub_xy_size  Size of public key in bytes.
 *
 * @retval true   Peer static public key was accepted.
 * @retval false  Invalid key material or invalid context state.
 */
extern bool libspdm_sm2_key_exchange_set_static_pub_peer(
    void *sm2_context, const uint8_t *pub_xy, size_t pub_xy_size);

#if LIBSPDM_SM2_KEX_TEST_HOOKS
/**
 * Set local ephemeral private scalar r for SM2 key exchange (test hook only).
 */
extern bool libspdm_sm2_key_exchange_set_ephemeral_priv_for_test(
    void *sm2_context, const uint8_t *eph_d, size_t eph_d_size);

/**
 * Export local ephemeral public key (X||Y) for SM2 key exchange (test hook only).
 */
extern bool libspdm_sm2_key_exchange_get_ephemeral_pub_for_test(
    void *sm2_context, uint8_t *pub_xy, size_t *pub_xy_size);

/**
 * Compute ZA digest for a given ID and static public key (test hook only).
 */
extern bool libspdm_sm2_kex_compute_za_for_test(
    const uint8_t *id, size_t id_size, const uint8_t pub_xy[64], uint8_t out_za[32]);

/**
 * Compute x_hat reduction from a 32-byte X coordinate (test hook only).
 */
extern bool libspdm_sm2_kex_compute_x_hat_for_test(
    const uint8_t x_bytes[32], uint8_t out_x_hat[32]);

/**
 * Compute SM2 KEX SM3-KDF output (test hook only).
 */
extern bool libspdm_sm2_kex_sm3_kdf_for_test(
    const uint8_t *input, size_t input_size, uint8_t *out_key, size_t out_size);
#endif /* LIBSPDM_SM2_KEX_TEST_HOOKS */
#endif /* LIBSPDM_SM2_KEY_EXCHANGE_FULL_GBT_32918_3_SUPPORT */
#endif /* LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT */
#endif /* CRYPTLIB_SM2_H */
