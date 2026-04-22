#pragma once

#include <mbedtls/ecp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zerofido_types.h"

typedef struct {
    uint8_t private_key[ZF_PRIVATE_KEY_LEN];
    uint8_t public_x[ZF_PUBLIC_KEY_LEN];
    uint8_t public_y[ZF_PUBLIC_KEY_LEN];
} ZfP256KeyAgreementKey;

bool zf_crypto_ensure_store_key(void);
void zf_crypto_sha256(const uint8_t *data, size_t size, uint8_t out[32]);
void zf_crypto_sha256_concat(const uint8_t *first, size_t first_size, const uint8_t *second,
                             size_t second_size, uint8_t out[32]);
bool zf_crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t size,
                           uint8_t out[32]);
bool zf_crypto_aes256_cbc_zero_iv_encrypt(const uint8_t key[32], const uint8_t *input,
                                          uint8_t *output, size_t size);
bool zf_crypto_aes256_cbc_zero_iv_decrypt(const uint8_t key[32], const uint8_t *input,
                                          uint8_t *output, size_t size);
bool zf_crypto_generate_key_agreement_key(ZfP256KeyAgreementKey *key);
bool zf_crypto_ecdh_shared_secret(const ZfP256KeyAgreementKey *key,
                                  const uint8_t peer_x[ZF_PUBLIC_KEY_LEN],
                                  const uint8_t peer_y[ZF_PUBLIC_KEY_LEN], uint8_t out[32]);
bool zf_crypto_generate_credential_keypair(ZfCredentialRecord *record);
bool zf_crypto_compute_public_key_from_private(const uint8_t private_key[ZF_PRIVATE_KEY_LEN],
                                               uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                               uint8_t public_y[ZF_PUBLIC_KEY_LEN]);
bool zf_crypto_sign_hash_with_private_key(const uint8_t private_key[ZF_PRIVATE_KEY_LEN],
                                          const uint8_t hash[32], uint8_t *out, size_t out_capacity,
                                          size_t *out_len);
bool zf_crypto_verify_hash_with_public_key(const uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                           const uint8_t public_y[ZF_PUBLIC_KEY_LEN],
                                           const uint8_t hash[32], const uint8_t *signature,
                                           size_t signature_len);
bool zf_crypto_sign_hash(const ZfCredentialRecord *record, const uint8_t hash[32], uint8_t *out,
                         size_t out_capacity, size_t *out_len);
bool zf_crypto_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size);
