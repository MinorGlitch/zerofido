/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "zerofido_crypto.h"

#include <furi_hal.h>
#include <furi_hal_random.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <string.h>

#define ZF_UNIQUE_KEY_SLOT FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT

static int zf_random_cb(void *context, unsigned char *output, size_t output_len) {
    UNUSED(context);
    furi_hal_random_fill_buf(output, output_len);
    return 0;
}

static uint8_t zf_der_encode_int(uint8_t *out, const uint8_t *value, size_t value_len) {
    size_t start = 0;
    while (start + 1 < value_len && value[start] == 0) {
        start++;
    }

    size_t len = value_len - start;
    out[0] = 0x02;
    if (value[start] & 0x80) {
        out[1] = (uint8_t)(len + 1);
        out[2] = 0;
        memcpy(&out[3], value + start, len);
        return (uint8_t)(len + 3);
    }

    out[1] = (uint8_t)len;
    memcpy(&out[2], value + start, len);
    return (uint8_t)(len + 2);
}

static size_t zf_der_encode_signature(const uint8_t r[ZF_PUBLIC_KEY_LEN],
                                      const uint8_t s[ZF_PUBLIC_KEY_LEN], uint8_t *out,
                                      size_t capacity) {
    uint8_t tmp[80];
    uint8_t r_len = zf_der_encode_int(tmp, r, ZF_PUBLIC_KEY_LEN);
    uint8_t s_len = zf_der_encode_int(tmp + r_len, s, ZF_PUBLIC_KEY_LEN);
    size_t total = 2 + r_len + s_len;

    if (total > capacity) {
        return 0;
    }

    out[0] = 0x30;
    out[1] = (uint8_t)(r_len + s_len);
    memcpy(&out[2], tmp, r_len + s_len);
    return total;
}

static bool zf_unwrap_private_key(const ZfCredentialRecord *record,
                                  uint8_t private_key[ZF_PRIVATE_KEY_LEN]) {
    if (!furi_hal_crypto_enclave_load_key(ZF_UNIQUE_KEY_SLOT, record->private_iv)) {
        return false;
    }

    bool ok = furi_hal_crypto_decrypt(record->private_wrapped, private_key,
                                      sizeof(record->private_wrapped));
    furi_hal_crypto_enclave_unload_key(ZF_UNIQUE_KEY_SLOT);
    return ok;
}

static bool zf_load_group(mbedtls_ecp_group *grp) {
    return mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1) == 0;
}

void zf_crypto_secure_zero(void *data, size_t size) {
    volatile uint8_t *ptr = data;

    if (!ptr) {
        return;
    }

    while (size-- > 0) {
        *ptr++ = 0;
    }
}

static bool zf_der_decode_length(const uint8_t *input, size_t input_len, size_t *header_len,
                                 size_t *value_len) {
    if (!input || input_len < 2 || !header_len || !value_len) {
        return false;
    }

    if ((input[1] & 0x80U) == 0) {
        *header_len = 2;
        *value_len = input[1];
        return *value_len <= input_len - *header_len;
    }

    size_t length_octets = input[1] & 0x7FU;
    if (length_octets == 0 || length_octets > sizeof(size_t) || length_octets > input_len - 2U) {
        return false;
    }

    size_t length = 0;
    for (size_t i = 0; i < length_octets; ++i) {
        length = (length << 8) | input[2 + i];
    }

    *header_len = 2 + length_octets;
    *value_len = length;
    return *value_len <= input_len - *header_len;
}

static bool zf_der_decode_signature(const uint8_t *signature, size_t signature_len, mbedtls_mpi *r,
                                    mbedtls_mpi *s) {
    size_t seq_header_len = 0;
    size_t seq_len = 0;
    size_t int_header_len = 0;
    size_t int_len = 0;
    size_t offset = 0;

    if (!signature || !r || !s || signature_len < 2 || signature[0] != 0x30) {
        return false;
    }
    if (!zf_der_decode_length(signature, signature_len, &seq_header_len, &seq_len)) {
        return false;
    }

    offset = seq_header_len;
    if (offset >= signature_len || signature[offset] != 0x02) {
        return false;
    }
    if (!zf_der_decode_length(&signature[offset], signature_len - offset, &int_header_len,
                              &int_len)) {
        return false;
    }
    if (mbedtls_mpi_read_binary(r, &signature[offset + int_header_len], int_len) != 0) {
        return false;
    }

    if (int_header_len > signature_len - offset ||
        int_len > signature_len - offset - int_header_len) {
        return false;
    }
    offset += int_header_len + int_len;
    if (offset >= signature_len || signature[offset] != 0x02) {
        return false;
    }
    if (!zf_der_decode_length(&signature[offset], signature_len - offset, &int_header_len,
                              &int_len)) {
        return false;
    }
    if (mbedtls_mpi_read_binary(s, &signature[offset + int_header_len], int_len) != 0) {
        return false;
    }

    if (int_header_len > signature_len - offset ||
        int_len > signature_len - offset - int_header_len) {
        return false;
    }
    offset += int_header_len + int_len;
    return offset == seq_header_len + seq_len;
}

bool zf_crypto_sign_hash_with_private_key(const uint8_t private_key[ZF_PRIVATE_KEY_LEN],
                                          const uint8_t hash[32], uint8_t *out, size_t out_capacity,
                                          size_t *out_len) {
    bool ok = false;
    uint8_t r[ZF_PUBLIC_KEY_LEN];
    uint8_t s[ZF_PUBLIC_KEY_LEN];
    mbedtls_ecp_group grp;
    mbedtls_mpi mpi_r;
    mbedtls_mpi mpi_s;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&mpi_r);
    mbedtls_mpi_init(&mpi_s);
    mbedtls_mpi_init(&d);

    do {
        if (!zf_load_group(&grp)) {
            break;
        }
        if (mbedtls_mpi_read_binary(&d, private_key, ZF_PRIVATE_KEY_LEN) != 0) {
            break;
        }
        if (mbedtls_ecdsa_sign(&grp, &mpi_r, &mpi_s, &d, hash, 32, zf_random_cb, NULL) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&mpi_r, r, sizeof(r)) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&mpi_s, s, sizeof(s)) != 0) {
            break;
        }

        *out_len = zf_der_encode_signature(r, s, out, out_capacity);
        ok = *out_len > 0;
    } while (false);

    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&mpi_s);
    mbedtls_mpi_free(&mpi_r);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool zf_crypto_verify_hash_with_public_key(const uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                           const uint8_t public_y[ZF_PUBLIC_KEY_LEN],
                                           const uint8_t hash[32], const uint8_t *signature,
                                           size_t signature_len) {
    bool ok = false;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r;
    mbedtls_mpi s;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    do {
        if (!zf_load_group(&grp)) {
            break;
        }
        if (mbedtls_mpi_read_binary(&q.MBEDTLS_PRIVATE(X), public_x, ZF_PUBLIC_KEY_LEN) != 0) {
            break;
        }
        if (mbedtls_mpi_read_binary(&q.MBEDTLS_PRIVATE(Y), public_y, ZF_PUBLIC_KEY_LEN) != 0) {
            break;
        }
        if (mbedtls_mpi_lset(&q.MBEDTLS_PRIVATE(Z), 1) != 0) {
            break;
        }
        if (mbedtls_ecp_check_pubkey(&grp, &q) != 0) {
            break;
        }
        if (!zf_der_decode_signature(signature, signature_len, &r, &s)) {
            break;
        }

        ok = mbedtls_ecdsa_verify(&grp, hash, 32, &q, &r, &s) == 0;
    } while (false);

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool zf_crypto_ensure_store_key(void) {
    return furi_hal_crypto_enclave_ensure_key(ZF_UNIQUE_KEY_SLOT);
}

void zf_crypto_sha256(const uint8_t *data, size_t size, uint8_t out[32]) {
    mbedtls_sha256_context sha;

    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, data, size);
    mbedtls_sha256_finish(&sha, out);
    mbedtls_sha256_free(&sha);
}

void zf_crypto_sha256_concat(const uint8_t *first, size_t first_size, const uint8_t *second,
                             size_t second_size, uint8_t out[32]) {
    mbedtls_sha256_context sha;

    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    if (first_size > 0) {
        mbedtls_sha256_update(&sha, first, first_size);
    }
    if (second_size > 0) {
        mbedtls_sha256_update(&sha, second, second_size);
    }
    mbedtls_sha256_finish(&sha, out);
    mbedtls_sha256_free(&sha);
}

bool zf_crypto_hmac_sha256_parts_with_scratch(
    ZfHmacSha256Scratch *scratch, const uint8_t *key, size_t key_len, const uint8_t *first,
    size_t first_size, const uint8_t *second, size_t second_size, uint8_t out[32]) {
    if (!scratch || !key || !out || (first_size > 0U && !first) ||
        (second_size > 0U && !second)) {
        return false;
    }

    memset(scratch, 0, sizeof(*scratch));

    if (key_len > sizeof(scratch->key_block)) {
        mbedtls_sha256_init(&scratch->sha);
        mbedtls_sha256_starts(&scratch->sha, 0);
        mbedtls_sha256_update(&scratch->sha, key, key_len);
        mbedtls_sha256_finish(&scratch->sha, scratch->key_block);
        mbedtls_sha256_free(&scratch->sha);
    } else if (key_len > 0U) {
        memcpy(scratch->key_block, key, key_len);
    }

    for (size_t i = 0; i < sizeof(scratch->pad); ++i) {
        scratch->pad[i] = scratch->key_block[i] ^ 0x36U;
    }
    mbedtls_sha256_init(&scratch->sha);
    mbedtls_sha256_starts(&scratch->sha, 0);
    mbedtls_sha256_update(&scratch->sha, scratch->pad, sizeof(scratch->pad));
    if (first_size > 0U) {
        mbedtls_sha256_update(&scratch->sha, first, first_size);
    }
    if (second_size > 0U) {
        mbedtls_sha256_update(&scratch->sha, second, second_size);
    }
    mbedtls_sha256_finish(&scratch->sha, scratch->inner_hash);
    mbedtls_sha256_free(&scratch->sha);

    for (size_t i = 0; i < sizeof(scratch->pad); ++i) {
        scratch->pad[i] = scratch->key_block[i] ^ 0x5CU;
    }
    mbedtls_sha256_init(&scratch->sha);
    mbedtls_sha256_starts(&scratch->sha, 0);
    mbedtls_sha256_update(&scratch->sha, scratch->pad, sizeof(scratch->pad));
    mbedtls_sha256_update(&scratch->sha, scratch->inner_hash, sizeof(scratch->inner_hash));
    mbedtls_sha256_finish(&scratch->sha, out);
    mbedtls_sha256_free(&scratch->sha);

    zf_crypto_secure_zero(scratch, sizeof(*scratch));
    return true;
}

bool zf_crypto_hmac_sha256_parts(const uint8_t *key, size_t key_len, const uint8_t *first,
                                 size_t first_size, const uint8_t *second, size_t second_size,
                                 uint8_t out[32]) {
    ZfHmacSha256Scratch scratch;

    return zf_crypto_hmac_sha256_parts_with_scratch(&scratch, key, key_len, first, first_size,
                                                    second, second_size, out);
}

bool zf_crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t size,
                           uint8_t out[32]) {
    return zf_crypto_hmac_sha256_parts(key, key_len, data, size, NULL, 0, out);
}

bool zf_crypto_aes256_cbc_zero_iv_encrypt(const uint8_t key[32], const uint8_t *input,
                                          uint8_t *output, size_t size) {
    const uint8_t iv[16] = {0};

    if ((size == 0) || (size % 16 != 0)) {
        return false;
    }

    if (!furi_hal_crypto_load_key(key, iv)) {
        return false;
    }

    bool ok = furi_hal_crypto_encrypt(input, output, size);
    furi_hal_crypto_unload_key();
    return ok;
}

bool zf_crypto_aes256_cbc_zero_iv_decrypt(const uint8_t key[32], const uint8_t *input,
                                          uint8_t *output, size_t size) {
    const uint8_t iv[16] = {0};

    if ((size == 0) || (size % 16 != 0)) {
        return false;
    }

    if (!furi_hal_crypto_load_key(key, iv)) {
        return false;
    }

    bool ok = furi_hal_crypto_decrypt(input, output, size);
    furi_hal_crypto_unload_key();
    return ok;
}

bool zf_crypto_generate_key_agreement_key(ZfP256KeyAgreementKey *key) {
    bool ok = false;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    do {
        if (!zf_load_group(&grp)) {
            break;
        }
        if (mbedtls_ecp_gen_keypair(&grp, &d, &q, zf_random_cb, NULL) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&d, key->private_key, sizeof(key->private_key)) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&q.MBEDTLS_PRIVATE(X), key->public_x, sizeof(key->public_x)) !=
            0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&q.MBEDTLS_PRIVATE(Y), key->public_y, sizeof(key->public_y)) !=
            0) {
            break;
        }
        ok = true;
    } while (false);

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool zf_crypto_ecdh_shared_secret(const ZfP256KeyAgreementKey *key,
                                  const uint8_t peer_x[ZF_PUBLIC_KEY_LEN],
                                  const uint8_t peer_y[ZF_PUBLIC_KEY_LEN], uint8_t out[32]) {
    bool ok = false;
    uint8_t secret_x[32];
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point peer;
    mbedtls_ecp_point shared;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&peer);
    mbedtls_ecp_point_init(&shared);

    do {
        if (!zf_load_group(&grp)) {
            break;
        }
        if (mbedtls_mpi_read_binary(&d, key->private_key, sizeof(key->private_key)) != 0) {
            break;
        }
        if (mbedtls_mpi_read_binary(&peer.MBEDTLS_PRIVATE(X), peer_x, ZF_PUBLIC_KEY_LEN) != 0) {
            break;
        }
        if (mbedtls_mpi_read_binary(&peer.MBEDTLS_PRIVATE(Y), peer_y, ZF_PUBLIC_KEY_LEN) != 0) {
            break;
        }
        if (mbedtls_mpi_lset(&peer.MBEDTLS_PRIVATE(Z), 1) != 0) {
            break;
        }
        if (mbedtls_ecp_check_pubkey(&grp, &peer) != 0) {
            break;
        }
        if (mbedtls_ecp_mul(&grp, &shared, &d, &peer, zf_random_cb, NULL) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&shared.MBEDTLS_PRIVATE(X), secret_x, sizeof(secret_x)) != 0) {
            break;
        }
        zf_crypto_sha256(secret_x, sizeof(secret_x), out);
        ok = true;
    } while (false);

    zf_crypto_secure_zero(secret_x, sizeof(secret_x));
    mbedtls_ecp_point_free(&shared);
    mbedtls_ecp_point_free(&peer);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool zf_crypto_generate_credential_keypair(ZfCredentialRecord *record) {
    bool ok = false;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    uint8_t iv[ZF_WRAP_IV_LEN];
    uint8_t private_key[ZF_PRIVATE_KEY_LEN];

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    do {
        if (!zf_load_group(&grp)) {
            break;
        }
        if (mbedtls_ecp_gen_keypair(&grp, &d, &q, zf_random_cb, NULL) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&d, private_key, sizeof(private_key)) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&q.MBEDTLS_PRIVATE(X), record->public_x,
                                     sizeof(record->public_x)) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&q.MBEDTLS_PRIVATE(Y), record->public_y,
                                     sizeof(record->public_y)) != 0) {
            break;
        }

        furi_hal_random_fill_buf(iv, sizeof(iv));
        memcpy(record->private_iv, iv, sizeof(iv));

        if (!furi_hal_crypto_enclave_load_key(ZF_UNIQUE_KEY_SLOT, iv)) {
            break;
        }
        if (!furi_hal_crypto_encrypt(private_key, record->private_wrapped,
                                     sizeof(record->private_wrapped))) {
            furi_hal_crypto_enclave_unload_key(ZF_UNIQUE_KEY_SLOT);
            break;
        }
        furi_hal_crypto_enclave_unload_key(ZF_UNIQUE_KEY_SLOT);
        ok = true;
    } while (false);

    zf_crypto_secure_zero(private_key, sizeof(private_key));
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool zf_crypto_compute_public_key_from_private(const uint8_t private_key[ZF_PRIVATE_KEY_LEN],
                                               uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                               uint8_t public_y[ZF_PUBLIC_KEY_LEN]) {
    bool ok = false;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    do {
        if (!zf_load_group(&grp)) {
            break;
        }
        if (mbedtls_mpi_read_binary(&d, private_key, ZF_PRIVATE_KEY_LEN) != 0) {
            break;
        }
        if (mbedtls_ecp_mul(&grp, &q, &d, &grp.G, zf_random_cb, NULL) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&q.MBEDTLS_PRIVATE(X), public_x, ZF_PUBLIC_KEY_LEN) != 0) {
            break;
        }
        if (mbedtls_mpi_write_binary(&q.MBEDTLS_PRIVATE(Y), public_y, ZF_PUBLIC_KEY_LEN) != 0) {
            break;
        }

        ok = true;
    } while (false);

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool zf_crypto_sign_hash(const ZfCredentialRecord *record, const uint8_t hash[32], uint8_t *out,
                         size_t out_capacity, size_t *out_len) {
    bool ok = false;
    uint8_t private_key[ZF_PRIVATE_KEY_LEN] = {0};

    do {
        if (!zf_unwrap_private_key(record, private_key)) {
            break;
        }
        ok = zf_crypto_sign_hash_with_private_key(private_key, hash, out, out_capacity, out_len);
    } while (false);

    zf_crypto_secure_zero(private_key, sizeof(private_key));
    return ok;
}

bool zf_crypto_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size) {
    uint8_t diff = 0;

    if (!left || !right) {
        return false;
    }

    for (size_t i = 0; i < size; ++i) {
        diff |= left[i] ^ right[i];
    }

    return diff == 0;
}
