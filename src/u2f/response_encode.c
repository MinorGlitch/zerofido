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

#include "response_encode.h"

#include <stddef.h>

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_random.h>

#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>

#include "apdu_internal.h"
#include "session_internal.h"
#include "persistence.h"
#include "../zerofido_crypto.h"

#define TAG "U2f"

#if !ZF_RELEASE_DIAGNOSTICS
#undef FURI_LOG_D
#undef FURI_LOG_W
#define FURI_LOG_D(...) ((void)0)
#define FURI_LOG_W(...) ((void)0)
#endif

static int zf_u2f_random_cb(void *context, uint8_t *dest, unsigned size) {
    UNUSED(context);
    furi_hal_random_fill_buf(dest, size);
    return 0;
}

static uint8_t zf_u2f_der_encode_int(uint8_t *der, const uint8_t *val, uint8_t val_len) {
    der[0] = 0x02;

    uint8_t len = 2;
    while (val_len > 1 && val[0] == 0) {
        ++val;
        --val_len;
    }

    if (val[0] > 0x7F) {
        der[len++] = 0;
    }

    memcpy(der + len, val, val_len);
    len += val_len;

    der[1] = len - 2;
    return len;
}

static uint8_t zf_u2f_der_encode_signature(uint8_t *der, size_t der_capacity, const uint8_t *sig) {
    if (der_capacity < U2F_DER_SIGNATURE_MAX_LEN) {
        return 0;
    }

    der[0] = 0x30;

    uint8_t len = 2;
    len += zf_u2f_der_encode_int(der + len, sig, U2F_HASH_SIZE);
    len += zf_u2f_der_encode_int(der + len, sig + U2F_HASH_SIZE, U2F_HASH_SIZE);

    der[1] = len - 2;
    return len;
}

static bool zf_u2f_ecc_sign(mbedtls_ecp_group *grp, const uint8_t *key, const uint8_t *hash,
                            uint8_t *signature) {
    mbedtls_mpi r, s, d;
    bool ok = false;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&d);

    ok = mbedtls_mpi_read_binary(&d, key, U2F_EC_KEY_SIZE) == 0 &&
         mbedtls_ecdsa_sign(grp, &r, &s, &d, hash, U2F_HASH_SIZE, zf_u2f_random_cb, NULL) == 0 &&
         mbedtls_mpi_write_binary(&r, signature, U2F_EC_BIGNUM_SIZE) == 0 &&
         mbedtls_mpi_write_binary(&s, signature + U2F_EC_BIGNUM_SIZE, U2F_EC_BIGNUM_SIZE) == 0;

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&d);
    return ok;
}

static bool zf_u2f_ecc_compute_public_key(mbedtls_ecp_group *grp, const uint8_t *private_key,
                                          U2fPubKey *public_key) {
    mbedtls_ecp_point q;
    mbedtls_mpi d;
    size_t output_len = 0;
    bool ok = false;

    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&d);

    ok = mbedtls_mpi_read_binary(&d, private_key, U2F_EC_KEY_SIZE) == 0 &&
         mbedtls_ecp_mul(grp, &q, &d, &grp->G, zf_u2f_random_cb, NULL) == 0 &&
         mbedtls_ecp_check_privkey(grp, &d) == 0 &&
         mbedtls_ecp_point_write_binary(grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &output_len,
                                        (unsigned char *)public_key, sizeof(U2fPubKey)) == 0;

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    return ok && output_len == sizeof(U2fPubKey);
}

static inline uint32_t zf_u2f_to_big_endian(uint32_t value) {
    return __builtin_bswap32(value);
}

uint16_t zf_u2f_encode_register_response(U2fData *instance, uint8_t *buf,
                                         uint16_t response_capacity) {
    const U2fRegisterReq *req = (const U2fRegisterReq *)buf;
    U2fRegisterResp *resp = (U2fRegisterResp *)buf;
    U2fKeyHandle handle;
    uint8_t private_key[U2F_EC_KEY_SIZE];
    U2fPubKey public_key;
    uint8_t hash[U2F_HASH_SIZE];
    uint8_t signature[U2F_EC_BIGNUM_SIZE * 2];
    ZfHmacSha256Scratch hmac_scratch;
    size_t response_base_len = offsetof(U2fRegisterResp, cert);
    size_t cert_capacity =
        response_capacity > response_base_len ? response_capacity - response_base_len : 0;
    uint16_t cert_len = 0;
    uint8_t signature_len = 0;

    if (instance->callback != NULL) {
        instance->callback(U2fNotifyRegister, instance->context);
    }
    if (!u2f_consume_user_present(instance)) {
        memcpy(&buf[0], zf_u2f_state_user_missing, sizeof(zf_u2f_state_user_missing));
        return sizeof(zf_u2f_state_user_missing);
    }

    handle.len = U2F_HASH_SIZE * 2;
    furi_hal_random_fill_buf(handle.nonce, sizeof(handle.nonce));

    if (!zf_crypto_hmac_sha256_parts_with_scratch(
            &hmac_scratch, instance->device_key, sizeof(instance->device_key), req->app_id,
            sizeof(req->app_id), handle.nonce, sizeof(handle.nonce), private_key) ||
        !zf_crypto_hmac_sha256_parts_with_scratch(
            &hmac_scratch, instance->device_key, sizeof(instance->device_key), private_key,
            sizeof(private_key), req->app_id, sizeof(req->app_id), handle.hash)) {
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(&handle, sizeof(handle));
        return zf_u2f_reply_status(buf, zf_u2f_state_not_supported);
    }

    if (!zf_u2f_ecc_compute_public_key(&instance->group, private_key, &public_key)) {
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(&handle, sizeof(handle));
        zf_crypto_secure_zero(&public_key, sizeof(public_key));
        return zf_u2f_reply_status(buf, zf_u2f_state_not_supported);
    }

    {
        uint8_t reserved_byte = 0;
        mbedtls_sha256_context sha_ctx;

        mbedtls_sha256_init(&sha_ctx);
        mbedtls_sha256_starts(&sha_ctx, 0);
        mbedtls_sha256_update(&sha_ctx, &reserved_byte, 1);
        mbedtls_sha256_update(&sha_ctx, req->app_id, sizeof(req->app_id));
        mbedtls_sha256_update(&sha_ctx, req->challenge, sizeof(req->challenge));
        mbedtls_sha256_update(&sha_ctx, handle.hash, handle.len);
        mbedtls_sha256_update(&sha_ctx, (uint8_t *)&public_key, sizeof(U2fPubKey));
        mbedtls_sha256_finish(&sha_ctx, hash);
        mbedtls_sha256_free(&sha_ctx);
    }

    if (!zf_u2f_ecc_sign(&instance->group, instance->cert_key, hash, signature)) {
        zf_crypto_secure_zero(signature, sizeof(signature));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(&handle, sizeof(handle));
        zf_crypto_secure_zero(&public_key, sizeof(public_key));
        return zf_u2f_reply_status(buf, zf_u2f_state_not_supported);
    }

    cert_len = (uint16_t)u2f_data_cert_load(buf + response_base_len, cert_capacity);
    if (cert_len == 0 || cert_len > cert_capacity) {
        zf_crypto_secure_zero(signature, sizeof(signature));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(&handle, sizeof(handle));
        zf_crypto_secure_zero(&public_key, sizeof(public_key));
        return zf_u2f_reply_status(buf, zf_u2f_state_not_supported);
    }

    signature_len = zf_u2f_der_encode_signature(buf + response_base_len + cert_len,
                                                cert_capacity - cert_len, signature);
    if (signature_len == 0 ||
        cert_len + signature_len + sizeof(zf_u2f_state_no_error) > cert_capacity) {
        zf_crypto_secure_zero(signature, sizeof(signature));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(&handle, sizeof(handle));
        zf_crypto_secure_zero(&public_key, sizeof(public_key));
        return zf_u2f_reply_status(buf, zf_u2f_state_not_supported);
    }

    resp->reserved = 0x05;
    memcpy(&resp->pub_key, &public_key, sizeof(U2fPubKey));
    memcpy(&resp->key_handle, &handle, sizeof(U2fKeyHandle));
    memcpy(resp->cert + cert_len + signature_len, zf_u2f_state_no_error,
           sizeof(zf_u2f_state_no_error));

    zf_crypto_secure_zero(signature, sizeof(signature));
    zf_crypto_secure_zero(hash, sizeof(hash));
    zf_crypto_secure_zero(private_key, sizeof(private_key));
    zf_crypto_secure_zero(&handle, sizeof(handle));
    zf_crypto_secure_zero(&public_key, sizeof(public_key));

    return sizeof(U2fRegisterResp) + cert_len + signature_len + sizeof(zf_u2f_state_no_error);
}

uint16_t zf_u2f_encode_authenticate_response(U2fData *instance, uint8_t *buf, uint16_t request_len,
                                             uint16_t response_capacity) {
    U2fParsedApdu apdu = {0};
    U2fAuthResp *resp = (U2fAuthResp *)buf;
    uint8_t private_key[U2F_EC_KEY_SIZE];
    uint8_t mac_control[32];
    uint8_t flags = 0;
    uint8_t hash[U2F_HASH_SIZE];
    uint8_t signature[U2F_HASH_SIZE * 2];
    ZfHmacSha256Scratch hmac_scratch;
    uint32_t next_counter = 0;
    uint32_t be_u2f_counter = 0;
    bool user_present = false;

    if (!u2f_parse_apdu_header(buf, request_len, false, &apdu)) {
        return zf_u2f_reply_status(buf, zf_u2f_state_wrong_length);
    }
    if (apdu.lc < (U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1)) {
        return zf_u2f_reply_status(buf, zf_u2f_state_wrong_length);
    }

    const uint8_t *challenge = apdu.data;
    const uint8_t *app_id = apdu.data + U2F_CHALLENGE_SIZE;
    uint8_t key_handle_len = apdu.data[U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE];
    const uint8_t *key_handle = apdu.data + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1;

    if (instance->callback != NULL) {
        instance->callback(U2fNotifyAuth, instance->context);
    }
    if (instance->counter == UINT32_MAX) {
        memcpy(&buf[0], zf_u2f_state_not_supported, sizeof(zf_u2f_state_not_supported));
        return sizeof(zf_u2f_state_not_supported);
    }

    next_counter = instance->counter + 1;
    be_u2f_counter = zf_u2f_to_big_endian(next_counter);

    if (key_handle_len != (U2F_HASH_SIZE * 2)) {
        zf_crypto_secure_zero(mac_control, sizeof(mac_control));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(signature, sizeof(signature));
        if (apdu.p1 == U2fEnforce) {
            u2f_clear_user_present(instance);
        }
        memcpy(&buf[0], zf_u2f_state_wrong_data, sizeof(zf_u2f_state_wrong_data));
        return sizeof(zf_u2f_state_wrong_data);
    }

    if (!zf_crypto_hmac_sha256_parts_with_scratch(
            &hmac_scratch, instance->device_key, sizeof(instance->device_key), app_id,
            U2F_APP_ID_SIZE, key_handle + U2F_HASH_SIZE, U2F_NONCE_SIZE, private_key) ||
        !zf_crypto_hmac_sha256_parts_with_scratch(
            &hmac_scratch, instance->device_key, sizeof(instance->device_key), private_key,
            sizeof(private_key), app_id, U2F_APP_ID_SIZE, mac_control)) {
        zf_crypto_secure_zero(mac_control, sizeof(mac_control));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(signature, sizeof(signature));
        return zf_u2f_reply_status(buf, zf_u2f_state_not_supported);
    }

    if (memcmp(key_handle, mac_control, sizeof(mac_control)) != 0) {
        FURI_LOG_W(TAG, "Wrong handle!");
        zf_crypto_secure_zero(mac_control, sizeof(mac_control));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(signature, sizeof(signature));
        if (apdu.p1 == U2fEnforce) {
            u2f_clear_user_present(instance);
        }
        memcpy(&buf[0], zf_u2f_state_wrong_data, sizeof(zf_u2f_state_wrong_data));
        return sizeof(zf_u2f_state_wrong_data);
    }
    if (apdu.p1 == U2fCheckOnly) {
        zf_crypto_secure_zero(mac_control, sizeof(mac_control));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(signature, sizeof(signature));
        memcpy(&buf[0], zf_u2f_state_user_missing, sizeof(zf_u2f_state_user_missing));
        return sizeof(zf_u2f_state_user_missing);
    }

    user_present = u2f_consume_user_present(instance);
    if (user_present) {
        flags |= 1;
    } else if (apdu.p1 == U2fEnforce) {
        zf_crypto_secure_zero(mac_control, sizeof(mac_control));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(signature, sizeof(signature));
        memcpy(&buf[0], zf_u2f_state_user_missing, sizeof(zf_u2f_state_user_missing));
        return sizeof(zf_u2f_state_user_missing);
    }

    {
        mbedtls_sha256_context sha_ctx;

        mbedtls_sha256_init(&sha_ctx);
        mbedtls_sha256_starts(&sha_ctx, 0);
        mbedtls_sha256_update(&sha_ctx, app_id, U2F_APP_ID_SIZE);
        mbedtls_sha256_update(&sha_ctx, &flags, 1);
        mbedtls_sha256_update(&sha_ctx, (uint8_t *)&be_u2f_counter, sizeof(be_u2f_counter));
        mbedtls_sha256_update(&sha_ctx, challenge, U2F_CHALLENGE_SIZE);
        mbedtls_sha256_finish(&sha_ctx, hash);
        mbedtls_sha256_free(&sha_ctx);
    }

    if (!zf_u2f_ecc_sign(&instance->group, private_key, hash, signature)) {
        zf_crypto_secure_zero(mac_control, sizeof(mac_control));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(signature, sizeof(signature));
        return zf_u2f_reply_status(buf, zf_u2f_state_not_supported);
    }

    if (response_capacity <= sizeof(U2fAuthResp)) {
        zf_crypto_secure_zero(mac_control, sizeof(mac_control));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(signature, sizeof(signature));
        return zf_u2f_reply_status(buf, zf_u2f_state_not_supported);
    }

    resp->user_present = flags;
    resp->counter = be_u2f_counter;
    uint8_t signature_len = zf_u2f_der_encode_signature(
        resp->signature, response_capacity - sizeof(U2fAuthResp), signature);
    if (signature_len == 0 ||
        sizeof(U2fAuthResp) + signature_len + sizeof(zf_u2f_state_no_error) > response_capacity) {
        zf_crypto_secure_zero(mac_control, sizeof(mac_control));
        zf_crypto_secure_zero(private_key, sizeof(private_key));
        zf_crypto_secure_zero(hash, sizeof(hash));
        zf_crypto_secure_zero(signature, sizeof(signature));
        return zf_u2f_reply_status(buf, zf_u2f_state_not_supported);
    }
    memcpy(resp->signature + signature_len, zf_u2f_state_no_error, sizeof(zf_u2f_state_no_error));

    if (next_counter > instance->counter_high_water) {
        uint32_t high_water = 0;
        if (!u2f_data_cnt_reserve(next_counter, &high_water)) {
            zf_crypto_secure_zero(mac_control, sizeof(mac_control));
            zf_crypto_secure_zero(private_key, sizeof(private_key));
            zf_crypto_secure_zero(hash, sizeof(hash));
            zf_crypto_secure_zero(signature, sizeof(signature));
            memcpy(&buf[0], zf_u2f_state_not_supported, sizeof(zf_u2f_state_not_supported));
            return sizeof(zf_u2f_state_not_supported);
        }
        instance->counter_high_water = high_water;
    }
    instance->counter = next_counter;
    FURI_LOG_D(TAG, "Counter: %lu", (unsigned long)instance->counter);

    zf_crypto_secure_zero(mac_control, sizeof(mac_control));
    zf_crypto_secure_zero(private_key, sizeof(private_key));
    zf_crypto_secure_zero(hash, sizeof(hash));
    zf_crypto_secure_zero(signature, sizeof(signature));

    if (instance->callback != NULL) {
        instance->callback(U2fNotifyAuthSuccess, instance->context);
    }

    return sizeof(U2fAuthResp) + signature_len + sizeof(zf_u2f_state_no_error);
}
