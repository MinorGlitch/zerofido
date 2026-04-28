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

#include "internal.h"

#include <string.h>

static bool zf_client_pin_hmac_matches(ZfHmacSha256Scratch *scratch, const uint8_t key[32],
                                       const uint8_t *first, size_t first_len,
                                       const uint8_t *second, size_t second_len,
                                       const uint8_t *expected, size_t expected_len) {
    uint8_t hmac[32];
    bool matches = false;

    if (!zf_crypto_hmac_sha256_parts_with_scratch(scratch, key, 32, first, first_len, second,
                                                  second_len, hmac)) {
        return false;
    }
    matches = expected_len == ZF_PIN_AUTH_LEN &&
              zf_crypto_constant_time_equal(hmac, expected, ZF_PIN_AUTH_LEN);
    zf_crypto_secure_zero(hmac, sizeof(hmac));
    return matches;
}

uint8_t zf_client_pin_handle_set_pin(Storage *storage, ZfClientPinState *state,
                                     const ZfClientPinRequest *request,
                                     ZfClientPinCommandScratch *scratch, size_t *out_len) {
    uint8_t *shared_secret = scratch->shared_secret;
    uint8_t *new_pin_plain = scratch->new_pin_plain;
    size_t pin_len = 0;
    uint8_t status = ZF_CTAP_SUCCESS;

    if (state->pin_set) {
        status = ZF_CTAP_ERR_PIN_AUTH_INVALID;
        goto cleanup;
    }
    if (!request->has_key_agreement || !request->has_new_pin_enc || !request->has_pin_auth) {
        status = ZF_CTAP_ERR_MISSING_PARAMETER;
        goto cleanup;
    }
    if (!zf_pin_new_pin_enc_length_is_valid(request->new_pin_enc_len)) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (!zf_crypto_ecdh_shared_secret(&state->key_agreement, request->platform_x,
                                      request->platform_y, shared_secret)) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (!zf_client_pin_hmac_matches(&scratch->hmac_scratch, shared_secret, request->new_pin_enc,
                                    request->new_pin_enc_len, NULL, 0, request->pin_auth,
                                    request->pin_auth_len)) {
        status = ZF_CTAP_ERR_PIN_AUTH_INVALID;
        goto cleanup;
    }
    if (!zf_crypto_aes256_cbc_zero_iv_decrypt(shared_secret, request->new_pin_enc, new_pin_plain,
                                              request->new_pin_enc_len)) {
        status = ZF_CTAP_ERR_PIN_AUTH_INVALID;
        goto cleanup;
    }

    if (!zf_pin_validate_plaintext_block(new_pin_plain, request->new_pin_enc_len, &pin_len)) {
        status = ZF_CTAP_ERR_PIN_POLICY_VIOLATION;
        goto cleanup;
    }
    status = zf_pin_apply_plaintext(storage, state, new_pin_plain, pin_len, true);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    *out_len = 0;
    status = ZF_CTAP_SUCCESS;

cleanup:
    zf_crypto_secure_zero(shared_secret, sizeof(scratch->shared_secret));
    zf_crypto_secure_zero(new_pin_plain, sizeof(scratch->new_pin_plain));
    return status;
}

uint8_t zf_client_pin_handle_change_pin(Storage *storage, ZfClientPinState *state,
                                        const ZfClientPinRequest *request,
                                        ZfClientPinCommandScratch *scratch, size_t *out_len) {
    uint8_t *shared_secret = scratch->shared_secret;
    uint8_t *current_pin_hash = scratch->current_pin_hash;
    uint8_t *new_pin_plain = scratch->new_pin_plain;
    size_t pin_len = 0;
    uint8_t status = ZF_CTAP_SUCCESS;

    if (!state->pin_set) {
        status = ZF_CTAP_ERR_PIN_NOT_SET;
        goto cleanup;
    }
    if (state->pin_auth_blocked) {
        status = ZF_CTAP_ERR_PIN_AUTH_BLOCKED;
        goto cleanup;
    }
    if (state->pin_retries == 0U) {
        status = ZF_CTAP_ERR_PIN_BLOCKED;
        goto cleanup;
    }
    if (!request->has_key_agreement || !request->has_new_pin_enc || !request->has_pin_hash_enc ||
        !request->has_pin_auth) {
        status = ZF_CTAP_ERR_MISSING_PARAMETER;
        goto cleanup;
    }
    if (!zf_pin_new_pin_enc_length_is_valid(request->new_pin_enc_len) ||
        request->pin_hash_enc_len != ZF_PIN_HASH_LEN) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (!zf_crypto_ecdh_shared_secret(&state->key_agreement, request->platform_x,
                                      request->platform_y, shared_secret)) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (!zf_client_pin_hmac_matches(&scratch->hmac_scratch, shared_secret, request->new_pin_enc,
                                    request->new_pin_enc_len, request->pin_hash_enc,
                                    request->pin_hash_enc_len, request->pin_auth,
                                    request->pin_auth_len)) {
        status = ZF_CTAP_ERR_PIN_AUTH_INVALID;
        goto cleanup;
    }
    if (!zf_crypto_aes256_cbc_zero_iv_decrypt(shared_secret, request->pin_hash_enc,
                                              current_pin_hash, request->pin_hash_enc_len)) {
        status = zf_pin_auth_failure(storage, state);
        goto cleanup;
    }
    status = zf_pin_verify_hash(storage, state, current_pin_hash);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    if (!zf_crypto_aes256_cbc_zero_iv_decrypt(shared_secret, request->new_pin_enc, new_pin_plain,
                                              request->new_pin_enc_len)) {
        status = ZF_CTAP_ERR_PIN_AUTH_INVALID;
        goto cleanup;
    }

    if (!zf_pin_validate_plaintext_block(new_pin_plain, request->new_pin_enc_len, &pin_len)) {
        status = ZF_CTAP_ERR_PIN_POLICY_VIOLATION;
        goto cleanup;
    }
    status = zf_pin_apply_plaintext(storage, state, new_pin_plain, pin_len, false);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    *out_len = 0;
    status = ZF_CTAP_SUCCESS;

cleanup:
    zf_crypto_secure_zero(shared_secret, sizeof(scratch->shared_secret));
    zf_crypto_secure_zero(current_pin_hash, sizeof(scratch->current_pin_hash));
    zf_crypto_secure_zero(new_pin_plain, sizeof(scratch->new_pin_plain));
    return status;
}

uint8_t zf_client_pin_handle_get_pin_token(Storage *storage, ZfClientPinState *state,
                                           const ZfClientPinRequest *request,
                                           ZfClientPinCommandScratch *scratch,
                                           bool permissions_mode, uint8_t *out, size_t out_capacity,
                                           size_t *out_len) {
    uint8_t *shared_secret = scratch->shared_secret;
    uint8_t *pin_hash_plain = scratch->pin_hash_plain;
    uint8_t *next_pin_token = scratch->next_pin_token;
    uint8_t *encrypted_token = scratch->encrypted_token;
    uint8_t status = ZF_CTAP_SUCCESS;

    if (!state->pin_set) {
        return ZF_CTAP_ERR_PIN_NOT_SET;
    }
    if (state->pin_auth_blocked) {
        return ZF_CTAP_ERR_PIN_AUTH_BLOCKED;
    }
    if (state->pin_retries == 0) {
        return ZF_CTAP_ERR_PIN_BLOCKED;
    }
    if (!request->has_key_agreement || !request->has_pin_hash_enc) {
        return ZF_CTAP_ERR_MISSING_PARAMETER;
    }
    if (!permissions_mode && (request->has_permissions || request->has_rp_id)) {
        return ZF_CTAP_ERR_INVALID_PARAMETER;
    }
    if (permissions_mode && !request->has_permissions) {
        return ZF_CTAP_ERR_MISSING_PARAMETER;
    }
    if (permissions_mode && request->permissions == 0U) {
        return ZF_CTAP_ERR_INVALID_PARAMETER;
    }
    if (permissions_mode &&
        (request->permissions &
         ~(uint64_t)(ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA | ZF_PIN_PERMISSION_BE)) != 0U) {
        return ZF_CTAP_ERR_INVALID_PARAMETER;
    }
    if (permissions_mode &&
        (request->permissions & (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA)) != 0U &&
        !request->has_rp_id) {
        return ZF_CTAP_ERR_MISSING_PARAMETER;
    }
    if (request->pin_hash_enc_len != ZF_PIN_HASH_LEN) {
        return ZF_CTAP_ERR_INVALID_PARAMETER;
    }
    if (!zf_crypto_ecdh_shared_secret(&state->key_agreement, request->platform_x,
                                      request->platform_y, shared_secret)) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (!zf_crypto_aes256_cbc_zero_iv_decrypt(shared_secret, request->pin_hash_enc, pin_hash_plain,
                                              request->pin_hash_enc_len)) {
        status = zf_pin_auth_failure(storage, state);
        goto cleanup;
    }
    if (!zf_crypto_constant_time_equal(pin_hash_plain, state->pin_hash, ZF_PIN_HASH_LEN)) {
        status = zf_pin_auth_failure(storage, state);
        goto cleanup;
    }

    if (zf_pin_auth_success(storage, state) != ZF_CTAP_SUCCESS) {
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }
    zf_pin_refresh_pin_token(next_pin_token);
    if (!zf_crypto_aes256_cbc_zero_iv_encrypt(shared_secret, next_pin_token, encrypted_token,
                                              sizeof(scratch->encrypted_token))) {
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }
    status = zf_client_pin_response_token(encrypted_token, out, out_capacity, out_len);
    if (status == ZF_CTAP_SUCCESS) {
        memcpy(state->pin_token, next_pin_token, sizeof(state->pin_token));
        zf_pin_set_token_permissions(
            state,
            permissions_mode ? request->permissions : (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA),
            permissions_mode, permissions_mode ? request->rp_id : NULL);
        zf_pin_note_pin_token_issued(state);
    }

cleanup:
    zf_crypto_secure_zero(shared_secret, sizeof(scratch->shared_secret));
    zf_crypto_secure_zero(pin_hash_plain, sizeof(scratch->pin_hash_plain));
    zf_crypto_secure_zero(next_pin_token, sizeof(scratch->next_pin_token));
    zf_crypto_secure_zero(encrypted_token, sizeof(scratch->encrypted_token));
    return status;
}
