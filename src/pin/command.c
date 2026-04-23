#include "../zerofido_pin.h"

#include <stdlib.h>
#include <string.h>

#include "../ctap/parse_internal.h"
#include "../zerofido_app_i.h"
#include "../zerofido_cbor.h"
#include "internal.h"

static bool zf_pin_parse_key_agreement(ZfCborCursor *cursor, ZfClientPinRequest *request) {
    size_t pairs = 0;
    bool saw_kty = false;
    bool saw_alg = false;
    bool saw_crv = false;
    bool saw_x = false;
    bool saw_y = false;

    if (!zf_cbor_read_map_start(cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        int64_t key = 0;
        if (!zf_cbor_read_int(cursor, &key)) {
            return false;
        }

        switch (key) {
        case 1: {
            int64_t kty = 0;
            if (!zf_cbor_read_int(cursor, &kty) || kty != 2) {
                return false;
            }
            saw_kty = true;
            break;
        }
        case 3: {
            int64_t alg = 0;
            if (!zf_cbor_read_int(cursor, &alg) || alg != -25) {
                return false;
            }
            saw_alg = true;
            break;
        }
        case -1: {
            int64_t crv = 0;
            if (!zf_cbor_read_int(cursor, &crv) || crv != 1) {
                return false;
            }
            saw_crv = true;
            break;
        }
        case -2: {
            size_t size = 0;
            if (!zf_ctap_cbor_read_bytes_copy(cursor, request->platform_x,
                                              sizeof(request->platform_x), &size) ||
                size != sizeof(request->platform_x)) {
                return false;
            }
            saw_x = true;
            break;
        }
        case -3: {
            size_t size = 0;
            if (!zf_ctap_cbor_read_bytes_copy(cursor, request->platform_y,
                                              sizeof(request->platform_y), &size) ||
                size != sizeof(request->platform_y)) {
                return false;
            }
            saw_y = true;
            break;
        }
        default:
            return false;
        }
    }

    request->has_key_agreement = saw_kty && saw_alg && saw_crv && saw_x && saw_y;
    return request->has_key_agreement;
}

static uint8_t zf_pin_parse_request(const uint8_t *data, size_t size, ZfClientPinRequest *request) {
    ZfCborCursor cursor;
    size_t pairs = 0;

    memset(request, 0, sizeof(*request));
    zf_cbor_cursor_init(&cursor, data, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return ZF_CTAP_ERR_INVALID_CBOR;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return ZF_CTAP_ERR_INVALID_CBOR;
        }

        switch (key) {
        case 1:
            if (!zf_cbor_read_uint(&cursor, &request->pin_protocol)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            request->has_pin_protocol = true;
            break;
        case 2:
            if (!zf_cbor_read_uint(&cursor, &request->subcommand)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            request->has_subcommand = true;
            break;
        case 3:
            if (!zf_pin_parse_key_agreement(&cursor, request)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            break;
        case 4:
            if (!zf_ctap_cbor_read_bytes_copy(&cursor, request->pin_auth, sizeof(request->pin_auth),
                                              &request->pin_auth_len)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            request->has_pin_auth = true;
            break;
        case 5:
            if (!zf_ctap_cbor_read_bytes_copy(&cursor, request->new_pin_enc,
                                              sizeof(request->new_pin_enc),
                                              &request->new_pin_enc_len)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            request->has_new_pin_enc = true;
            break;
        case 6:
            if (!zf_ctap_cbor_read_bytes_copy(&cursor, request->pin_hash_enc,
                                              sizeof(request->pin_hash_enc),
                                              &request->pin_hash_enc_len)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            request->has_pin_hash_enc = true;
            break;
        case 9:
            if (!zf_cbor_read_uint(&cursor, &request->permissions)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            request->has_permissions = true;
            break;
        case 10:
            if (!zf_ctap_cbor_read_text_copy(&cursor, request->rp_id, sizeof(request->rp_id))) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            request->has_rp_id = true;
            break;
        default:
            if (!zf_cbor_skip(&cursor)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            break;
        }
    }

    if (!request->has_subcommand || !request->has_pin_protocol) {
        return ZF_CTAP_ERR_MISSING_PARAMETER;
    }
    if (request->pin_protocol != ZF_PIN_PROTOCOL_V1) {
        return ZF_CTAP_ERR_INVALID_PARAMETER;
    }
    if (cursor.ptr != cursor.end) {
        return ZF_CTAP_ERR_INVALID_CBOR;
    }

    return ZF_CTAP_SUCCESS;
}

const char *zerofido_pin_subcommand_tag(uint64_t subcommand) {
    switch (subcommand) {
    case ZF_CLIENT_PIN_SUBCMD_GET_RETRIES:
        return "CP-RT";
    case ZF_CLIENT_PIN_SUBCMD_GET_KEY_AGREEMENT:
        return "CP-GA";
    case ZF_CLIENT_PIN_SUBCMD_SET_PIN:
        return "CP-SP";
    case ZF_CLIENT_PIN_SUBCMD_CHANGE_PIN:
        return "CP-CH";
    case ZF_CLIENT_PIN_SUBCMD_GET_PIN_TOKEN:
        return "CP-TK";
    case ZF_CLIENT_PIN_SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS:
        return "CP-PT";
    default:
        return "CP-UK";
    }
}

static uint8_t zf_pin_response_retries(const ZfClientPinState *state, uint8_t *out,
                                       size_t out_capacity, size_t *out_len) {
    ZfCborEncoder enc;
    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return ZF_CTAP_ERR_OTHER;
    }

    if (!(zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_uint(&enc, 3) &&
          zf_cbor_encode_uint(&enc, state->pin_retries))) {
        return ZF_CTAP_ERR_OTHER;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return ZF_CTAP_SUCCESS;
}

static uint8_t zf_pin_response_key_agreement(const ZfClientPinState *state, uint8_t *out,
                                             size_t out_capacity, size_t *out_len) {
    ZfCborEncoder enc;

    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return ZF_CTAP_ERR_OTHER;
    }

    if (!(zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_uint(&enc, 1) &&
          zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_int(&enc, 1) &&
          zf_cbor_encode_int(&enc, 2) && zf_cbor_encode_int(&enc, 3) &&
          zf_cbor_encode_int(&enc, -25) && zf_cbor_encode_int(&enc, -1) &&
          zf_cbor_encode_int(&enc, 1) && zf_cbor_encode_int(&enc, -2) &&
          zf_cbor_encode_bytes(&enc, state->key_agreement.public_x,
                               sizeof(state->key_agreement.public_x)) &&
          zf_cbor_encode_int(&enc, -3) &&
          zf_cbor_encode_bytes(&enc, state->key_agreement.public_y,
                               sizeof(state->key_agreement.public_y)))) {
        return ZF_CTAP_ERR_OTHER;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return ZF_CTAP_SUCCESS;
}

static uint8_t zf_pin_response_token(const uint8_t token[ZF_PIN_TOKEN_LEN], uint8_t *out,
                                     size_t out_capacity, size_t *out_len) {
    ZfCborEncoder enc;
    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return ZF_CTAP_ERR_OTHER;
    }

    if (!(zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_uint(&enc, 2) &&
          zf_cbor_encode_bytes(&enc, token, ZF_PIN_TOKEN_LEN))) {
        return ZF_CTAP_ERR_OTHER;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return ZF_CTAP_SUCCESS;
}

static bool zf_pin_hmac_matches(const uint8_t key[32], const uint8_t *data, size_t data_len,
                                const uint8_t *expected, size_t expected_len) {
    uint8_t hmac[32];

    if (!zf_crypto_hmac_sha256(key, 32, data, data_len, hmac)) {
        return false;
    }
    return expected_len == ZF_PIN_AUTH_LEN &&
           zf_crypto_constant_time_equal(hmac, expected, ZF_PIN_AUTH_LEN);
}

static bool zf_pin_hmac_matches_joined(const uint8_t key[32], const uint8_t *first,
                                       size_t first_len, const uint8_t *second, size_t second_len,
                                       const uint8_t *expected, size_t expected_len) {
    uint8_t combined[288];
    bool matches = false;
    size_t combined_len = first_len + second_len;

    if (combined_len > 288U) {
        return false;
    }

    memcpy(combined, first, first_len);
    memcpy(combined + first_len, second, second_len);
    matches = zf_pin_hmac_matches(key, combined, combined_len, expected, expected_len);
    memset(combined, 0, combined_len);
    return matches;
}

static uint8_t zf_pin_handle_set_pin(ZerofidoApp *app, ZfClientPinRequest *request,
                                     size_t *out_len) {
    uint8_t shared_secret[32] = {0};
    uint8_t new_pin_plain[sizeof(request->new_pin_enc)] = {0};
    size_t pin_len = 0;
    uint8_t status = ZF_CTAP_SUCCESS;

    if (app->pin_state.pin_set) {
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
    if (!zf_crypto_ecdh_shared_secret(&app->pin_state.key_agreement, request->platform_x,
                                      request->platform_y, shared_secret)) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (!zf_pin_hmac_matches(shared_secret, request->new_pin_enc, request->new_pin_enc_len,
                             request->pin_auth, request->pin_auth_len)) {
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
    status = zf_pin_apply_plaintext(app->storage, &app->pin_state, new_pin_plain, pin_len, true);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    *out_len = 0;
    status = ZF_CTAP_SUCCESS;

cleanup:
    memset(shared_secret, 0, sizeof(shared_secret));
    memset(new_pin_plain, 0, request->new_pin_enc_len > 0 ? request->new_pin_enc_len : 1U);
    return status;
}

static uint8_t zf_pin_handle_change_pin(ZerofidoApp *app, const ZfClientPinRequest *request,
                                        size_t *out_len) {
    uint8_t shared_secret[32] = {0};
    uint8_t current_pin_hash[ZF_PIN_HASH_LEN] = {0};
    uint8_t new_pin_plain[sizeof(request->new_pin_enc)] = {0};
    size_t pin_len = 0;
    uint8_t status = ZF_CTAP_SUCCESS;

    if (!app->pin_state.pin_set) {
        status = ZF_CTAP_ERR_PIN_NOT_SET;
        goto cleanup;
    }
    if (app->pin_state.pin_auth_blocked) {
        status = ZF_CTAP_ERR_PIN_AUTH_BLOCKED;
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
    if (!zf_crypto_ecdh_shared_secret(&app->pin_state.key_agreement, request->platform_x,
                                      request->platform_y, shared_secret)) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (!zf_pin_hmac_matches_joined(shared_secret, request->new_pin_enc, request->new_pin_enc_len,
                                    request->pin_hash_enc, request->pin_hash_enc_len,
                                    request->pin_auth, request->pin_auth_len)) {
        status = ZF_CTAP_ERR_PIN_AUTH_INVALID;
        goto cleanup;
    }
    if (!zf_crypto_aes256_cbc_zero_iv_decrypt(shared_secret, request->pin_hash_enc,
                                              current_pin_hash, request->pin_hash_enc_len)) {
        status = zf_pin_auth_failure(app->storage, &app->pin_state);
        goto cleanup;
    }
    status = zf_pin_verify_hash(app->storage, &app->pin_state, current_pin_hash);
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
    status = zf_pin_apply_plaintext(app->storage, &app->pin_state, new_pin_plain, pin_len, false);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    *out_len = 0;
    status = ZF_CTAP_SUCCESS;

cleanup:
    memset(shared_secret, 0, sizeof(shared_secret));
    memset(current_pin_hash, 0, sizeof(current_pin_hash));
    memset(new_pin_plain, 0, request->new_pin_enc_len > 0 ? request->new_pin_enc_len : 1U);
    return status;
}

static uint8_t zf_pin_handle_get_pin_token(ZerofidoApp *app, const ZfClientPinRequest *request,
                                           bool permissions_mode, uint8_t *out, size_t out_capacity,
                                           size_t *out_len) {
    uint8_t shared_secret[32] = {0};
    uint8_t pin_hash_plain[32] = {0};
    uint8_t next_pin_token[ZF_PIN_TOKEN_LEN] = {0};
    uint8_t encrypted_token[ZF_PIN_TOKEN_LEN] = {0};
    uint8_t status = ZF_CTAP_SUCCESS;

    if (!app->pin_state.pin_set) {
        return ZF_CTAP_ERR_PIN_NOT_SET;
    }
    if (app->pin_state.pin_auth_blocked) {
        return ZF_CTAP_ERR_PIN_AUTH_BLOCKED;
    }
    if (app->pin_state.pin_retries == 0) {
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
    if (!zf_crypto_ecdh_shared_secret(&app->pin_state.key_agreement, request->platform_x,
                                      request->platform_y, shared_secret)) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (!zf_crypto_aes256_cbc_zero_iv_decrypt(shared_secret, request->pin_hash_enc, pin_hash_plain,
                                              request->pin_hash_enc_len)) {
        status = zf_pin_auth_failure(app->storage, &app->pin_state);
        goto cleanup;
    }
    if (!zf_crypto_constant_time_equal(pin_hash_plain, app->pin_state.pin_hash, ZF_PIN_HASH_LEN)) {
        status = zf_pin_auth_failure(app->storage, &app->pin_state);
        goto cleanup;
    }

    if (zf_pin_auth_success(app->storage, &app->pin_state) != ZF_CTAP_SUCCESS) {
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }
    zf_pin_refresh_pin_token(next_pin_token);
    if (!zf_crypto_aes256_cbc_zero_iv_encrypt(shared_secret, next_pin_token, encrypted_token,
                                              sizeof(encrypted_token))) {
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }
    status = zf_pin_response_token(encrypted_token, out, out_capacity, out_len);
    if (status == ZF_CTAP_SUCCESS) {
        memcpy(app->pin_state.pin_token, next_pin_token, sizeof(app->pin_state.pin_token));
        zf_pin_set_token_permissions(
            &app->pin_state,
            permissions_mode ? request->permissions : (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA),
            permissions_mode, permissions_mode ? request->rp_id : NULL);
        zf_pin_note_pin_token_issued(&app->pin_state);
    }

cleanup:
    memset(shared_secret, 0, sizeof(shared_secret));
    memset(pin_hash_plain, 0, sizeof(pin_hash_plain));
    memset(next_pin_token, 0, sizeof(next_pin_token));
    memset(encrypted_token, 0, sizeof(encrypted_token));
    return status;
}

uint8_t zerofido_pin_handle_command(ZerofidoApp *app, const uint8_t *request, size_t request_len,
                                    uint8_t *out, size_t out_capacity, size_t *out_len) {
    ZfClientPinRequest parsed = {0};
    uint8_t status = ZF_CTAP_ERR_OTHER;

    status = zf_pin_parse_request(request, request_len, &parsed);
    if (status != ZF_CTAP_SUCCESS) {
        strncpy(app->last_ctap_command_tag, "CP-PARSE", sizeof(app->last_ctap_command_tag) - 1);
        app->last_ctap_command_tag[sizeof(app->last_ctap_command_tag) - 1] = '\0';
        return status;
    }
    strncpy(app->last_ctap_command_tag, zerofido_pin_subcommand_tag(parsed.subcommand),
            sizeof(app->last_ctap_command_tag) - 1);
    app->last_ctap_command_tag[sizeof(app->last_ctap_command_tag) - 1] = '\0';

    switch (parsed.subcommand) {
    case ZF_CLIENT_PIN_SUBCMD_GET_RETRIES:
        status = zf_pin_response_retries(&app->pin_state, out, out_capacity, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_GET_KEY_AGREEMENT:
        status = zf_pin_response_key_agreement(&app->pin_state, out, out_capacity, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_SET_PIN:
        status = zf_pin_handle_set_pin(app, &parsed, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_GET_PIN_TOKEN:
        status = zf_pin_handle_get_pin_token(app, &parsed, false, out, out_capacity, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS:
        status = zf_pin_handle_get_pin_token(app, &parsed, true, out, out_capacity, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_CHANGE_PIN:
        status = zf_pin_handle_change_pin(app, &parsed, out_len);
        break;
    default:
        status = ZF_CTAP_ERR_INVALID_SUBCOMMAND;
        break;
    }
    memset(&parsed, 0, sizeof(parsed));
    return status;
}
