#include "../../zerofido_pin.h"

#include <furi_hal_random.h>
#include <string.h>

#include "../../zerofido_app_i.h"
#include "../internal.h"

void zf_pin_refresh_pin_token(uint8_t pin_token[ZF_PIN_TOKEN_LEN]) {
    furi_hal_random_fill_buf(pin_token, ZF_PIN_TOKEN_LEN);
}

void zf_pin_reset_token_metadata(ZfClientPinState *state) {
    state->pin_token_active = false;
    state->pin_token_issued_at = 0;
    state->pin_token_permissions = 0;
    state->pin_token_permissions_scoped = false;
    state->pin_token_permissions_rp_id_set = false;
    zf_crypto_secure_zero(state->pin_token_permissions_rp_id,
                          sizeof(state->pin_token_permissions_rp_id));
}

void zf_pin_invalidate_token_state(ZfClientPinState *state) {
    zf_crypto_secure_zero(state->pin_token, sizeof(state->pin_token));
    zf_pin_reset_token_metadata(state);
}

void zf_pin_note_pin_token_issued(ZfClientPinState *state) {
    state->pin_token_active = true;
    state->pin_token_issued_at = furi_get_tick();
}

void zf_pin_set_token_permissions(ZfClientPinState *state, uint64_t permissions,
                                  bool permission_scoped, const char *rp_id) {
    state->pin_token_permissions = permissions;
    state->pin_token_permissions_scoped = permission_scoped;
    state->pin_token_permissions_rp_id_set = rp_id && rp_id[0] != '\0';
    if (state->pin_token_permissions_rp_id_set) {
        strncpy(state->pin_token_permissions_rp_id, rp_id,
                sizeof(state->pin_token_permissions_rp_id) - 1);
        state->pin_token_permissions_rp_id[sizeof(state->pin_token_permissions_rp_id) - 1] = '\0';
    } else {
        state->pin_token_permissions_rp_id[0] = '\0';
    }
}

bool zf_pin_token_is_expired(const ZfClientPinState *state) {
    return (int32_t)(furi_get_tick() - state->pin_token_issued_at) >=
           (int32_t)ZF_PIN_TOKEN_TIMEOUT_MS;
}

uint8_t zerofido_pin_require_auth(Storage *storage, ZfClientPinState *state, bool uv_requested,
                                  bool has_pin_auth,
                                  const uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN],
                                  const uint8_t *pin_auth, size_t pin_auth_len,
                                  bool has_pin_protocol, uint64_t pin_protocol, const char *rp_id,
                                  uint64_t required_permissions, bool *uv_verified) {
    uint8_t expected[32];

    *uv_verified = false;
    if (has_pin_auth) {
        if (pin_auth_len != ZF_PIN_AUTH_LEN) {
            return ZF_CTAP_ERR_PIN_AUTH_INVALID;
        }
        if (state->pin_auth_blocked) {
            return ZF_CTAP_ERR_PIN_AUTH_BLOCKED;
        }
        if (!state->pin_set) {
            return ZF_CTAP_ERR_PIN_NOT_SET;
        }
        if (!has_pin_protocol) {
            return ZF_CTAP_ERR_MISSING_PARAMETER;
        }
        if (pin_protocol != ZF_PIN_PROTOCOL_V1) {
            return ZF_CTAP_ERR_INVALID_PARAMETER;
        }
        if (!state->pin_token_active) {
            return ZF_CTAP_ERR_PIN_AUTH_INVALID;
        }
        if (zf_pin_token_is_expired(state)) {
            zf_pin_invalidate_token_state(state);
            return ZF_CTAP_ERR_PIN_TOKEN_EXPIRED;
        }

        if (!zf_crypto_hmac_sha256(state->pin_token, sizeof(state->pin_token), client_data_hash,
                                   ZF_CLIENT_DATA_HASH_LEN, expected)) {
            return ZF_CTAP_ERR_OTHER;
        }
        if (!zf_crypto_constant_time_equal(expected, pin_auth, ZF_PIN_AUTH_LEN)) {
            zf_crypto_secure_zero(expected, sizeof(expected));
            return zf_pin_note_pin_auth_mismatch(storage, state);
        }
        if ((state->pin_token_permissions & required_permissions) != required_permissions) {
            zf_crypto_secure_zero(expected, sizeof(expected));
            return ZF_CTAP_ERR_PIN_AUTH_INVALID;
        }
        if (state->pin_token_permissions_scoped &&
            (required_permissions & (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA)) != 0U) {
            if (!rp_id || rp_id[0] == '\0') {
                zf_crypto_secure_zero(expected, sizeof(expected));
                return ZF_CTAP_ERR_PIN_AUTH_INVALID;
            }
            if (state->pin_token_permissions_rp_id_set) {
                if (strcmp(state->pin_token_permissions_rp_id, rp_id) != 0) {
                    zf_crypto_secure_zero(expected, sizeof(expected));
                    return ZF_CTAP_ERR_PIN_AUTH_INVALID;
                }
            } else {
                zf_pin_set_token_permissions(state, state->pin_token_permissions,
                                             state->pin_token_permissions_scoped, rp_id);
            }
        }

        uint8_t previous_pin_consecutive_mismatches = state->pin_consecutive_mismatches;
        bool previous_pin_auth_blocked = state->pin_auth_blocked;
        zf_pin_clear_auth_block_state(state);
        if (!zf_pin_persist_state(storage, state)) {
            state->pin_consecutive_mismatches = previous_pin_consecutive_mismatches;
            state->pin_auth_blocked = previous_pin_auth_blocked;
            zf_crypto_secure_zero(expected, sizeof(expected));
            return ZF_CTAP_ERR_OTHER;
        }
        *uv_verified = true;
        zf_crypto_secure_zero(expected, sizeof(expected));
        return ZF_CTAP_SUCCESS;
    }
    if (!state->pin_set) {
        return uv_requested ? ZF_CTAP_ERR_PIN_NOT_SET : ZF_CTAP_SUCCESS;
    }
    if (!uv_requested) {
        return ZF_CTAP_SUCCESS;
    }
    return ZF_CTAP_ERR_PIN_REQUIRED;
}
