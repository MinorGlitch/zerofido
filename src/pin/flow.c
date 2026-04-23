#include "../zerofido_pin.h"

#include <furi_hal_random.h>
#include <string.h>

#include "../zerofido_app_i.h"
#include "internal.h"
#include "state_store.h"

static bool zf_pin_validate_utf8(const uint8_t *pin, size_t pin_len, size_t *out_count);
static void zf_pin_clear_auth_block_state(ZfClientPinState *state);
static void zf_pin_force_runtime_block(ZfClientPinState *state);
bool zf_pin_new_pin_enc_length_is_valid(size_t length) {
    return length >= 64 && length <= sizeof(((ZfClientPinRequest *)0)->new_pin_enc) &&
           (length % 16U) == 0U;
}

static bool zf_pin_refresh_runtime_secrets(uint8_t pin_token[ZF_PIN_TOKEN_LEN],
                                           ZfP256KeyAgreementKey *key_agreement) {
    furi_hal_random_fill_buf(pin_token, ZF_PIN_TOKEN_LEN);
    memset(key_agreement, 0, sizeof(*key_agreement));
    return zf_crypto_generate_key_agreement_key(key_agreement);
}

void zf_pin_refresh_pin_token(uint8_t pin_token[ZF_PIN_TOKEN_LEN]) {
    furi_hal_random_fill_buf(pin_token, ZF_PIN_TOKEN_LEN);
}

void zf_pin_invalidate_token_state(ZfClientPinState *state) {
    state->pin_token_active = false;
    state->pin_token_issued_at = 0;
    state->pin_token_permissions = 0;
    state->pin_token_permissions_scoped = false;
    state->pin_token_permissions_rp_id_set = false;
    state->pin_token_permissions_rp_id[0] = '\0';
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

static bool zf_pin_refresh_key_agreement(ZfP256KeyAgreementKey *key_agreement) {
    memset(key_agreement, 0, sizeof(*key_agreement));
    return zf_crypto_generate_key_agreement_key(key_agreement);
}

static void zf_pin_clear_auth_block_state(ZfClientPinState *state) {
    state->pin_consecutive_mismatches = 0;
    state->pin_auth_blocked = false;
}

uint8_t zf_pin_note_pin_auth_mismatch(Storage *storage, ZfClientPinState *state) {
    if (state->pin_consecutive_mismatches < UINT8_MAX) {
        state->pin_consecutive_mismatches++;
    }
    if (state->pin_consecutive_mismatches >= 3) {
        state->pin_auth_blocked = true;
    }

    /*
     * Fail closed when storage is degraded: keep the stricter in-memory mismatch and block
     * state even if persisting it does not succeed.
     */
    if (!zf_pin_state_store_persist(storage, state) &&
        !zf_pin_state_store_fail_closed(storage, state)) {
        zf_pin_force_runtime_block(state);
    }

    return state->pin_auth_blocked ? ZF_CTAP_ERR_PIN_AUTH_BLOCKED : ZF_CTAP_ERR_PIN_AUTH_INVALID;
}

static void zf_pin_force_runtime_block(ZfClientPinState *state) {
    state->pin_retries = 0;
    state->pin_consecutive_mismatches = 3;
    state->pin_auth_blocked = true;
    zf_pin_invalidate_token_state(state);
}

static uint8_t zf_pin_validate_plaintext_length(size_t pin_len) {
    if (pin_len < ZF_MIN_PIN_LENGTH || pin_len > 63) {
        return ZF_CTAP_ERR_PIN_POLICY_VIOLATION;
    }
    return ZF_CTAP_SUCCESS;
}

static uint8_t zf_pin_validate_plaintext_policy(const uint8_t *pin, size_t pin_len) {
    size_t pin_codepoints = 0;

    if (pin_len > 63) {
        return ZF_CTAP_ERR_PIN_POLICY_VIOLATION;
    }
    if (!zf_pin_validate_utf8(pin, pin_len, &pin_codepoints)) {
        return ZF_CTAP_ERR_PIN_POLICY_VIOLATION;
    }

    return zf_pin_validate_plaintext_length(pin_codepoints);
}

static bool zf_pin_validate_utf8(const uint8_t *pin, size_t pin_len, size_t *out_count) {
    size_t count = 0;

    for (size_t i = 0; i < pin_len;) {
        uint8_t lead = pin[i];

        if (lead <= 0x7F) {
            ++count;
            ++i;
            continue;
        }
        if (lead >= 0xC2 && lead <= 0xDF) {
            if (i + 1 >= pin_len || (pin[i + 1] & 0xC0U) != 0x80U) {
                return false;
            }
            ++count;
            i += 2;
            continue;
        }
        if (lead == 0xE0) {
            if (i + 2 >= pin_len || pin[i + 1] < 0xA0 || pin[i + 1] > 0xBF ||
                (pin[i + 2] & 0xC0U) != 0x80U) {
                return false;
            }
            ++count;
            i += 3;
            continue;
        }
        if ((lead >= 0xE1 && lead <= 0xEC) || (lead >= 0xEE && lead <= 0xEF)) {
            if (i + 2 >= pin_len || (pin[i + 1] & 0xC0U) != 0x80U ||
                (pin[i + 2] & 0xC0U) != 0x80U) {
                return false;
            }
            ++count;
            i += 3;
            continue;
        }
        if (lead == 0xED) {
            if (i + 2 >= pin_len || pin[i + 1] < 0x80 || pin[i + 1] > 0x9F ||
                (pin[i + 2] & 0xC0U) != 0x80U) {
                return false;
            }
            ++count;
            i += 3;
            continue;
        }
        if (lead == 0xF0) {
            if (i + 3 >= pin_len || pin[i + 1] < 0x90 || pin[i + 1] > 0xBF ||
                (pin[i + 2] & 0xC0U) != 0x80U || (pin[i + 3] & 0xC0U) != 0x80U) {
                return false;
            }
            ++count;
            i += 4;
            continue;
        }
        if (lead >= 0xF1 && lead <= 0xF3) {
            if (i + 3 >= pin_len || (pin[i + 1] & 0xC0U) != 0x80U ||
                (pin[i + 2] & 0xC0U) != 0x80U || (pin[i + 3] & 0xC0U) != 0x80U) {
                return false;
            }
            ++count;
            i += 4;
            continue;
        }
        if (lead == 0xF4) {
            if (i + 3 >= pin_len || pin[i + 1] < 0x80 || pin[i + 1] > 0x8F ||
                (pin[i + 2] & 0xC0U) != 0x80U || (pin[i + 3] & 0xC0U) != 0x80U) {
                return false;
            }
            ++count;
            i += 4;
            continue;
        }

        return false;
    }

    *out_count = count;
    return true;
}

static size_t zf_pin_unpadded_length(const uint8_t *data, size_t size) {
    size_t len = 0;
    while (len < size && data[len] != 0) {
        len++;
    }
    return len;
}

bool zf_pin_validate_plaintext_block(const uint8_t *data, size_t size, size_t *out_len) {
    size_t pin_len = zf_pin_unpadded_length(data, size);
    if (pin_len == size) {
        return false;
    }
    if (pin_len > 63) {
        return false;
    }

    for (size_t i = pin_len; i < size; ++i) {
        if (data[i] != 0) {
            return false;
        }
    }

    *out_len = pin_len;
    return true;
}

static bool zf_pin_persist_state(Storage *storage, const ZfClientPinState *state) {
    return zf_pin_state_store_persist(storage, state);
}

uint8_t zf_pin_apply_plaintext(Storage *storage, ZfClientPinState *state, const uint8_t *pin,
                               size_t pin_len, bool require_unset) {
    uint8_t previous_hash[ZF_PIN_HASH_LEN];
    uint8_t pin_hash[32] = {0};
    uint8_t next_pin_token[ZF_PIN_TOKEN_LEN];
    uint8_t status = ZF_CTAP_SUCCESS;
    bool previous_pin_set = state->pin_set;
    uint8_t previous_pin_retries = state->pin_retries;
    uint8_t previous_pin_consecutive_mismatches = state->pin_consecutive_mismatches;
    bool previous_pin_auth_blocked = state->pin_auth_blocked;

    status = zf_pin_validate_plaintext_policy(pin, pin_len);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    if (require_unset && state->pin_set) {
        return ZF_CTAP_ERR_PIN_AUTH_INVALID;
    }
    zf_pin_refresh_pin_token(next_pin_token);

    zf_crypto_sha256(pin, pin_len, pin_hash);
    memcpy(previous_hash, state->pin_hash, sizeof(previous_hash));
    state->pin_set = true;
    state->pin_retries = ZF_PIN_RETRIES_MAX;
    zf_pin_clear_auth_block_state(state);
    memcpy(state->pin_hash, pin_hash, ZF_PIN_HASH_LEN);
    if (!zf_pin_persist_state(storage, state)) {
        memcpy(state->pin_hash, previous_hash, sizeof(previous_hash));
        state->pin_set = previous_pin_set;
        state->pin_retries = previous_pin_retries;
        state->pin_consecutive_mismatches = previous_pin_consecutive_mismatches;
        state->pin_auth_blocked = previous_pin_auth_blocked;
        memset(previous_hash, 0, sizeof(previous_hash));
        memset(pin_hash, 0, sizeof(pin_hash));
        memset(next_pin_token, 0, sizeof(next_pin_token));
        return ZF_CTAP_ERR_OTHER;
    }

    memcpy(state->pin_token, next_pin_token, sizeof(state->pin_token));
    zf_pin_invalidate_token_state(state);
    memset(previous_hash, 0, sizeof(previous_hash));
    memset(pin_hash, 0, sizeof(pin_hash));
    memset(next_pin_token, 0, sizeof(next_pin_token));
    return ZF_CTAP_SUCCESS;
}

uint8_t zf_pin_auth_failure(Storage *storage, ZfClientPinState *state) {
    ZfP256KeyAgreementKey next_key_agreement;

    if (state->pin_auth_blocked) {
        return ZF_CTAP_ERR_PIN_AUTH_BLOCKED;
    }
    if (!zf_pin_refresh_key_agreement(&next_key_agreement)) {
        return ZF_CTAP_ERR_OTHER;
    }
    state->key_agreement = next_key_agreement;
    memset(&next_key_agreement, 0, sizeof(next_key_agreement));
    if (state->pin_retries > 0) {
        state->pin_retries--;
    }
    if (state->pin_consecutive_mismatches < UINT8_MAX) {
        state->pin_consecutive_mismatches++;
    }
    if (state->pin_consecutive_mismatches >= 3) {
        state->pin_auth_blocked = true;
    }

    /*
     * Preserve the stricter in-memory retry, block, and key-agreement state even if persistence
     * fails so degraded storage cannot reopen brute-force attempts during the running session.
     */
    if (!zf_pin_persist_state(storage, state) && !zf_pin_state_store_fail_closed(storage, state)) {
        zf_pin_force_runtime_block(state);
    }
    if (state->pin_retries == 0) {
        return ZF_CTAP_ERR_PIN_BLOCKED;
    }

    return state->pin_auth_blocked ? ZF_CTAP_ERR_PIN_AUTH_BLOCKED : ZF_CTAP_ERR_PIN_INVALID;
}

uint8_t zf_pin_auth_success(Storage *storage, ZfClientPinState *state) {
    uint8_t previous_pin_retries = state->pin_retries;
    uint8_t previous_pin_consecutive_mismatches = state->pin_consecutive_mismatches;
    bool previous_pin_auth_blocked = state->pin_auth_blocked;

    state->pin_retries = ZF_PIN_RETRIES_MAX;
    zf_pin_clear_auth_block_state(state);
    if (zf_pin_persist_state(storage, state)) {
        return ZF_CTAP_SUCCESS;
    }

    state->pin_retries = previous_pin_retries;
    state->pin_consecutive_mismatches = previous_pin_consecutive_mismatches;
    state->pin_auth_blocked = previous_pin_auth_blocked;
    return ZF_CTAP_ERR_OTHER;
}

uint8_t zf_pin_verify_hash(Storage *storage, ZfClientPinState *state,
                           const uint8_t pin_hash[ZF_PIN_HASH_LEN]) {
    if (!state->pin_set) {
        return ZF_CTAP_ERR_PIN_NOT_SET;
    }
    if (state->pin_auth_blocked) {
        return ZF_CTAP_ERR_PIN_AUTH_BLOCKED;
    }
    if (state->pin_retries == 0) {
        return ZF_CTAP_ERR_PIN_BLOCKED;
    }
    if (!zf_crypto_constant_time_equal(pin_hash, state->pin_hash, ZF_PIN_HASH_LEN)) {
        return zf_pin_auth_failure(storage, state);
    }

    return zf_pin_auth_success(storage, state);
}

ZfPinInitResult zerofido_pin_init_with_result(Storage *storage, ZfClientPinState *state) {
    ZfPinLoadStatus load_status = ZfPinLoadMissing;

    memset(state, 0, sizeof(*state));
    zf_pin_state_store_cleanup_temp(storage);
    state->pin_retries = ZF_PIN_RETRIES_MAX;
    load_status =
        zf_pin_state_store_load(storage, state->pin_hash, &state->pin_retries,
                                &state->pin_consecutive_mismatches, &state->pin_auth_blocked);
    if (load_status == ZfPinLoadInvalid) {
        memset(state->pin_hash, 0, sizeof(state->pin_hash));
        return ZfPinInitInvalidPersistedState;
    }
    if (load_status == ZfPinLoadOk) {
        state->pin_set = true;
        /*
         * CTAP2 PIN_AUTH_BLOCKED is a temporary throttle that must clear when the authenticator
         * restarts, while the durable retry counter continues from persisted storage.
         */
        zf_pin_clear_auth_block_state(state);
    }
    if (!zf_pin_refresh_runtime_secrets(state->pin_token, &state->key_agreement)) {
        return ZfPinInitStorageError;
    }
    zf_pin_invalidate_token_state(state);
    return ZfPinInitOk;
}

bool zerofido_pin_init(Storage *storage, ZfClientPinState *state) {
    return zerofido_pin_init_with_result(storage, state) == ZfPinInitOk;
}

bool zerofido_pin_is_set(const ZfClientPinState *state) {
    return state->pin_set;
}

bool zerofido_pin_is_auth_blocked(const ZfClientPinState *state) {
    return state->pin_auth_blocked;
}

uint8_t zerofido_pin_get_retries(const ZfClientPinState *state) {
    return state->pin_retries;
}

uint8_t zerofido_pin_verify_plaintext(Storage *storage, ZfClientPinState *state, const char *pin) {
    uint8_t pin_hash[32] = {0};
    size_t pin_len = strlen(pin);
    uint8_t status = zf_pin_validate_plaintext_policy((const uint8_t *)pin, pin_len);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    zf_crypto_sha256((const uint8_t *)pin, pin_len, pin_hash);
    status = zf_pin_verify_hash(storage, state, pin_hash);
    memset(pin_hash, 0, sizeof(pin_hash));
    return status;
}

uint8_t zerofido_pin_set_plaintext(Storage *storage, ZfClientPinState *state, const char *pin) {
    return zf_pin_apply_plaintext(storage, state, (const uint8_t *)pin, strlen(pin), true);
}

uint8_t zerofido_pin_replace_plaintext(Storage *storage, ZfClientPinState *state,
                                       const char *new_pin) {
    return zf_pin_apply_plaintext(storage, state, (const uint8_t *)new_pin, strlen(new_pin), false);
}

bool zerofido_pin_resume_auth_attempts(Storage *storage, ZfClientPinState *state) {
    uint8_t previous_pin_consecutive_mismatches = state->pin_consecutive_mismatches;
    bool previous_pin_auth_blocked = state->pin_auth_blocked;

    if (!state->pin_set) {
        return false;
    }
    if (!state->pin_auth_blocked && state->pin_consecutive_mismatches == 0) {
        return true;
    }

    /*
     * Stock external apps do not have an app-owned retained power-session primitive.
     * ZeroFIDO therefore persists PIN_AUTH_BLOCKED and clears it only through this
     * explicit local unblock ceremony instead of depending on fragile hidden firmware
     * state. This is deliberate, even though it is not literal CTAP power-cycle semantics.
     */
    zf_pin_clear_auth_block_state(state);
    if (zf_pin_persist_state(storage, state)) {
        return true;
    }

    state->pin_consecutive_mismatches = previous_pin_consecutive_mismatches;
    state->pin_auth_blocked = previous_pin_auth_blocked;
    return false;
}

bool zerofido_pin_clear(Storage *storage, ZfClientPinState *state) {
    uint8_t next_pin_token[ZF_PIN_TOKEN_LEN];
    ZfP256KeyAgreementKey next_key_agreement;

    if (!zf_pin_refresh_runtime_secrets(next_pin_token, &next_key_agreement)) {
        return false;
    }
    if (!zf_pin_state_store_clear(storage)) {
        memset(next_pin_token, 0, sizeof(next_pin_token));
        memset(&next_key_agreement, 0, sizeof(next_key_agreement));
        return false;
    }

    memset(state->pin_hash, 0, sizeof(state->pin_hash));
    state->pin_set = false;
    state->pin_retries = ZF_PIN_RETRIES_MAX;
    zf_pin_clear_auth_block_state(state);
    memcpy(state->pin_token, next_pin_token, sizeof(state->pin_token));
    zf_pin_invalidate_token_state(state);
    state->key_agreement = next_key_agreement;
    memset(next_pin_token, 0, sizeof(next_pin_token));
    memset(&next_key_agreement, 0, sizeof(next_key_agreement));
    return true;
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
            return zf_pin_note_pin_auth_mismatch(storage, state);
        }
        if ((state->pin_token_permissions & required_permissions) != required_permissions) {
            return ZF_CTAP_ERR_PIN_AUTH_INVALID;
        }
        if (state->pin_token_permissions_scoped &&
            (required_permissions & (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA)) != 0U) {
            if (!rp_id || rp_id[0] == '\0') {
                return ZF_CTAP_ERR_PIN_AUTH_INVALID;
            }
            if (state->pin_token_permissions_rp_id_set) {
                if (strcmp(state->pin_token_permissions_rp_id, rp_id) != 0) {
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
            return ZF_CTAP_ERR_OTHER;
        }
        *uv_verified = true;
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
