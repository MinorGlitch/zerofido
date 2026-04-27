#pragma once

#include <stdbool.h>

#include <storage/storage.h>

#include "../../zerofido_pin.h"

typedef enum {
    ZfPinLoadMissing = 0,
    ZfPinLoadOk,
    ZfPinLoadInvalid,
} ZfPinLoadStatus;

void zf_pin_state_store_cleanup_temp(Storage *storage);
ZfPinLoadStatus zf_pin_state_store_load(Storage *storage, uint8_t pin_hash[ZF_PIN_HASH_LEN],
                                        uint8_t *pin_retries, uint8_t *pin_consecutive_mismatches,
                                        bool *pin_auth_blocked);
bool zf_pin_state_store_persist(Storage *storage, const ZfClientPinState *state);
bool zf_pin_state_store_fail_closed(Storage *storage, const ZfClientPinState *state);
bool zf_pin_state_store_clear(Storage *storage);
