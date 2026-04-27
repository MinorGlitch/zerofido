#pragma once

#include <stddef.h>
#include <stdint.h>

#include <storage/storage.h>

#include "../../zerofido_crypto.h"
#include "../internal.h"

typedef struct {
    ZfClientPinRequest request;
    ZfClientPinState state;
    uint8_t shared_secret[32];
    uint8_t current_pin_hash[ZF_PIN_HASH_LEN];
    uint8_t pin_hash_plain[32];
    uint8_t next_pin_token[ZF_PIN_TOKEN_LEN];
    uint8_t encrypted_token[ZF_PIN_TOKEN_LEN];
    uint8_t new_pin_plain[256];
    ZfHmacSha256Scratch hmac_scratch;
} ZfClientPinCommandScratch;

_Static_assert(sizeof(ZfClientPinCommandScratch) <= ZF_COMMAND_SCRATCH_SIZE,
               "Client PIN scratch exceeds command arena");

uint8_t zf_client_pin_parse_request(const uint8_t *data, size_t size, ZfClientPinRequest *request);

uint8_t zf_client_pin_response_retries(const ZfClientPinState *state, uint8_t *out,
                                       size_t out_capacity, size_t *out_len);
uint8_t zf_client_pin_response_key_agreement(const ZfClientPinState *state, uint8_t *out,
                                             size_t out_capacity, size_t *out_len);
uint8_t zf_client_pin_response_token(const uint8_t token[ZF_PIN_TOKEN_LEN], uint8_t *out,
                                     size_t out_capacity, size_t *out_len);

uint8_t zf_client_pin_handle_set_pin(Storage *storage, ZfClientPinState *state,
                                     const ZfClientPinRequest *request,
                                     ZfClientPinCommandScratch *scratch, size_t *out_len);
uint8_t zf_client_pin_handle_change_pin(Storage *storage, ZfClientPinState *state,
                                        const ZfClientPinRequest *request,
                                        ZfClientPinCommandScratch *scratch, size_t *out_len);
uint8_t zf_client_pin_handle_get_pin_token(Storage *storage, ZfClientPinState *state,
                                           const ZfClientPinRequest *request,
                                           ZfClientPinCommandScratch *scratch,
                                           bool permissions_mode, uint8_t *out, size_t out_capacity,
                                           size_t *out_len);
