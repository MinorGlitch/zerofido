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

#include "../../zerofido_cbor.h"

uint8_t zf_client_pin_response_retries(const ZfClientPinState *state, uint8_t *out,
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

uint8_t zf_client_pin_response_key_agreement(const ZfClientPinState *state, uint8_t *out,
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

uint8_t zf_client_pin_response_token(const uint8_t token[ZF_PIN_TOKEN_LEN], uint8_t *out,
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
