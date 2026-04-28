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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <nfc/protocols/iso14443_4a/iso14443_4a_listener.h>
#include <toolbox/bit_buffer.h>

typedef struct ZfNfcIso4Layer ZfNfcIso4Layer;

typedef enum {
    ZfNfcIso4LayerResultSkip = 0,
    ZfNfcIso4LayerResultData = (1U << 1),
    ZfNfcIso4LayerResultSend = (1U << 2),
    ZfNfcIso4LayerResultHalt = (1U << 3),
    ZfNfcIso4LayerResultSendHalt = ZfNfcIso4LayerResultSend | ZfNfcIso4LayerResultHalt,
} ZfNfcIso4LayerResult;

ZfNfcIso4Layer *zf_nfc_iso4_layer_alloc(void);
void zf_nfc_iso4_layer_free(ZfNfcIso4Layer *instance);
void zf_nfc_iso4_layer_reset(ZfNfcIso4Layer *instance);
void zf_nfc_iso4_layer_set_cid(ZfNfcIso4Layer *instance, uint8_t cid);
void zf_nfc_iso4_layer_set_nad_supported(ZfNfcIso4Layer *instance, bool supported);
ZfNfcIso4LayerResult zf_nfc_iso4_layer_decode_command(ZfNfcIso4Layer *instance,
                                                      const BitBuffer *input_data,
                                                      BitBuffer *block_data);
bool zf_nfc_iso4_layer_encode_response(ZfNfcIso4Layer *instance, const BitBuffer *input_data,
                                       BitBuffer *block_data);
