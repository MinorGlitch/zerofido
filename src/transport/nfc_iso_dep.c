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

#include "nfc_iso_dep.h"

#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a_listener.h>
#include <nfc/helpers/iso14443_crc.h>
#include <lib/toolbox/simple_array.h>
#include <string.h>
#include <toolbox/bit_buffer.h>

#include "nfc_iso4_backport.h"
#include "nfc_protocol.h"
#include "nfc_trace.h"

#if defined(ZF_RELEASE_DIAGNOSTICS) && ZF_RELEASE_DIAGNOSTICS
static void zf_transport_nfc_trace_cache_state(const char *event, const ZfNfcTransportState *state,
                                               uint8_t pcb, size_t data_len) {
    FURI_LOG_I(ZF_NFC_TRACE_TAG, "iso-cache %s pcb=%02X len=%u valid=%u cached=%u frame=%u", event,
               pcb, (unsigned)data_len, state && state->iso4_last_tx_valid ? 1U : 0U,
               state ? (unsigned)state->iso4_last_tx_len : 0U,
               state && state->iso4_frame_buffer
                   ? (unsigned)bit_buffer_get_size_bytes(state->iso4_frame_buffer)
                   : 0U);
}
#else
static void zf_transport_nfc_trace_cache_state(const char *event, const ZfNfcTransportState *state,
                                               uint8_t pcb, size_t data_len) {
    (void)event;
    (void)state;
    (void)pcb;
    (void)data_len;
}
#endif

static void zf_transport_nfc_cache_last_iso_response(ZfNfcTransportState *state,
                                                     const uint8_t *data, size_t data_len) {
    if (!state || (!data && data_len > 0U) || data_len > sizeof(state->iso4_last_tx)) {
        zf_transport_nfc_trace_cache_state("skip", state, data && data_len > 0U ? data[0] : 0U,
                                           data_len);
        return;
    }

    if (data_len > 0U) {
        memcpy(state->iso4_last_tx, data, data_len);
    }
    state->iso4_last_tx_len = data_len;
    state->iso4_last_tx_valid = true;
    zf_transport_nfc_trace_cache_state("set", state, data_len > 0U ? data[0] : 0U, data_len);
}

static void zf_transport_nfc_cache_last_tx_buffer(ZfNfcTransportState *state) {
    if (!state || !state->tx_buffer || !state->iso4_last_tx_buffer) {
        return;
    }

    bit_buffer_reset(state->iso4_last_tx_buffer);
    bit_buffer_append_bytes(state->iso4_last_tx_buffer, bit_buffer_get_data(state->tx_buffer),
                            bit_buffer_get_size_bytes(state->tx_buffer));
}

static bool zf_transport_nfc_is_replayable_iso_i_response(const uint8_t *data, size_t data_len) {
    if (!data || data_len < 2U) {
        return false;
    }

    return (data[0] & 0xC2U) == ZF_NFC_PCB_BLOCK;
}

static bool zf_transport_nfc_replay_bit_buffer_if_i_response(ZfNfcTransportState *state,
                                                             BitBuffer *buffer) {
    const uint8_t *data = NULL;
    size_t data_len = 0U;

    if (!state || !buffer) {
        return false;
    }

    data_len = bit_buffer_get_size_bytes(buffer);
    data = bit_buffer_get_data(buffer);
    if (!zf_transport_nfc_is_replayable_iso_i_response(data, data_len)) {
        return false;
    }

    return zf_transport_nfc_send_frame(state, data, data_len);
}

static bool zf_transport_nfc_send_listener_block(ZfNfcTransportState *state) {
    bool sent = false;

    if (!state || !state->iso4_layer || !state->iso4_frame_buffer || !state->tx_buffer) {
        return false;
    }

    if (!zf_nfc_iso4_layer_encode_response(state->iso4_layer, state->tx_buffer,
                                           state->iso4_frame_buffer)) {
        return false;
    }
    if (bit_buffer_get_size_bytes(state->iso4_frame_buffer) > 0U &&
        (state->iso_pcb & ZF_NFC_PCB_BLOCK) == ZF_NFC_PCB_BLOCK) {
        bit_buffer_set_byte(state->iso4_frame_buffer, 0U, state->iso_pcb);
    }

    sent = zf_transport_nfc_send_frame(state, bit_buffer_get_data(state->iso4_frame_buffer),
                                       bit_buffer_get_size_bytes(state->iso4_frame_buffer));
    if (sent) {
        zf_transport_nfc_cache_last_iso_response(
            state, bit_buffer_get_data(state->iso4_frame_buffer),
            bit_buffer_get_size_bytes(state->iso4_frame_buffer));
    }
    return sent;
}

bool zf_transport_nfc_send_frame(ZfNfcTransportState *state, const uint8_t *data, size_t data_len) {
    if (!state || !state->nfc || !state->tx_buffer || (!data && data_len > 0U)) {
        return false;
    }

    bit_buffer_reset(state->tx_buffer);
    bit_buffer_append_bytes(state->tx_buffer, data, data_len);
    iso14443_crc_append(Iso14443CrcTypeA, state->tx_buffer);
    const bool sent = nfc_listener_tx(state->nfc, state->tx_buffer) == NfcErrorNone;
    if (sent) {
        if (zf_transport_nfc_is_replayable_iso_i_response(data, data_len)) {
            zf_transport_nfc_cache_last_iso_response(state, data, data_len);
            zf_transport_nfc_cache_last_tx_buffer(state);
        }
        zf_transport_nfc_trace_bytes("iso-tx", data, data_len);
    }
    return sent;
}

bool zf_transport_nfc_send_raw_bits(ZfNfcTransportState *state, const uint8_t *data,
                                    size_t bit_len) {
    const size_t byte_len = (bit_len + 7U) / 8U;

    if (!state || !state->nfc || !state->tx_buffer || (!data && bit_len > 0U)) {
        return false;
    }

    bit_buffer_reset(state->tx_buffer);
    bit_buffer_set_size(state->tx_buffer, bit_len);
    for (size_t i = 0; i < byte_len; ++i) {
        bit_buffer_set_byte(state->tx_buffer, i, data[i]);
    }
    return nfc_listener_tx(state->nfc, state->tx_buffer) == NfcErrorNone;
}

bool zf_transport_nfc_send_short_frame(ZfNfcTransportState *state, uint8_t data) {
    return zf_transport_nfc_send_raw_bits(state, &data, 4U);
}

bool zf_transport_nfc_send_iso_response(ZfNfcTransportState *state, const uint8_t *data,
                                        size_t data_len, bool chaining) {
    uint8_t block[ZF_NFC_MAX_FRAME_INF_SIZE + 2U];
    size_t block_len = 0U;
    uint8_t pcb = 0U;
    bool sent = false;

    if (!state || (!data && data_len > 0U) || data_len > ZF_NFC_MAX_FRAME_INF_SIZE) {
        return false;
    }

    if (!chaining && !state->iso4_tx_chain_active) {
        bit_buffer_reset(state->tx_buffer);
        if (data_len > 0U) {
            bit_buffer_append_bytes(state->tx_buffer, data, data_len);
        }
        if (zf_transport_nfc_send_listener_block(state)) {
            zf_transport_nfc_trace_bytes("apdu-tx", data, data_len);
            return true;
        }
    }

    pcb = (uint8_t)(ZF_NFC_PCB_BLOCK | (state->iso_pcb & 0x01U) |
                    (state->iso_cid_present ? ZF_NFC_PCB_CID : 0U) |
                    (chaining ? ZF_NFC_PCB_CHAIN : 0U));
    block[block_len++] = pcb;
    if (state->iso_cid_present) {
        block[block_len++] = state->iso_cid;
    }
    if (data_len > 0) {
        memcpy(&block[block_len], data, data_len);
        block_len += data_len;
    }
    sent = zf_transport_nfc_send_frame(state, block, block_len);
    if (sent) {
        zf_transport_nfc_cache_last_iso_response(state, block, block_len);
        state->iso_pcb ^= 0x01U;
        zf_transport_nfc_trace_bytes("apdu-tx", data, data_len);
    }
    return sent;
}

bool zf_transport_nfc_send_r_ack(ZfNfcTransportState *state, uint8_t pcb) {
    const uint8_t ack[2] = {
        (uint8_t)(ZF_NFC_PCB_R_BLOCK | (pcb & 0x01U) | ZF_NFC_PCB_BLOCK |
                  (state && state->iso_cid_present ? ZF_NFC_PCB_CID : 0U)),
        state ? state->iso_cid : 0U,
    };
    return zf_transport_nfc_send_frame(state, ack, state && state->iso_cid_present ? 2U : 1U);
}

void zf_transport_nfc_clear_last_iso_response(ZfNfcTransportState *state) {
    bool had_cached_response = false;

    if (!state) {
        return;
    }

    had_cached_response = state->iso4_last_tx_valid || state->iso4_last_tx_len > 0U ||
                          (state->iso4_last_tx_buffer &&
                           bit_buffer_get_size_bytes(state->iso4_last_tx_buffer) > 0U) ||
                          (state->iso4_frame_buffer &&
                           bit_buffer_get_size_bytes(state->iso4_frame_buffer) > 0U);
    state->iso4_last_tx_valid = false;
    state->iso4_last_tx_len = 0U;
    memset(state->iso4_last_tx, 0, sizeof(state->iso4_last_tx));
    if (state->iso4_last_tx_buffer) {
        bit_buffer_reset(state->iso4_last_tx_buffer);
    }
    if (state->iso4_frame_buffer) {
        bit_buffer_reset(state->iso4_frame_buffer);
    }
    if (had_cached_response) {
        zf_transport_nfc_trace_cache_state("clear", state, 0U, 0U);
    }
}

bool zf_transport_nfc_replay_last_iso_response(ZfNfcTransportState *state) {
    if (!state) {
        zf_transport_nfc_trace_cache_state("replay-null", state, 0U, 0U);
        return false;
    }

    if (state->iso4_last_tx_valid && state->iso4_last_tx_len > 0U &&
        state->iso4_last_tx_len <= sizeof(state->iso4_last_tx)) {
        bool sent = false;

        sent = zf_transport_nfc_send_frame(state, state->iso4_last_tx, state->iso4_last_tx_len);
        zf_transport_nfc_trace_cache_state(sent ? "replay-array" : "replay-array-fail", state,
                                           state->iso4_last_tx[0], state->iso4_last_tx_len);
        return sent;
    }

    if (zf_transport_nfc_replay_bit_buffer_if_i_response(state, state->iso4_frame_buffer)) {
        zf_transport_nfc_trace_cache_state("replay-frame", state, 0U, state->iso4_last_tx_len);
        return true;
    }

    zf_transport_nfc_trace_cache_state("replay-miss", state, 0U, 0U);
    return false;
}

void zf_transport_nfc_clear_tx_chain(ZfNfcTransportState *state) {
    if (!state) {
        return;
    }

    state->iso4_tx_chain_active = false;
    state->iso4_tx_chain_completed = false;
    state->iso4_tx_chain_len = 0U;
    state->iso4_tx_chain_offset = 0U;
    memset(state->iso4_tx_chain, 0, sizeof(state->iso4_tx_chain));
}

bool zf_transport_nfc_send_next_tx_chain_block(ZfNfcTransportState *state) {
    size_t remaining = 0U;
    size_t chunk_len = 0U;
    bool chaining = false;
    bool sent = false;

    if (!state || !state->iso4_tx_chain_active ||
        state->iso4_tx_chain_offset >= state->iso4_tx_chain_len ||
        state->iso4_tx_chain_len > sizeof(state->iso4_tx_chain)) {
        return false;
    }

    remaining = state->iso4_tx_chain_len - state->iso4_tx_chain_offset;
    chunk_len = remaining > ZF_NFC_TX_CHAIN_CHUNK_SIZE ? ZF_NFC_TX_CHAIN_CHUNK_SIZE : remaining;
    chaining = remaining > chunk_len;
    sent = zf_transport_nfc_send_iso_response(
        state, &state->iso4_tx_chain[state->iso4_tx_chain_offset], chunk_len, chaining);
    if (!sent) {
        return false;
    }

    state->iso4_tx_chain_offset += chunk_len;
    if (state->iso4_tx_chain_offset >= state->iso4_tx_chain_len) {
        state->iso4_tx_chain_active = false;
        state->iso4_tx_chain_completed = true;
        state->iso4_tx_chain_len = 0U;
        state->iso4_tx_chain_offset = 0U;
        memset(state->iso4_tx_chain, 0, sizeof(state->iso4_tx_chain));
    }
    return true;
}

bool zf_transport_nfc_begin_chained_apdu_payload(ZfNfcTransportState *state, const uint8_t *data,
                                                 size_t data_len, uint16_t status_word) {
    const size_t total_len = data_len + 2U;

    if (!state || (!data && data_len > 0U) || total_len > sizeof(state->iso4_tx_chain)) {
        return false;
    }

    zf_transport_nfc_clear_tx_chain(state);
    if (data_len > 0U) {
        memcpy(state->iso4_tx_chain, data, data_len);
    }
    state->iso4_tx_chain[data_len] = (uint8_t)(status_word >> 8);
    state->iso4_tx_chain[data_len + 1U] = (uint8_t)status_word;
    state->iso4_tx_chain_len = total_len;
    state->iso4_tx_chain_offset = 0U;
    state->iso4_tx_chain_active = true;
    return zf_transport_nfc_send_next_tx_chain_block(state);
}

bool zf_transport_nfc_send_status_word(ZfNfcTransportState *state, uint16_t status_word) {
    const uint8_t bytes[2] = {(uint8_t)(status_word >> 8), (uint8_t)status_word};

    return zf_transport_nfc_send_iso_response(state, bytes, sizeof(bytes), false);
}

bool zf_transport_nfc_send_forced_iso_status_word(ZfNfcTransportState *state,
                                                  uint16_t status_word) {
    if (!state) {
        return false;
    }

    return zf_transport_nfc_send_status_word(state, status_word);
}

bool zf_transport_nfc_send_apdu_payload(ZfNfcTransportState *state, const uint8_t *data,
                                        size_t data_len, uint16_t status_word) {
    size_t frame_len = data_len + 2U;
    uint8_t block[ZF_NFC_MAX_FRAME_INF_SIZE + 2U];
    size_t block_len = 0U;
    uint8_t pcb = 0U;
    uint8_t sw[2] = {(uint8_t)(status_word >> 8), (uint8_t)status_word};
    bool sent = false;

    if (!state || (!data && data_len > 0U) || frame_len > ZF_NFC_MAX_FRAME_INF_SIZE) {
        return false;
    }

    if (state->iso4_layer) {
        bit_buffer_reset(state->tx_buffer);
        if (data_len > 0U) {
            bit_buffer_append_bytes(state->tx_buffer, data, data_len);
        }
        bit_buffer_append_bytes(state->tx_buffer, sw, sizeof(sw));
        if (zf_transport_nfc_send_listener_block(state)) {
            zf_transport_nfc_trace_apdu_tx(data, data_len, status_word);
            return true;
        }
    }

    pcb = (uint8_t)(ZF_NFC_PCB_BLOCK | (state->iso_pcb & 0x01U) |
                    (state->iso_cid_present ? ZF_NFC_PCB_CID : 0U));
    block[block_len++] = pcb;
    if (state->iso_cid_present) {
        block[block_len++] = state->iso_cid;
    }
    if (data_len > 0U) {
        memcpy(&block[block_len], data, data_len);
        block_len += data_len;
    }
    memcpy(&block[block_len], sw, sizeof(sw));
    block_len += sizeof(sw);
    sent = zf_transport_nfc_send_frame(state, block, block_len);
    if (sent) {
        zf_transport_nfc_cache_last_iso_response(state, block, block_len);
        state->iso_pcb ^= 0x01U;
        zf_transport_nfc_trace_apdu_tx(data, data_len, status_word);
    }
    return sent;
}

void zf_transport_nfc_prepare_listener(ZfNfcTransportState *state) {
    static const uint8_t uid[] = {0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6};
    static const uint8_t atqa[] = {0x44, 0x00};
    Iso14443_3aData *base_data = NULL;

    iso14443_4a_reset(state->iso14443_4a_data);
    iso14443_4a_set_uid(state->iso14443_4a_data, uid, sizeof(uid));
    base_data = iso14443_4a_get_base_data(state->iso14443_4a_data);
    iso14443_3a_set_atqa(base_data, atqa);
    iso14443_3a_set_sak(base_data, 0x20U);
    state->iso14443_4a_data->ats_data.tl = 0x05U;
    state->iso14443_4a_data->ats_data.t0 = 0x78U;
    state->iso14443_4a_data->ats_data.ta_1 = 0x91U;
    state->iso14443_4a_data->ats_data.tb_1 = 0xE8U;
    state->iso14443_4a_data->ats_data.tc_1 = 0x00U;
    simple_array_reset(state->iso14443_4a_data->ats_data.t1_tk);
}
