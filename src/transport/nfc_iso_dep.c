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

static void zf_transport_nfc_cache_last_iso_response(ZfNfcTransportState *state,
                                                     const uint8_t *data, size_t data_len) {
    if (!state || !state->iso4_last_tx_buffer || (!data && data_len > 0U)) {
        return;
    }

    bit_buffer_reset(state->iso4_last_tx_buffer);
    if (data_len > 0U) {
        bit_buffer_append_bytes(state->iso4_last_tx_buffer, data, data_len);
    }
    state->iso4_last_tx_valid = true;
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

    if (!chaining) {
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
    if (!state) {
        return;
    }

    state->iso4_last_tx_valid = false;
    if (state->iso4_last_tx_buffer) {
        bit_buffer_reset(state->iso4_last_tx_buffer);
    }
}

bool zf_transport_nfc_replay_last_iso_response(ZfNfcTransportState *state) {
    if (!state || !state->iso4_last_tx_valid || !state->iso4_last_tx_buffer) {
        return false;
    }

    return zf_transport_nfc_send_frame(state, bit_buffer_get_data(state->iso4_last_tx_buffer),
                                       bit_buffer_get_size_bytes(state->iso4_last_tx_buffer));
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
