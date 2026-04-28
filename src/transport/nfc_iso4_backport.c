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

#include "nfc_iso4_backport.h"

#include <stdlib.h>

#define ZF_ISO4_BLOCK_PCB (1U << 1)
#define ZF_ISO4_BLOCK_PCB_MASK (0x03U)

#define ZF_ISO4_BLOCK_PCB_I (0U)
#define ZF_ISO4_BLOCK_PCB_I_MASK (1U << 1)
#define ZF_ISO4_BLOCK_PCB_I_ZERO_MASK (7U << 5)
#define ZF_ISO4_BLOCK_PCB_I_NAD_OFFSET (2U)
#define ZF_ISO4_BLOCK_PCB_I_CID_OFFSET (3U)
#define ZF_ISO4_BLOCK_PCB_I_CHAIN_OFFSET (4U)
#define ZF_ISO4_BLOCK_PCB_I_NAD_MASK (1U << ZF_ISO4_BLOCK_PCB_I_NAD_OFFSET)
#define ZF_ISO4_BLOCK_PCB_I_CID_MASK (1U << ZF_ISO4_BLOCK_PCB_I_CID_OFFSET)
#define ZF_ISO4_BLOCK_PCB_I_CHAIN_MASK (1U << ZF_ISO4_BLOCK_PCB_I_CHAIN_OFFSET)

#define ZF_ISO4_BLOCK_PCB_R_MASK (5U << 5)
#define ZF_ISO4_BLOCK_PCB_R_NACK_OFFSET (4U)
#define ZF_ISO4_BLOCK_PCB_R_CID_OFFSET (3U)
#define ZF_ISO4_BLOCK_PCB_R_CID_MASK (1U << ZF_ISO4_BLOCK_PCB_R_CID_OFFSET)
#define ZF_ISO4_BLOCK_PCB_R_NACK_MASK (1U << ZF_ISO4_BLOCK_PCB_R_NACK_OFFSET)

#define ZF_ISO4_BLOCK_PCB_S_MASK (3U << 6)
#define ZF_ISO4_BLOCK_PCB_S_CID_OFFSET (3U)
#define ZF_ISO4_BLOCK_PCB_S_WTX_DESELECT_OFFSET (4U)
#define ZF_ISO4_BLOCK_PCB_S_CID_MASK (1U << ZF_ISO4_BLOCK_PCB_S_CID_OFFSET)
#define ZF_ISO4_BLOCK_PCB_S_WTX_DESELECT_MASK (3U << ZF_ISO4_BLOCK_PCB_S_WTX_DESELECT_OFFSET)

#define ZF_ISO4_BLOCK_PPS_START (0xD0U)
#define ZF_ISO4_BLOCK_PPS_START_MASK (0xF0U)
#define ZF_ISO4_BLOCK_PPS_0_HAS_PPS1 (1U << 4)
#define ZF_ISO4_BLOCK_CID_MASK (0x0FU)

#define ZF_ISO4_LAYER_CID_NOT_SUPPORTED ((uint8_t)-1)
#define ZF_ISO4_LAYER_NAD_NOT_SUPPORTED ((uint8_t)-1)
#define ZF_ISO4_LAYER_NAD_NOT_SET ((uint8_t)-2)

#define ZF_ISO4_BITS_ACTIVE(pcb, mask) (((pcb) & (mask)) == (mask))
#define ZF_ISO4_IS_I_BLOCK(pcb)                                                                    \
    (ZF_ISO4_BITS_ACTIVE((pcb), ZF_ISO4_BLOCK_PCB_I_MASK) &&                                       \
     (((pcb) & ZF_ISO4_BLOCK_PCB_I_ZERO_MASK) == 0U))
#define ZF_ISO4_IS_R_BLOCK(pcb) ZF_ISO4_BITS_ACTIVE((pcb), ZF_ISO4_BLOCK_PCB_R_MASK)
#define ZF_ISO4_IS_S_BLOCK(pcb) ZF_ISO4_BITS_ACTIVE((pcb), ZF_ISO4_BLOCK_PCB_S_MASK)
#define ZF_ISO4_CHAIN_ACTIVE(pcb) ZF_ISO4_BITS_ACTIVE((pcb), ZF_ISO4_BLOCK_PCB_I_CHAIN_MASK)
#define ZF_ISO4_R_NACK_ACTIVE(pcb) ZF_ISO4_BITS_ACTIVE((pcb), ZF_ISO4_BLOCK_PCB_R_NACK_MASK)
#define ZF_ISO4_IS_PPS_START(pps)                                                                  \
    (((pps) & ZF_ISO4_BLOCK_PPS_START_MASK) == ZF_ISO4_BLOCK_PPS_START)

struct ZfNfcIso4Layer {
    uint8_t pcb;
    uint8_t pcb_prev;
    uint8_t cid;
    uint8_t nad;
    bool can_pps;
};

static void zf_nfc_iso4_append_byte(BitBuffer *buffer, uint8_t value) {
    bit_buffer_append_bytes(buffer, &value, 1U);
}

static void zf_nfc_iso4_update_pcb(ZfNfcIso4Layer *instance, bool toggle_num) {
    instance->pcb_prev = instance->pcb;
    if (toggle_num) {
        instance->pcb ^= 0x01U;
    }
}

ZfNfcIso4Layer *zf_nfc_iso4_layer_alloc(void) {
    ZfNfcIso4Layer *instance = malloc(sizeof(*instance));

    if (instance) {
        zf_nfc_iso4_layer_reset(instance);
    }
    return instance;
}

void zf_nfc_iso4_layer_free(ZfNfcIso4Layer *instance) {
    free(instance);
}

void zf_nfc_iso4_layer_reset(ZfNfcIso4Layer *instance) {
    if (!instance) {
        return;
    }

    instance->pcb_prev = 0U;
    instance->pcb = ZF_ISO4_BLOCK_PCB_I | ZF_ISO4_BLOCK_PCB;
    instance->cid = ZF_ISO4_LAYER_CID_NOT_SUPPORTED;
    instance->nad = ZF_ISO4_LAYER_NAD_NOT_SUPPORTED;
    instance->can_pps = true;
}

void zf_nfc_iso4_layer_set_cid(ZfNfcIso4Layer *instance, uint8_t cid) {
    if (instance) {
        instance->cid = cid & ZF_ISO4_BLOCK_CID_MASK;
    }
}

void zf_nfc_iso4_layer_set_nad_supported(ZfNfcIso4Layer *instance, bool supported) {
    if (instance) {
        instance->nad = supported ? ZF_ISO4_LAYER_NAD_NOT_SET : ZF_ISO4_LAYER_NAD_NOT_SUPPORTED;
    }
}

static bool zf_nfc_iso4_accept_cid(ZfNfcIso4Layer *instance, uint8_t cid) {
    return instance->cid != ZF_ISO4_LAYER_CID_NOT_SUPPORTED &&
           (cid & ZF_ISO4_BLOCK_CID_MASK) == instance->cid;
}

ZfNfcIso4LayerResult zf_nfc_iso4_layer_decode_command(ZfNfcIso4Layer *instance,
                                                      const BitBuffer *input_data,
                                                      BitBuffer *block_data) {
    const uint8_t *data = NULL;
    size_t input_len = 0U;
    size_t prologue_len = 0U;
    uint8_t pcb = 0U;

    if (!instance || !input_data || !block_data) {
        return ZfNfcIso4LayerResultSkip;
    }

    bit_buffer_reset(block_data);
    input_len = bit_buffer_get_size_bytes(input_data);
    if (input_len == 0U) {
        return ZfNfcIso4LayerResultSkip;
    }

    data = bit_buffer_get_data(input_data);
    if (ZF_ISO4_IS_PPS_START(data[0])) {
        if (!instance->can_pps || input_len < 2U) {
            return ZfNfcIso4LayerResultSkip;
        }
        if ((data[0] & ZF_ISO4_BLOCK_CID_MASK) != 0U &&
            !zf_nfc_iso4_accept_cid(instance, data[0] & ZF_ISO4_BLOCK_CID_MASK)) {
            return ZfNfcIso4LayerResultSkip;
        }
        if ((data[1] & ZF_ISO4_BLOCK_PPS_0_HAS_PPS1) != 0U && input_len < 3U) {
            return ZfNfcIso4LayerResultSkip;
        }
        instance->can_pps = false;
        zf_nfc_iso4_append_byte(block_data, data[0]);
        return ZfNfcIso4LayerResultSend;
    }

    instance->can_pps = false;
    pcb = data[prologue_len++];
    instance->pcb = pcb;

    if (ZF_ISO4_IS_I_BLOCK(pcb)) {
        if ((pcb & ZF_ISO4_BLOCK_PCB_I_CID_MASK) != 0U) {
            if (input_len <= prologue_len) {
                return ZfNfcIso4LayerResultSkip;
            }
            const uint8_t cid = data[prologue_len] & ZF_ISO4_BLOCK_CID_MASK;
            prologue_len++;
            if (!zf_nfc_iso4_accept_cid(instance, cid)) {
                return ZfNfcIso4LayerResultSkip;
            }
        } else if (instance->cid != ZF_ISO4_LAYER_CID_NOT_SUPPORTED && instance->cid != 0U) {
            return ZfNfcIso4LayerResultSkip;
        }
        if ((pcb & ZF_ISO4_BLOCK_PCB_I_NAD_MASK) != 0U) {
            if (input_len <= prologue_len || instance->nad == ZF_ISO4_LAYER_NAD_NOT_SUPPORTED) {
                return ZfNfcIso4LayerResultSkip;
            }
            instance->nad = data[prologue_len++];
        }
        if (input_len > prologue_len) {
            bit_buffer_append_bytes(block_data, &data[prologue_len], input_len - prologue_len);
        }
        zf_nfc_iso4_update_pcb(instance, false);
        return ZfNfcIso4LayerResultData;
    }

    if (ZF_ISO4_IS_S_BLOCK(pcb)) {
        if ((pcb & ZF_ISO4_BLOCK_PCB_S_CID_MASK) != 0U) {
            if (input_len <= prologue_len) {
                return ZfNfcIso4LayerResultSkip;
            }
            const uint8_t cid = data[prologue_len] & ZF_ISO4_BLOCK_CID_MASK;
            if (!zf_nfc_iso4_accept_cid(instance, cid)) {
                return ZfNfcIso4LayerResultSkip;
            }
        } else if (instance->cid != ZF_ISO4_LAYER_CID_NOT_SUPPORTED && instance->cid != 0U) {
            return ZfNfcIso4LayerResultSkip;
        }
        if ((pcb & ZF_ISO4_BLOCK_PCB_S_WTX_DESELECT_MASK) == 0U) {
            bit_buffer_append_bytes(block_data, data, input_len);
            return ZfNfcIso4LayerResultSendHalt;
        }
        return ZfNfcIso4LayerResultSkip;
    }

    if (ZF_ISO4_IS_R_BLOCK(pcb)) {
        zf_nfc_iso4_update_pcb(instance, true);
        instance->pcb |= ZF_ISO4_BLOCK_PCB_R_NACK_MASK;
        zf_nfc_iso4_append_byte(block_data, instance->pcb);
        zf_nfc_iso4_update_pcb(instance, false);
        return ZfNfcIso4LayerResultSend;
    }

    return ZfNfcIso4LayerResultSkip;
}

bool zf_nfc_iso4_layer_encode_response(ZfNfcIso4Layer *instance, const BitBuffer *input_data,
                                       BitBuffer *block_data) {
    uint8_t pcb = 0U;

    if (!instance || !input_data || !block_data || !ZF_ISO4_IS_I_BLOCK(instance->pcb_prev)) {
        return false;
    }

    bit_buffer_reset(block_data);
    zf_nfc_iso4_append_byte(block_data, 0U);
    if ((instance->pcb_prev & ZF_ISO4_BLOCK_PCB_I_CID_MASK) != 0U) {
        zf_nfc_iso4_append_byte(block_data, instance->cid);
    }
    if ((instance->pcb_prev & ZF_ISO4_BLOCK_PCB_I_NAD_MASK) != 0U &&
        instance->nad != ZF_ISO4_LAYER_NAD_NOT_SET) {
        zf_nfc_iso4_append_byte(block_data, instance->nad);
        instance->nad = ZF_ISO4_LAYER_NAD_NOT_SET;
    } else {
        instance->pcb &= (uint8_t)~ZF_ISO4_BLOCK_PCB_I_NAD_MASK;
    }

    instance->pcb &= (uint8_t)~ZF_ISO4_BLOCK_PCB_I_CHAIN_MASK;
    pcb = instance->pcb;
    bit_buffer_set_byte(block_data, 0U, pcb);
    if (bit_buffer_get_size_bytes(input_data) > 0U) {
        bit_buffer_append_bytes(block_data, bit_buffer_get_data(input_data),
                                bit_buffer_get_size_bytes(input_data));
    }
    instance->pcb = pcb;
    zf_nfc_iso4_update_pcb(instance, false);
    return true;
}
