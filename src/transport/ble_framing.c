/*
 * ZeroFIDO (BLE transport fork)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "ble_framing.h"

#include <string.h>

static bool zf_ble_cmd_is_valid(uint8_t cmd) {
    return cmd == ZF_BLE_CMD_PING || cmd == ZF_BLE_CMD_MSG || cmd == ZF_BLE_CMD_CANCEL;
}

static ZfBleRxStatus zf_ble_rx_fail(ZfBleRx *rx, uint8_t error_code) {
    rx->active = false;
    rx->len = 0;
    rx->expected = 0;
    rx->next_seq = 0;
    rx->error_code = error_code;
    return ZfBleRxError;
}

void zf_ble_rx_init(ZfBleRx *rx, uint8_t *buf, size_t capacity) {
    memset(rx, 0, sizeof(*rx));
    rx->buf = buf;
    rx->capacity = capacity;
}

void zf_ble_rx_reset(ZfBleRx *rx) {
    rx->active = false;
    rx->len = 0;
    rx->expected = 0;
    rx->cmd = 0;
    rx->next_seq = 0;
    rx->error_code = 0;
}

static ZfBleRxStatus zf_ble_rx_feed_init(ZfBleRx *rx, const uint8_t *fragment,
                                         size_t fragment_len) {
    uint8_t cmd = fragment[0];
    size_t hlen;
    size_t data_len;

    if (!zf_ble_cmd_is_valid(cmd)) {
        return zf_ble_rx_fail(rx, ZF_BLE_ERR_INVALID_CMD);
    }
    if (fragment_len < ZF_BLE_INIT_HEADER_SIZE) {
        return zf_ble_rx_fail(rx, ZF_BLE_ERR_INVALID_LEN);
    }

    hlen = ((size_t)fragment[1] << 8) | fragment[2];
    data_len = fragment_len - ZF_BLE_INIT_HEADER_SIZE;

    if (hlen > rx->capacity || data_len > hlen) {
        return zf_ble_rx_fail(rx, ZF_BLE_ERR_INVALID_LEN);
    }

    if (cmd == ZF_BLE_CMD_CANCEL) {
        zf_ble_rx_reset(rx);
        return ZfBleRxCancel;
    }

    rx->cmd = cmd;
    rx->expected = hlen;
    rx->len = data_len;
    rx->next_seq = 0;
    if (data_len > 0) {
        memcpy(rx->buf, fragment + ZF_BLE_INIT_HEADER_SIZE, data_len);
    }

    if (rx->len == rx->expected) {
        rx->active = false;
        return ZfBleRxComplete;
    }

    rx->active = true;
    return ZfBleRxIncomplete;
}

static ZfBleRxStatus zf_ble_rx_feed_continuation(ZfBleRx *rx, const uint8_t *fragment,
                                                 size_t fragment_len) {
    size_t data_len = fragment_len - ZF_BLE_CONT_HEADER_SIZE;

    if (fragment[0] != rx->next_seq) {
        return zf_ble_rx_fail(rx, ZF_BLE_ERR_INVALID_SEQ);
    }
    if (data_len > rx->expected - rx->len) {
        return zf_ble_rx_fail(rx, ZF_BLE_ERR_INVALID_LEN);
    }

    memcpy(rx->buf + rx->len, fragment + ZF_BLE_CONT_HEADER_SIZE, data_len);
    rx->len += data_len;
    rx->next_seq = (uint8_t)((rx->next_seq + 1U) & 0x7FU);

    if (rx->len == rx->expected) {
        rx->active = false;
        return ZfBleRxComplete;
    }
    return ZfBleRxIncomplete;
}

ZfBleRxStatus zf_ble_rx_feed(ZfBleRx *rx, const uint8_t *fragment, size_t fragment_len) {
    if (!rx || !rx->buf || !fragment || fragment_len == 0) {
        if (rx) {
            return zf_ble_rx_fail(rx, ZF_BLE_ERR_INVALID_LEN);
        }
        return ZfBleRxError;
    }

    if (!rx->active) {
        if ((fragment[0] & 0x80U) == 0U) {
            /* A continuation with nothing in flight cannot be matched to a message. */
            return zf_ble_rx_fail(rx, ZF_BLE_ERR_INVALID_SEQ);
        }
        return zf_ble_rx_feed_init(rx, fragment, fragment_len);
    }

    if ((fragment[0] & 0x80U) != 0U) {
        /* CANCEL may interrupt a message; any other command mid-message is a violation. */
        if (fragment[0] == ZF_BLE_CMD_CANCEL) {
            zf_ble_rx_reset(rx);
            return ZfBleRxCancel;
        }
        return zf_ble_rx_fail(rx, ZF_BLE_ERR_INVALID_SEQ);
    }

    return zf_ble_rx_feed_continuation(rx, fragment, fragment_len);
}

bool zf_ble_tx_init(ZfBleTx *tx, uint8_t cmd, const uint8_t *data, size_t len,
                    size_t fragment_size) {
    if (!tx || (len > 0 && !data) || len > 0xFFFFU || fragment_size < ZF_BLE_MIN_FRAGMENT_SIZE ||
        fragment_size > ZF_BLE_MAX_FRAGMENT_SIZE) {
        return false;
    }

    tx->cmd = cmd;
    tx->data = data;
    tx->len = len;
    tx->offset = 0;
    tx->fragment_size = fragment_size;
    tx->next_seq = 0;
    tx->started = false;
    return true;
}

size_t zf_ble_tx_next(ZfBleTx *tx, uint8_t *out, size_t out_capacity) {
    size_t remaining;
    size_t room;
    size_t chunk;

    if (!tx || !out || zf_ble_tx_done(tx)) {
        return 0;
    }

    remaining = tx->len - tx->offset;

    if (!tx->started) {
        room = tx->fragment_size - ZF_BLE_INIT_HEADER_SIZE;
        chunk = remaining < room ? remaining : room;
        if (out_capacity < ZF_BLE_INIT_HEADER_SIZE + chunk) {
            return 0;
        }
        out[0] = tx->cmd;
        out[1] = (uint8_t)(tx->len >> 8);
        out[2] = (uint8_t)(tx->len & 0xFFU);
        if (chunk > 0) {
            memcpy(out + ZF_BLE_INIT_HEADER_SIZE, tx->data, chunk);
        }
        tx->offset += chunk;
        tx->started = true;
        return ZF_BLE_INIT_HEADER_SIZE + chunk;
    }

    room = tx->fragment_size - ZF_BLE_CONT_HEADER_SIZE;
    chunk = remaining < room ? remaining : room;
    if (out_capacity < ZF_BLE_CONT_HEADER_SIZE + chunk) {
        return 0;
    }
    out[0] = tx->next_seq;
    memcpy(out + ZF_BLE_CONT_HEADER_SIZE, tx->data + tx->offset, chunk);
    tx->offset += chunk;
    tx->next_seq = (uint8_t)((tx->next_seq + 1U) & 0x7FU);
    return ZF_BLE_CONT_HEADER_SIZE + chunk;
}

bool zf_ble_tx_done(const ZfBleTx *tx) {
    return !tx || (tx->started && tx->offset >= tx->len);
}

ZfBleMessageKind zf_ble_classify_msg(const uint8_t *payload, size_t len) {
    if (!payload || len == 0) {
        return ZfBleMessageKindInvalid;
    }
    /* U2F raw messages are ISO 7816 APDUs whose CLA byte is 0x00. */
    if (payload[0] == 0x00U) {
        return ZfBleMessageKindU2f;
    }
    return ZfBleMessageKindCtap2;
}

static size_t zf_ble_build_single(uint8_t cmd, uint8_t value, uint8_t *out, size_t out_capacity) {
    if (!out || out_capacity < 4U) {
        return 0;
    }
    out[0] = cmd;
    out[1] = 0x00;
    out[2] = 0x01;
    out[3] = value;
    return 4U;
}

size_t zf_ble_build_error(uint8_t error_code, uint8_t *out, size_t out_capacity) {
    return zf_ble_build_single(ZF_BLE_CMD_ERROR, error_code, out, out_capacity);
}

size_t zf_ble_build_keepalive(uint8_t status, uint8_t *out, size_t out_capacity) {
    return zf_ble_build_single(ZF_BLE_CMD_KEEPALIVE, status, out, out_capacity);
}
