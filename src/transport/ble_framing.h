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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * FIDO-over-BLE message framing (CTAP "BLE" transport).
 *
 * This layer is deliberately free of Flipper and GATT dependencies so it can be
 * unit-tested on a host. It only turns GATT writes to the fidoControlPoint
 * characteristic into complete messages, and complete messages into fragments
 * to notify on the fidoStatus characteristic.
 *
 * Initialization fragment:  CMD(1, bit7 set) | HLEN(2, big-endian) | DATA
 * Continuation fragment:    SEQ(1, 0..127)   | DATA
 */

#define ZF_BLE_CMD_PING 0x81U
#define ZF_BLE_CMD_KEEPALIVE 0x82U
#define ZF_BLE_CMD_MSG 0x83U
#define ZF_BLE_CMD_CANCEL 0xBEU
#define ZF_BLE_CMD_ERROR 0xBFU

#define ZF_BLE_KEEPALIVE_PROCESSING 0x01U
#define ZF_BLE_KEEPALIVE_USER_PRESENCE_NEEDED 0x02U

#define ZF_BLE_ERR_INVALID_CMD 0x01U
#define ZF_BLE_ERR_INVALID_PAR 0x02U
#define ZF_BLE_ERR_INVALID_LEN 0x03U
#define ZF_BLE_ERR_INVALID_SEQ 0x04U
#define ZF_BLE_ERR_REQ_TIMEOUT 0x05U
#define ZF_BLE_ERR_OTHER 0x7FU

/* Spec bounds for the fidoControlPointLength characteristic value. */
#define ZF_BLE_MIN_FRAGMENT_SIZE 20U
#define ZF_BLE_MAX_FRAGMENT_SIZE 512U

#define ZF_BLE_INIT_HEADER_SIZE 3U
#define ZF_BLE_CONT_HEADER_SIZE 1U

typedef enum {
    ZfBleRxIncomplete = 0, /* fragment accepted, more expected */
    ZfBleRxComplete = 1,   /* a full message is ready in rx->buf */
    ZfBleRxCancel = 2,     /* peer sent CANCEL; any partial message dropped */
    ZfBleRxError = 3,      /* protocol violation; see error_code */
} ZfBleRxStatus;

typedef enum {
    ZfBleMessageKindPing = 0,
    ZfBleMessageKindU2f = 1,
    ZfBleMessageKindCtap2 = 2,
    ZfBleMessageKindInvalid = 3,
} ZfBleMessageKind;

typedef struct {
    uint8_t *buf;       /* caller-owned reassembly buffer */
    size_t capacity;    /* bytes available in buf */
    size_t len;         /* bytes received so far */
    size_t expected;    /* total payload length announced by HLEN */
    uint8_t cmd;        /* command of the message being assembled */
    uint8_t next_seq;   /* sequence number expected on the next continuation */
    bool active;        /* true while a multi-fragment message is in flight */
    uint8_t error_code; /* valid after ZfBleRxError */
} ZfBleRx;

typedef struct {
    uint8_t cmd;
    const uint8_t *data;
    size_t len;
    size_t offset;
    size_t fragment_size; /* max bytes per GATT notification, header included */
    uint8_t next_seq;
    bool started;
} ZfBleTx;

void zf_ble_rx_init(ZfBleRx *rx, uint8_t *buf, size_t capacity);
void zf_ble_rx_reset(ZfBleRx *rx);

/*
 * Feeds one fidoControlPoint write. On ZfBleRxComplete, rx->cmd, rx->buf and
 * rx->len describe the message and the assembler is ready for the next one.
 * The buffer stays valid until the next call that feeds a fragment.
 */
ZfBleRxStatus zf_ble_rx_feed(ZfBleRx *rx, const uint8_t *fragment, size_t fragment_len);

/* Returns false if fragment_size is outside the spec bounds or len is > 0xFFFF. */
bool zf_ble_tx_init(ZfBleTx *tx, uint8_t cmd, const uint8_t *data, size_t len,
                    size_t fragment_size);

/*
 * Writes the next fragment into out and returns its length, or 0 when the whole
 * message has been produced (or out_capacity is too small for the fragment).
 */
size_t zf_ble_tx_next(ZfBleTx *tx, uint8_t *out, size_t out_capacity);
bool zf_ble_tx_done(const ZfBleTx *tx);

/*
 * A BLE MSG payload carries either a raw U2F APDU (first byte is CLA, always
 * 0x00) or a CTAP2 command byte followed by CBOR. Used to route into the
 * existing U2F or CTAP2 handlers.
 */
ZfBleMessageKind zf_ble_classify_msg(const uint8_t *payload, size_t len);

/* Builds a one-fragment ERROR message. Returns its length (always 4). */
size_t zf_ble_build_error(uint8_t error_code, uint8_t *out, size_t out_capacity);

/* Builds a one-fragment KEEPALIVE message. Returns its length (always 4). */
size_t zf_ble_build_keepalive(uint8_t status, uint8_t *out, size_t out_capacity);
