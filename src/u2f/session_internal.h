/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
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
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "session.h"

/* Private U2F runtime state shared by session, response, and persistence code. */
typedef struct U2fData {
    uint8_t device_key[U2F_EC_KEY_SIZE];
    uint8_t cert_key[U2F_EC_KEY_SIZE];
    uint32_t counter;
    uint32_t counter_high_water;
    bool cert_ready;
    bool ready;
    bool user_present;
    U2fEvtCallback callback;
    void *context;
} U2fData;

/* ISO7816 status words returned by U2F APDU handlers. */
static const uint8_t zf_u2f_state_no_error[] = {0x90, 0x00};
static const uint8_t zf_u2f_state_not_supported[] = {0x6D, 0x00};
static const uint8_t zf_u2f_state_wrong_length[] = {0x67, 0x00};
static const uint8_t zf_u2f_state_user_missing[] = {0x69, 0x85};
static const uint8_t zf_u2f_state_wrong_data[] = {0x6A, 0x80};

static inline uint16_t zf_u2f_reply_status(uint8_t *buf, const uint8_t status[2]) {
    memcpy(&buf[0], status, 2);
    return 2;
}
