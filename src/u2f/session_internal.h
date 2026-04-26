#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <mbedtls/ecp.h>

#include "common.h"
#include "session.h"

typedef struct U2fData {
    uint8_t device_key[U2F_EC_KEY_SIZE];
    uint8_t cert_key[U2F_EC_KEY_SIZE];
    uint32_t counter;
    uint32_t counter_high_water;
    bool ready;
    bool user_present;
    U2fEvtCallback callback;
    void *context;
    mbedtls_ecp_group group;
} U2fData;

static const uint8_t zf_u2f_state_no_error[] = {0x90, 0x00};
static const uint8_t zf_u2f_state_not_supported[] = {0x6D, 0x00};
static const uint8_t zf_u2f_state_wrong_length[] = {0x67, 0x00};
static const uint8_t zf_u2f_state_user_missing[] = {0x69, 0x85};
static const uint8_t zf_u2f_state_wrong_data[] = {0x6A, 0x80};

static inline uint16_t zf_u2f_reply_status(uint8_t *buf, const uint8_t status[2]) {
    memcpy(&buf[0], status, 2);
    return 2;
}
