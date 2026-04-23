#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "common.h"

typedef struct {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    const uint8_t *data;
    uint32_t lc;
} U2fParsedApdu;

bool u2f_parse_apdu_header(const uint8_t *buf, uint16_t len, bool allow_short, U2fParsedApdu *apdu);
