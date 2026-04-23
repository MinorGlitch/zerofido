#pragma once

#include <stdint.h>

#include "session.h"

uint16_t zf_u2f_encode_register_response(U2fData *instance, uint8_t *buf,
                                         uint16_t response_capacity);
uint16_t zf_u2f_encode_authenticate_response(U2fData *instance, uint8_t *buf, uint16_t request_len,
                                             uint16_t response_capacity);
