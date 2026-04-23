#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "common.h"

uint16_t u2f_validate_request(uint8_t *buf, uint16_t request_len);
uint16_t u2f_validate_request_into_response(const uint8_t *request, uint16_t request_len,
                                            uint8_t *response, uint16_t response_capacity);
bool u2f_request_needs_user_presence(const uint8_t *buf, uint16_t request_len,
                                     const char **operation);
