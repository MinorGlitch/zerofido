#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../zerofido_types.h"

uint8_t zf_ctap_parse_make_credential(const uint8_t *data, size_t size,
                                      ZfMakeCredentialRequest *request);
uint8_t zf_ctap_parse_get_assertion(const uint8_t *data, size_t size,
                                    ZfGetAssertionRequest *request);
