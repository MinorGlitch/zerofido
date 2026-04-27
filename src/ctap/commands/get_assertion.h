#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../../zerofido_types.h"

typedef struct ZerofidoApp ZerofidoApp;

uint8_t zf_ctap_handle_get_assertion(ZerofidoApp *app, ZfTransportSessionId session_id,
                                     const uint8_t *data, size_t data_len, uint8_t *out,
                                     size_t out_capacity, size_t *out_len);
