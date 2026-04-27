#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../../zerofido_types.h"

typedef struct ZerofidoApp ZerofidoApp;

uint8_t zf_ctap_handle_reset(ZerofidoApp *app, ZfTransportSessionId session_id,
                             size_t request_len, size_t *out_len);
