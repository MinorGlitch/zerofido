#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zerofido_types.h"

typedef struct ZerofidoApp ZerofidoApp;

size_t zerofido_handle_ctap2(ZerofidoApp *app, ZfTransportSessionId session_id,
                             const uint8_t *request, size_t request_len, uint8_t *response,
                             size_t response_capacity);
void zerofido_ctap_invalidate_assertion_queue(ZerofidoApp *app);
