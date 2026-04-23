#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../zerofido_runtime_config.h"

typedef struct ZerofidoApp ZerofidoApp;

uint8_t zf_ctap_dispatch_command(ZerofidoApp *app, const ZfResolvedCapabilities *capabilities,
                                 uint32_t cid, uint8_t cmd, const uint8_t *request_body,
                                 size_t request_body_len, uint8_t *response_body,
                                 size_t response_body_capacity, size_t *response_body_len);
