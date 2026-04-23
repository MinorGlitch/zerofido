#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../zerofido_types.h"

typedef struct ZerofidoApp ZerofidoApp;

void zf_ctap_assertion_queue_clear(ZerofidoApp *app);
void zf_ctap_assertion_queue_seed(ZerofidoApp *app, uint32_t cid,
                                  const ZfGetAssertionRequest *request, bool uv_verified,
                                  const uint16_t *match_indices, size_t match_count);
uint8_t zf_ctap_assertion_queue_handle_next(ZerofidoApp *app, uint32_t cid, uint8_t *out,
                                            size_t out_capacity, size_t *out_len);
