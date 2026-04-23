#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../zerofido_types.h"

typedef struct ZerofidoApp ZerofidoApp;

uint8_t zf_ctap_request_approval(ZerofidoApp *app, const char *operation, const char *rp_id,
                                 const char *user_text, uint32_t cid);
uint8_t zf_ctap_request_assertion_selection(ZerofidoApp *app, const char *rp_id,
                                            const uint16_t *match_indices, size_t match_count,
                                            uint32_t cid, uint32_t *selected_record_index);
uint8_t zf_ctap_handle_empty_pin_auth_probe(ZerofidoApp *app, uint32_t cid, const char *operation,
                                            const char *rp_id, const char *user_text);
