#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct ZerofidoApp ZerofidoApp;

bool zf_u2f_adapter_init(ZerofidoApp *app);
void zf_u2f_adapter_deinit(ZerofidoApp *app);
bool zf_u2f_adapter_is_available(const ZerofidoApp *app);
void zf_u2f_adapter_set_connected(ZerofidoApp *app, bool connected);
size_t zf_u2f_adapter_handle_msg(ZerofidoApp *app, uint32_t cid, const uint8_t *request,
                                 size_t request_len, uint8_t *response, size_t response_capacity);
void zf_u2f_adapter_wink(ZerofidoApp *app);
